/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "libknot/xdp/tcp.h"

#include <assert.h>
#include <string.h>

#include "libknot/attribute.h"
#include "libknot/error.h"
#include "contrib/mempattern.h"

static int add_relay(knot_tcp_relay_t *relays[], uint32_t *max_relays,
                     uint32_t *n_relays, knot_tcp_relay_t *to_add, knot_mm_t *mm)
{
	assert(*n_relays <= *max_relays);
	if (*relays == NULL) {
		assert(*n_relays == 0);
		*relays = mm_alloc(mm, *max_relays * sizeof(**relays));
		if (*relays == NULL) {
			return KNOT_ENOMEM;
		}
	} else if (*n_relays == *max_relays) {
		uint32_t new_max_relays = 2 * *max_relays;
		knot_tcp_relay_t *new_relays = mm_alloc(mm, new_max_relays * sizeof(*new_relays));
		if (new_relays == NULL) {
			return KNOT_ENOMEM;
		}
		memcpy(new_relays, *relays, *max_relays * sizeof(*new_relays));
		mm_free(mm, *relays);
		*relays = new_relays;
		*max_relays = new_max_relays;
	}
	memcpy(&(*relays)[(*n_relays)++], to_add, sizeof(*to_add));
	return KNOT_EOK;
}

_public_
int knot_xdp_tcp_relay(knot_xdp_socket_t *socket, knot_xdp_msg_t msgs[],
                       uint32_t msg_count, knot_tcp_relay_t *relays[],
                       uint32_t *relay_count, knot_mm_t *mm)
{
	if (msg_count == 0) {
		return KNOT_EOK;
	}
	if (socket == NULL || msgs == NULL || relays == NULL ||
	    relay_count == NULL || *relay_count != 0) {
		return KNOT_EINVAL;
	}

	knot_xdp_send_prepare(socket);

	knot_xdp_msg_t acks[msg_count];
	uint32_t n_acks = 0, max_relays = msg_count;
	int ret = KNOT_EOK;

#define resp_ack(msg) \
	{ \
		knot_xdp_msg_t *ack = &acks[n_acks++]; \
		int ackret = knot_xdp_reply_alloc(socket, (msg), ack); \
		if (ackret != KNOT_EOK) { \
			n_acks--; \
			continue; \
		} \
		ack->payload.iov_len = 0; \
		ack->flags |= KNOT_XDP_MSG_ACK; \
	}

#define add_to_relays(relay) add_relay(relays, &max_relays, relay_count, (relay), mm);

	for (size_t i = 0; i < msg_count && ret == KNOT_EOK; i++) {
		knot_xdp_msg_t *msg = &msgs[i];
		if (!(msg->flags & KNOT_XDP_MSG_TCP)) {
			continue;
		}

		knot_tcp_relay_t relay = { .msg = msg };

		switch (msg->flags & (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK |
		                      KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_RST)) {
		case KNOT_XDP_MSG_SYN:
			break;
		case (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK):
			resp_ack(msg);
			relay.action = XDP_TCP_ESTABLISH;
			ret = add_to_relays(&relay);
			break;
		case KNOT_XDP_MSG_ACK:
			if (msg->payload.iov_len > 0) {
				resp_ack(msg);
				relay.action = XDP_TCP_DATA;

				uint16_t dns_len;
				uint8_t *payl = msg->payload.iov_base;
				size_t paylen = msg->payload.iov_len;

				while (ret == KNOT_EOK && paylen >= sizeof(dns_len) &&
				       paylen >= sizeof(dns_len) + (dns_len = be16toh(*(uint16_t *)payl))) {

					relay.data.iov_base = payl + sizeof(dns_len);
					relay.data.iov_len = dns_len - sizeof(dns_len);
					ret = add_to_relays(&relay);

					payl += sizeof(dns_len) + dns_len;
					paylen -= sizeof(dns_len) + dns_len;
				}
			}
			break; // sole ACK without PSH is ignored
		case (KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_ACK):
			resp_ack(msg);
			relay.action = XDP_TCP_CLOSE;
			ret = add_to_relays(&relay);
			break;
		case KNOT_XDP_MSG_RST:
			relay.action = XDP_TCP_RESET;
			ret = add_to_relays(&relay);
			break;
		default:
			break;
		}
	}

	if (n_acks > 0 && ret == KNOT_EOK) {
		uint32_t sent_unused;
		ret = knot_xdp_send(socket, acks, n_acks, &sent_unused);
		if (ret == KNOT_EOK) {
			ret = knot_xdp_send_finish(socket);
		}
	}

	return ret;
}

_public_
int knot_xdp_tcp_send(knot_xdp_socket_t *socket, knot_tcp_relay_t relays[],
                      uint32_t relay_count)
{
	if (relay_count == 0) {
		return KNOT_EOK;
	}
	if (socket == NULL || relays == NULL) {
		return KNOT_EINVAL;
	}

	knot_xdp_msg_t msgs[relay_count], *msg = &msgs[0];
	int ret = KNOT_EOK, n_msgs = 0;

	knot_xdp_send_prepare(socket);

	for (size_t irl = 0; irl < relay_count; irl++) {
		knot_tcp_relay_t *rl = &relays[irl];
		if ((rl->answer & 0x07) == XDP_TCP_NOOP) {
			continue;
		}

		if (rl->answer & XDP_TCP_ANSWER) {
			ret = knot_xdp_reply_alloc(socket, rl->msg, msg);
		} else {
			ret = knot_xdp_send_alloc(socket, rl->msg->flags, msg);

			memcpy( msg->eth_from, rl->msg->eth_from, sizeof(msg->eth_from));
			memcpy( msg->eth_to,   rl->msg->eth_to,   sizeof(msg->eth_to));
			memcpy(&msg->ip_from, &rl->msg->ip_from,  sizeof(msg->ip_from));
			memcpy(&msg->ip_to,   &rl->msg->ip_to,    sizeof(msg->ip_to));
		}
		if (ret != KNOT_EOK) {
			break;
		}

		switch (rl->answer & 0x07) {
		case XDP_TCP_ESTABLISH:
			msg->flags |= KNOT_XDP_MSG_SYN;
			msg->payload.iov_len = 0;
			break;
		case XDP_TCP_DATA:
			msg->flags |= KNOT_XDP_MSG_ACK;
			if (rl->data.iov_len > UINT16_MAX ||
			    rl->data.iov_len > msg->payload.iov_len - sizeof(uint16_t)) {
				ret = KNOT_ESPACE;
			} else {
				*(uint16_t *)msg->payload.iov_base = htobe16(rl->data.iov_len);
				memcpy(msg->payload.iov_base + sizeof(uint16_t), rl->data.iov_base, rl->data.iov_len);
				msg->payload.iov_len = rl->data.iov_len + sizeof(uint16_t);
			}
			break;
		case XDP_TCP_CLOSE:
			msg->flags |= (KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_ACK);
			msg->payload.iov_len = 0;
			break;
		case XDP_TCP_RESET:
		default:
			assert(0);
			break;
		}

		msg++;
		n_msgs++;
		if (ret != KNOT_EOK) {
			break;
		}
	}

	uint32_t sent_unused;
	if (ret == KNOT_EOK) {
		ret = knot_xdp_send(socket, msgs, n_msgs, &sent_unused);
	} else {
		knot_xdp_send_free(socket, msgs, n_msgs);
	}
	if (ret == KNOT_EOK) {
		ret = knot_xdp_send_finish(socket);
	}
	return ret;
}
