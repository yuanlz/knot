/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/xdp/protocols.h"

#include <assert.h>
#include <errno.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/tcp.h>
#include <linux/udp.h>

#include "libknot/attribute.h"
#include "libknot/endian.h"
#include "libknot/errcode.h"
#include "contrib/macros.h"

/* Don't fragment flag. */
#define	IP_DF 0x4000

#define check_payload(p, proto, minlen) \
	do { if ((p).err != KNOT_EOK) { return (p); } \
	     if ((p).next_proto != (proto)) { (p).err = KNOT_EINVAL; return (p); } \
	     if ((p).len < (minlen)) { (p).err = KNOT_EMALF; return (p); } \
	} while (0)

static knot_xdp_payload_t read_eth(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	check_payload(p, KNOT_XDP_H_ETH, sizeof(struct ethhdr));

	knot_xdp_payload_t res = { 0 };

	const struct ethhdr *eth = p.buf;

	if (msg != NULL) {
		memcpy(msg->eth_from, eth->h_source, ETH_ALEN);
		memcpy(msg->eth_to, eth->h_dest, ETH_ALEN);
	}

	res.next_proto = eth->h_proto;
	res.buf = p.buf + sizeof(*eth);
	res.len = p.len - sizeof(*eth);

	return res;
}

static knot_xdp_payload_t read_ipv4(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	check_payload(p, KNOT_XDP_H_IPV4, sizeof(struct iphdr));

	knot_xdp_payload_t res = { 0 };

	const struct iphdr *ip4 = p.buf;

	if (msg != NULL) {
		msg->flags &= ~KNOT_XDP_IPV6;

		// those asserts are ensured by the BPF filter that does not let the packet through otherwise
		assert(ip4->version == 4);
		assert(ip4->frag_off == 0 || ip4->frag_off == __constant_htons(IP_DF));

		struct sockaddr_in *src_v4 = (struct sockaddr_in *)&msg->ip_from;
		struct sockaddr_in *dst_v4 = (struct sockaddr_in *)&msg->ip_to;
		memcpy(&src_v4->sin_addr, &ip4->saddr, sizeof(src_v4->sin_addr));
		memcpy(&dst_v4->sin_addr, &ip4->daddr, sizeof(dst_v4->sin_addr));
		src_v4->sin_family = AF_INET;
		dst_v4->sin_family = AF_INET;
	}

	res.next_proto = ip4->protocol;
	res.buf = p.buf + ip4->ihl * 4;
	if (ip4->tot_len == 0) {
		res.len = p.len - ip4->ihl * 4;
	} else {
		res.len = be16toh(ip4->tot_len) - ip4->ihl * 4;
	}

	return res;
}

static knot_xdp_payload_t read_ipv6(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	check_payload(p, KNOT_XDP_H_IPV6, sizeof(struct ipv6hdr));

	knot_xdp_payload_t res = { 0 };

	const struct ipv6hdr *ip6 = p.buf;

	if (msg != NULL) {
		msg->flags |= KNOT_XDP_IPV6;

		assert(ip6->version == 6);

		struct sockaddr_in6 *src_v6 = (struct sockaddr_in6 *)&msg->ip_from;
		struct sockaddr_in6 *dst_v6 = (struct sockaddr_in6 *)&msg->ip_to;
		memcpy(&src_v6->sin6_addr, &ip6->saddr, sizeof(src_v6->sin6_addr));
		memcpy(&dst_v6->sin6_addr, &ip6->daddr, sizeof(dst_v6->sin6_addr));
		src_v6->sin6_family = AF_INET6;
		dst_v6->sin6_family = AF_INET6;
		// Flow label is ignored.
	}

	res.next_proto = ip6->nexthdr;
	res.buf = p.buf + sizeof(struct ipv6hdr);
	if (ip6->payload_len == 0) {
		res.len = p.len - sizeof(struct ipv6hdr);
	} else {
		res.len = be16toh(ip6->payload_len);
	}

	return res;
}

static knot_xdp_payload_t read_udp(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	check_payload(p, KNOT_XDP_H_UDP, sizeof(struct udphdr));

	knot_xdp_payload_t res = { 0 };

	const struct udphdr *udp = p.buf;

	if (msg != NULL) {
		msg->flags &= ~KNOT_XDP_TCP;

		assert(p.len == be16toh(udp->len));
		// NOTICE: UDP checksum is not verified

		assert(offsetof(struct sockaddr_in, sin_port) == offsetof(struct sockaddr_in6, sin6_port));
		msg->ip_from.sin6_port = udp->source;
		msg->ip_to.sin6_port = udp->dest;
	}

	res.next_proto = KNOT_XDP_H_DNS_MSG;
	res.buf = p.buf + sizeof(struct udphdr);
	res.len = p.len - sizeof(struct udphdr);

	return res;
}

static knot_xdp_payload_t read_tcp(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	check_payload(p, KNOT_XDP_H_TCP, sizeof(struct tcphdr));

	knot_xdp_payload_t res = { 0 };

	const struct tcphdr *tcp = p.buf;

	if (msg != NULL) {
		msg->flags |= KNOT_XDP_TCP;
		if (tcp->syn) {
			msg->flags |= KNOT_XDP_SYN;
		}
		if (tcp->ack) {
			msg->flags |= KNOT_XDP_ACK;
		}
		if (tcp->fin) {
			msg->flags |= KNOT_XDP_FIN;
		}
		if (tcp->rst) {
			msg->flags |= KNOT_XDP_RST;
		}
		msg->seqno = be32toh(tcp->seq);
		msg->ackno = be32toh(tcp->ack_seq);

		assert(offsetof(struct sockaddr_in, sin_port) == offsetof(struct sockaddr_in6, sin6_port));
		msg->ip_from.sin6_port = tcp->source;
		msg->ip_to.sin6_port = tcp->dest;
	}

	res.next_proto = KNOT_XDP_H_DNS_PAYLOAD;
	res.buf = p.buf + tcp->doff * 4;
	res.len = p.len - tcp->doff * 4;

	return res;
}

// this function is based on the (FIXME!) assumption that a TCP packet contains one whole DNS msg
static knot_xdp_payload_t read_payload(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	UNUSED(msg);

	// special case: empty packet means empty DNS msg
	if (p.len == 0) {
		p.next_proto = KNOT_XDP_H_DNS_MSG;
		return p;
	}

	check_payload(p, KNOT_XDP_H_DNS_PAYLOAD, sizeof(uint16_t));

	knot_xdp_payload_t res = { 0 };

	uint16_t len = be16toh(*(uint16_t *)p.buf);

	if (len != p.len - sizeof(uint16_t) && msg != NULL) {
		res.err = KNOT_ENOTSUP;
	} else {
		res.next_proto = KNOT_XDP_H_DNS_MSG;
		res.buf = p.buf + sizeof(uint16_t);
		res.len = p.len - sizeof(uint16_t);
	}

	return res;
}

#define ret_err(p, errcode) do { if ((p).err == KNOT_EOK) { (p).err = (errcode); } return (p); } while (0)

knot_xdp_payload_t knot_xdp_read_all(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	p = read_eth(p, msg);

	switch (p.next_proto) {
	case KNOT_XDP_H_IPV4:
		p = read_ipv4(p, msg);
		break;
	case KNOT_XDP_H_IPV6:
		p = read_ipv6(p, msg);
		break;
	default:
		ret_err(p, KNOT_EMALF);
	}

	switch (p.next_proto) {
	case KNOT_XDP_H_UDP:
		p = read_udp(p, msg);
		break;
	case KNOT_XDP_H_TCP:
		p = read_tcp(p, msg);
		p = read_payload(p, msg);
		break;
	default:
		ret_err(p, KNOT_EMALF);
	}

	if (p.err == KNOT_EOK) {
		assert(p.next_proto == KNOT_XDP_H_DNS_MSG);
	}
	return p;
}

static uint16_t flags_ip(knot_xdp_flags_t flags)
{
	return ((flags & KNOT_XDP_IPV6) ? KNOT_XDP_H_IPV6 : KNOT_XDP_H_IPV4);
}

static uint8_t flags_p(knot_xdp_flags_t flags)
{
	return ((flags & KNOT_XDP_TCP) ? KNOT_XDP_H_TCP : KNOT_XDP_H_UDP);
}

static void *reserve_eth(void *buf, knot_xdp_flags_t flags)
{
	struct ethhdr *eth = buf;
	return eth + 1;
}

static void *reserve_ip(void *buf, knot_xdp_flags_t flags)
{
	if (!(flags & KNOT_XDP_IPV6)) {
		struct iphdr *ip4 = buf;
		return ip4 + 1;
	} else {
		struct ipv6hdr *ip6 = buf;
		return ip6 + 1;
	}
}

static void *reserve_p(void *buf, knot_xdp_flags_t flags)
{
	if (!(flags & KNOT_XDP_TCP)) {
		return buf + sizeof(struct udphdr);
	} else {
		struct tcphdr *tcp = buf;
		return ((void *)(tcp + 1)) + 2; // 2 == DNS message size
	}
}

/*!
 * \brief Prepare headers for outgoing packet.
 *
 * \param buf     Pointer to future ethernet frame of the msg.
 * \param flags   Basic properties of outgoing msg.
 *
 * \return Pointer where the DNS payload shall be inserted.
 */
static void *xdp_reserve(void *buf, knot_xdp_flags_t flags)
{
	buf = reserve_eth(buf, flags);
	buf = reserve_ip(buf, flags);
	buf = reserve_p(buf, flags);
	return buf;
}

static knot_xdp_payload_t write_eth(knot_xdp_payload_t p, const knot_xdp_msg_t *msg)
{
	struct ethhdr *eth = p.buf;

	check_payload(p, KNOT_XDP_H_NONE, sizeof(*eth));

	memcpy(eth->h_source, msg->eth_from, ETH_ALEN);
	memcpy(eth->h_dest, msg->eth_to, ETH_ALEN);
	eth->h_proto = flags_ip(msg->flags);

	p.buf += sizeof(*eth);
	p.len -= sizeof(*eth);

	return p;
}

static uint16_t from32to16(uint32_t sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

static uint16_t ipv4_checksum(const uint16_t *ipv4_hdr)
{
	uint32_t sum32 = 0;
	for (int i = 0; i < 10; ++i) {
		if (i != 5) {
			sum32 += ipv4_hdr[i];
		}
	}
	return ~from32to16(sum32);
}

static knot_xdp_payload_t write_ipv4(knot_xdp_payload_t p, const knot_xdp_msg_t *msg)
{
	struct iphdr *ip4 = p.buf;

	check_payload(p, KNOT_XDP_H_NONE, sizeof(*ip4));

	ip4->version  = 4;
	ip4->ihl      = 5;
	ip4->tos      = 0;
	ip4->tot_len  = htobe16(5 * 4 + p.len - sizeof(*ip4));
	ip4->id       = 0;
	ip4->frag_off = 0;
	ip4->ttl      = IPDEFTTL;
	ip4->protocol = flags_p(msg->flags);

	const struct sockaddr_in *src_v4 = (const struct sockaddr_in *)&msg->ip_from;
	const struct sockaddr_in *dst_v4 = (const struct sockaddr_in *)&msg->ip_to;
	memcpy(&ip4->saddr, &src_v4->sin_addr, sizeof(src_v4->sin_addr));
	memcpy(&ip4->daddr, &dst_v4->sin_addr, sizeof(dst_v4->sin_addr));

	ip4->check = ipv4_checksum(p.buf);

	p.buf += sizeof(*ip4);
	p.len -= sizeof(*ip4);

	return p;
}

static knot_xdp_payload_t write_ipv6(knot_xdp_payload_t p, const knot_xdp_msg_t *msg)
{
	struct ipv6hdr *ip6 = p.buf;

	check_payload(p, KNOT_XDP_H_NONE, sizeof(*ip6));

	ip6->version     = 6;
	ip6->priority    = 0;
	ip6->payload_len = htobe16(p.len - sizeof(*ip6)); // == p.len afterwards
	ip6->nexthdr     = flags_p(msg->flags);
	ip6->hop_limit   = IPDEFTTL;
	memset(ip6->flow_lbl, 0, sizeof(ip6->flow_lbl));

	const struct sockaddr_in6 *src_v6 = (const struct sockaddr_in6 *)&msg->ip_from;
	const struct sockaddr_in6 *dst_v6 = (const struct sockaddr_in6 *)&msg->ip_to;

	memcpy(&ip6->saddr, &src_v6->sin6_addr, sizeof(src_v6->sin6_addr));
	memcpy(&ip6->daddr, &dst_v6->sin6_addr, sizeof(dst_v6->sin6_addr));

	p.buf += sizeof(*ip6);
	p.len -= sizeof(*ip6);

	return p;
}

/* Checksum endianness implementation notes for ipv4_checksum() and checksum().
 *
 * The basis for checksum is addition on big-endian 16-bit words, with bit 16 carrying
 * over to bit 0.  That can be viewed as first byte carrying to the second and the
 * second one carrying back to the first one, i.e. a symmetrical situation.
 * Therefore the result is the same even when arithmetics is done on litte-endian (!)
 */

static void checksum(uint32_t *result, const void *_data, uint32_t _data_len)
{
	assert(!(_data_len & 1));
	const uint16_t *data = _data;
	uint32_t len = _data_len / 2;
	while (len-- > 0) {
		*result += *data++;
	}
}

static void checksum_uint16(uint32_t *result, uint16_t x)
{
	checksum(result, &x, sizeof(x));
}

static uint16_t checksum_finish(uint32_t result, bool nonzero)
{
	while (result > 0xffff) {
		result = (result & 0xffff) + (result >> 16);
	}
	if (!nonzero || result != 0xffff) {
		result = ~result;
	}
	return result;
}

static void checksum_payload(uint32_t *result, void *payload, size_t paylen)
{
	if (paylen & 1) {
		((uint8_t *)payload)[paylen++] = 0;
	}
	checksum(result, payload, paylen);
}

static knot_xdp_payload_t write_udp(knot_xdp_payload_t p, const knot_xdp_msg_t *msg)
{
	struct udphdr *udp = p.buf;

	check_payload(p, KNOT_XDP_H_NONE, sizeof(*udp));

	udp->len = htobe16(p.len);

	assert(offsetof(struct sockaddr_in, sin_port) == offsetof(struct sockaddr_in6, sin6_port));
	udp->source = msg->ip_from.sin6_port; // already in be16
	udp->dest   = msg->ip_to.sin6_port;

	if (!(msg->flags & KNOT_XDP_IPV6)) {
		udp->check  = 0; // UDP over IPv4 doesn't require checksum
	} else {
		udp->check  = 0; // temporarily to enable checksum calculation

		uint32_t chk = 0;
		checksum(&chk, &msg->ip_from.sin6_addr, sizeof(msg->ip_from.sin6_addr));
		checksum(&chk, &msg->ip_to.sin6_addr,   sizeof(msg->ip_to.sin6_addr));
		checksum(&chk, &udp->len, sizeof(udp->len));
		checksum_uint16(&chk, htobe16(KNOT_XDP_H_UDP));
		checksum(&chk, udp, sizeof(*udp));
		checksum_payload(&chk, p.buf + sizeof(*udp), p.len - sizeof(*udp));
		udp->check = checksum_finish(chk, true);
	}

	p.buf += sizeof(*udp);
	p.len -= sizeof(*udp);

	return p;
}

static knot_xdp_payload_t write_tcp(knot_xdp_payload_t p, const knot_xdp_msg_t *msg)
{
	struct tcphdr *tcp = p.buf;

	check_payload(p, KNOT_XDP_H_NONE, sizeof(*tcp));

	assert(offsetof(struct sockaddr_in, sin_port) == offsetof(struct sockaddr_in6, sin6_port));
	tcp->source = msg->ip_from.sin6_port;
	tcp->dest   = msg->ip_to.sin6_port;

	tcp->doff   = 5; // size of TCP hdr with no options in 32bit dwords

	tcp->seq = htobe32(msg->seqno);
	tcp->ack_seq = htobe32(msg->ackno);

	tcp->syn = ((msg->flags & KNOT_XDP_SYN) ? 1 : 0);
	tcp->ack = ((msg->flags & KNOT_XDP_ACK) ? 1 : 0);
	tcp->fin = ((msg->flags & KNOT_XDP_FIN) ? 1 : 0);
	tcp->rst = ((msg->flags & KNOT_XDP_RST) ? 1 : 0);
	tcp->psh = ((msg->payload.iov_len > 0) ? 1 : 0);

	tcp->window = htobe16(0x8000); // FIXME ???
	tcp->check  = 0; // temporarily to enable checksum calculation

	uint32_t chk = 0;
	if (!(msg->flags & KNOT_XDP_IPV6)) {
		checksum(&chk, &((struct sockaddr_in *)&msg->ip_from)->sin_addr, sizeof(struct in_addr));
		checksum(&chk, &((struct sockaddr_in *)&msg->ip_to)->sin_addr,   sizeof(struct in_addr));
	} else {
		checksum(&chk, &msg->ip_from.sin6_addr, sizeof(msg->ip_from.sin6_addr));
		checksum(&chk, &msg->ip_to.sin6_addr,   sizeof(msg->ip_to.sin6_addr));
	}
	checksum_uint16(&chk, htobe16(KNOT_XDP_H_TCP));
	checksum_uint16(&chk, htobe16(p.len));
	checksum(&chk, tcp, sizeof(*tcp));
	if (msg->payload.iov_len > 0) {
		checksum_uint16(&chk, htobe16(msg->payload.iov_len));
		checksum_payload(&chk, msg->payload.iov_base, msg->payload.iov_len);
	}
	tcp->check = checksum_finish(chk, false);

	p.buf += sizeof(*tcp);
	p.len -= sizeof(*tcp);
	return p;
}

static knot_xdp_payload_t write_payload(knot_xdp_payload_t p, const knot_xdp_msg_t *msg)
{
	if (msg != NULL && msg->payload.iov_len == 0) {
		return p;
	}

	uint16_t len = p.len - sizeof(len);

	check_payload(p, KNOT_XDP_H_NONE, sizeof(len));

	*(uint16_t *)p.buf = htobe16(len);

	p.buf += sizeof(len);
	p.len -= sizeof(len);

	return p;
}

int knot_xdp_write_all(knot_xdp_payload_t p, const knot_xdp_msg_t *msg)
{
	p = write_eth(p, msg);

	if (!(msg->flags & KNOT_XDP_IPV6)) {
		p = write_ipv4(p, msg);
	} else {
		p = write_ipv6(p, msg);
	}

	if (!(msg->flags & KNOT_XDP_TCP)) {
		p = write_udp(p, msg);
	} else {
		p = write_tcp(p, msg);
		p = write_payload(p, msg);
	}

	if (p.err == KNOT_EOK && msg->payload.iov_len > 0) {
		assert(p.buf == msg->payload.iov_base);
		assert(p.len == msg->payload.iov_len);
	}

	return p.err;
}

bool knot_xdp_empty_msg(const knot_xdp_msg_t *msg)
{
	if (msg->payload.iov_len > 0) {
		return false;
	}
	if (msg->flags & KNOT_XDP_TCPFL) {
		assert(msg->flags & KNOT_XDP_TCP);
		return false;
	}
	return true;
}

// FIXME do we care for better random?
static uint32_t rnd_uint32(void)
{
	uint32_t res = rand() & 0xffff;
	res <<= 16;
	res |= rand() & 0xffff;
	return res;
}

static void msg_init_base(knot_xdp_msg_t *msg, void *buf, size_t buf_size,
                          knot_xdp_flags_t flags, size_t headroom)
{
	memset(msg, 0, sizeof(*msg));

	msg->flags = flags;

	struct ethhdr *eth = buf + headroom;
	assert(buf_size >= sizeof(*eth) + headroom);

	memcpy(msg->eth_from, eth->h_source, ETH_ALEN);
	memcpy(msg->eth_to,   eth->h_dest,   ETH_ALEN);

	msg->payload.iov_base = xdp_reserve(buf + headroom, flags);
	assert(buf_size >= msg->payload.iov_base - buf);
	msg->payload.iov_len = buf_size - (msg->payload.iov_base - buf) - headroom;

	msg->xdp_headroom = headroom;
}

void knot_xdp_msg_init(knot_xdp_msg_t *msg, void *buf, size_t buf_size, knot_xdp_flags_t flags)
{
	msg_init_base(msg, buf, buf_size, flags, 0);

	if (flags & KNOT_XDP_TCP) {
		msg->ackno = 0;
		msg->seqno = rnd_uint32();
	}
}

void knot_xdp_msg_answer(knot_xdp_msg_t *msg, void *buf, size_t buf_size, const knot_xdp_msg_t *from)
{
	msg_init_base(msg, buf, buf_size, from->flags & (KNOT_XDP_IPV6 | KNOT_XDP_TCP), 0);

	memcpy(msg->eth_from, from->eth_to, ETH_ALEN);
	memcpy(msg->eth_to,   from->eth_from, ETH_ALEN);

	memcpy(&msg->ip_from, &from->ip_to, sizeof(msg->ip_from));
	memcpy(&msg->ip_to, &from->ip_from, sizeof(msg->ip_to));

	if (msg->flags & KNOT_XDP_TCP) {
		assert(from->flags & KNOT_XDP_TCP);
		msg->ackno = from->seqno;
		msg->ackno += from->payload.iov_len;
		if (from->flags & (KNOT_XDP_SYN | KNOT_XDP_FIN)) {
			msg->ackno++;
		}
		msg->seqno = from->ackno;
		if (msg->seqno == 0) {
			msg->seqno = rnd_uint32();
		}
	}
}
