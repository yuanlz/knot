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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <netinet/in.h>

typedef enum {
	KNOT_XDP_IPV6   = (1 << 0), /*!< This packet is a IPv6 (IPv4 otherwise). */
	KNOT_XDP_TCP    = (1 << 1), /*!< This packet is a TCP (UDP otherwise). */
	KNOT_XDP_SYN    = (1 << 2), /*!< SYN flag set (TCP only). */
	KNOT_XDP_ACK    = (1 << 3), /*!< ACK flag set (TCP only). */
	KNOT_XDP_FIN    = (1 << 4), /*!< FIN flag set (TCP only). */
	KNOT_XDP_RST    = (1 << 5), /*!< RST flag set (TCP only). */
	KNOT_XDP_TCPFL  = KNOT_XDP_SYN | KNOT_XDP_ACK | KNOT_XDP_FIN | KNOT_XDP_RST,
} knot_xdp_flags_t;

/*! \brief A packet with src & dst MAC & IP addrs + DNS payload. */
typedef struct knot_xdp_msg knot_xdp_msg_t;
struct knot_xdp_msg {
	struct sockaddr_in6 ip_from;
	struct sockaddr_in6 ip_to;
	uint8_t eth_from[ETH_ALEN];
	uint8_t eth_to[ETH_ALEN];
	knot_xdp_flags_t flags;
	uint32_t seqno;
	uint32_t ackno;
	struct iovec payload;
	intptr_t xdp_headroom;
};

typedef enum {
	KNOT_XDP_H_NONE = 0,                            // unknown/any payload follows
	KNOT_XDP_H_DNS_MSG,                             // payload is a single DNS message
	KNOT_XDP_H_DNS_PAYLOAD,                         // payload is a fraction of s data stream formed from DNS messages
	KNOT_XDP_H_ETH,                                 // ethernet frame
	KNOT_XDP_H_IPV4 = __constant_htons(ETH_P_IP),   // IPv4 frame
	KNOT_XDP_H_IPV6 = __constant_htons(ETH_P_IPV6), // IPv6 frame
	KNOT_XDP_H_UDP = IPPROTO_UDP,                   // UDP frame
	KNOT_XDP_H_TCP = IPPROTO_TCP,                   // TCP frame
} knot_xdp_proto_t;

typedef struct {
	void *buf;
	size_t len;
	int err;
	uint16_t next_proto;
} knot_xdp_payload_t;

/*!
 * \brief Parse incomming packet's eth, IP and UDP/TCP headers.
 *
 * \param p     Ethernet frame of incomming packet.
 * \param msg   Optional: msg struct to be filled with parsed details.
 *
 * \return DNS payload of incomming packet, or KNOT_E*
 */
knot_xdp_payload_t knot_xdp_read_all(knot_xdp_payload_t p, knot_xdp_msg_t *msg);

/*!
 * \brief Write outgoing packet's eth, IP and UDP/TCP headers.
 *
 * \warning Packet payload must be written beforehand, otherwise incorrect checksum.
 *
 * \warning Frame length must be already set according to payload length.
 *
 * \param p      Pointer to ethernet frame of the msg.
 * \param msg    Msg struct with packet details.
 *
 * \return KNOT_E*
 */
int knot_xdp_write_all(const knot_xdp_msg_t *msg, uint8_t *frame, size_t frame_len);

/*!
 * \brief If true, then this message is empty and shall not be sent.
 */
bool knot_xdp_empty_msg(const knot_xdp_msg_t *msg);

/*!
 * \brief Initialize empty msg struct to be filled with packet.
 *
 * \param msg         Msg to be initialized.
 * \param buf         Buffer available.
 * \param buf_size    Size of buffer.
 * \param flags       Desired msg type (IP version, UDP/TCP).
 */
void knot_xdp_msg_init(knot_xdp_msg_t *msg, void *buf, size_t buf_size, knot_xdp_flags_t flags);

/*!
 * \brief Initialize msg struct as an answer to incomming one.
 *
 * \param msg        Msg to be initialized.
 * \param buf        Buffer available.
 * \param buf_size   Size of buffer.
 * \param from       Incomming msg to be answered.
 */
void knot_xdp_msg_answer(knot_xdp_msg_t *msg, void *buf, size_t buf_size, const knot_xdp_msg_t *from);
