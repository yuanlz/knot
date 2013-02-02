/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file dig_params.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief dig command line parameters.
 *
 * \addtogroup knot_utils
 * @{
 */

#ifndef _DIG__DIG_PARAMS_H_
#define _DIG__DIG_PARAMS_H_

#include <stdbool.h>			// bool

#include "utils/common/params.h"	// params_t

/*! \brief Structure containing basic parameters for DNS query. */
typedef struct {
	/*!< List node (for list container). */
	node		n;
	/*!< Name to query on. */
	char		*qname;
	/*!< Class number (16unsigned + -1 uninitialized). */
	int32_t		qclass;
	/*!< Type number (16unsigned + -1 uninitialized). */
	int32_t		qtype;
	/*!< SOA serial for XFR. */
	uint32_t	xfr_serial;
} query_t;

typedef struct {
	/*!< Recursion desired flag. */
	bool		rd_flag;
} options_t;

/*! \brief Settings for dig. */
typedef struct {
	/*!< List of nameservers to query to. */
	list		servers;
	/*!< List of DNS queries to process. */
	list		queries;
	/*!< Operation mode. */
	operation_t	operation;
	/*!< Output format. */
	format_t	format;
	/*!< Version of ip protocol to use. */
	ip_t		ip;
	/*!< Type (TCP, UDP) protocol to use. */
	protocol_t	protocol;
	/*!< Default port/service to connect to. */
	char		*port;
	/*!< UDP buffer size. */
	uint32_t	udp_size;
	/*!< Number of UDP retries. */
	uint32_t	retries;
	/*!< Wait for network response in seconds (-1 means forever). */
	int32_t		wait;
	/*!< Stop quering if servfail. */
	bool		servfail_stop;
	/*!< Default class number (16unsigned + -1 uninitialized). */
	int32_t		class_num;
	/*!< Default type number (16unsigned + -1 uninitialized). */
	int32_t		type_num;
	/*!< Default SOA serial for XFR. */
	uint32_t	xfr_serial;
	/*!< Global options. */
	options_t	options;
} dig_params_t;

query_t* query_create(const char    *qname,
                      const int32_t qtype,
                      const int32_t qclass);
void query_free(query_t *query);

int dig_parse(dig_params_t *params, int argc, char *argv[]);
void dig_clean(dig_params_t *params);

#endif // _DIG__DIG_PARAMS_H_

/*! @} */
