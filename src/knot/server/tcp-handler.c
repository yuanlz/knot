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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <urcu.h>
#ifdef HAVE_SYS_UIO_H			// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif // HAVE_SYS_UIO_H
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "dnssec/random.h"
#include "knot/server/tcp-handler.h"
#include "knot/common/fdset.h"
#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "contrib/ucw/mempool.h"

typedef struct tcp_context {
	fdset_t set;                     /*!< Set of server/client sockets. */
	unsigned thread_id;              /*!< Thread identifier. */
	server_t *server;                /*!< Name server structure. */
	unsigned client_threshold;
	struct timespec now;
	int process;
	int polltime;
} tcp_context_t;

static inline struct timespec tcp_time(tcp_context_t *ctx)
{
	return ctx->now;
}

enum tcp_client_state {
	CLIENT_READ,
	CLIENT_WRITE,
	CLIENT_PROCESS,
};

typedef struct tcp_client {
	tcp_context_t *tcp;
	enum tcp_client_state state;
	int fd;
	knot_layer_t layer;             
	struct iovec rx;    
	struct iovec tx;
	struct process_query_param param;
	struct sockaddr_storage remote;
	knot_pkt_t *query;
	knot_pkt_t *ans;
	unsigned fdset_pos;
	knot_mm_t mm;
} tcp_client_t;

static bool tcp_active_state(int state)
{
	return (state == KNOT_STATE_PRODUCE || state == KNOT_STATE_FAIL);
}

static bool tcp_send_state(int state)
{
	return (state != KNOT_STATE_FAIL && state != KNOT_STATE_NOOP);
}

int tcp_accept(int fd)
{
	/* Accept incoming connection. */
	int incoming = net_accept(fd, NULL);

	/* Evaluate connection. */
	if (incoming >= 0) {
#ifdef SO_RCVTIMEO
		struct timeval tv;
		rcu_read_lock();
		tv.tv_sec = conf()->cache.srv_tcp_idle_timeout;
		rcu_read_unlock();
		tv.tv_usec = 0;
		if (setsockopt(incoming, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
			log_warning("TCP, failed to set up watchdog timer"
			            ", fd %d", incoming);
		}
#endif
	}

	return incoming;
}

static int client_add(tcp_client_t *client)
{
	int id = fdset_add(&client->tcp->set, client->fd, POLLIN, NULL);
	if (id < 0) {
		return id; /* Contains errno. */
	}
	client->tcp->set.ctx[id] = client;
	client->fdset_pos = id;

	rcu_read_lock();
	int timeout = conf()->cache.srv_tcp_hshake_timeout;
	fdset_set_watchdog(&client->tcp->set, id, timeout);
	rcu_read_unlock();
	return KNOT_EOK;
}


static void client_start(tcp_client_t *client)
{
	client->param.socket = client->fd ;
	client->param.remote = &client->remote;
	client->param.server = client->tcp->server;
	client->param.thread_id = client->tcp->thread_id;
	
	client->rx.iov_len = KNOT_WIRE_MAX_PKTSIZE;
	client->tx.iov_len = KNOT_WIRE_MAX_PKTSIZE;
	client->rx.iov_base = mm_alloc(&client->mm, client->rx.iov_len);
	client->rx.iov_base = mm_alloc(&client->mm, client->rx.iov_len);
}

static int tcp_new_client(tcp_context_t *tcp, int fd)
{
	int client_fd, ret;
	client_fd = ret = tcp_accept(fd);
	if (ret < 0) {
		return ret;
	}

	tcp_client_t *client = calloc(1, sizeof(tcp_client_t));

	client->tcp = tcp;
	client->fd = client_fd;

	ret = client_add(client);
	if (ret != KNOT_EOK) {
		close(client->fd);
		free(client);
		return ret;
	}

	mm_ctx_mempool(&client->mm,  16 * MM_DEFAULT_BLKSIZE);
	knot_layer_init(&client->layer, &client->mm, process_query_layer());

	/* Receive peer name. */
	socklen_t addrlen = sizeof(struct sockaddr_storage);
	getpeername(client_fd, (struct sockaddr *)&client->remote, &addrlen);

	client_start(client);
}

static void client_set_state(tcp_client_t *client, int state)
{
	if (client->state == CLIENT_PROCESS) {
		client->tcp->process--;
	}
	switch (state) {
		case CLIENT_READ:
			client->tcp->set.pfd[client->fdset_pos].events = POLLIN;
			break;
		case CLIENT_WRITE:
			client->tcp->set.pfd[client->fdset_pos].events = POLLOUT;
			break;
		case CLIENT_PROCESS:
			client->tcp->set.pfd[client->fdset_pos].events = 0;
			client->tcp->process++;
			break;
	}
	client->state = state;
}

static void tcp_client_free(tcp_client_t *client)
{
	mp_delete(client->mm.ctx);
	free(client);
}

static int client_read(tcp_client_t *client)
{
	client_start(client);
	
	rcu_read_lock();
	int timeout = 1000 * conf()->cache.srv_tcp_reply_timeout;
	rcu_read_unlock();
	int ret = net_dns_tcp_recv(client->fd,
	                           client->rx.iov_base,
				   client->rx.iov_len,
				   timeout);
	if (ret <= 0) {
		if (ret == KNOT_EAGAIN) {
			char addr_str[SOCKADDR_STRLEN] = {0};
			sockaddr_tostr(addr_str, sizeof(addr_str),
				(struct sockaddr *)&client->remote);
			log_warning("TCP, connection timed out, address '%s'",
			            addr_str);
		}
		return KNOT_ECONNREFUSED;
	} else {
		client->rx.iov_len = ret;
	}
	/* Initialize processing layer. */
	knot_layer_begin(&client->layer, &client->param);

	/* Create packets. */
	client->query = knot_pkt_new(client->rx.iov_base,
	                             client->rx.iov_len,
				     client->layer.mm);
	client->ans = knot_pkt_new(client->tx.iov_base,
	                           client->tx.iov_len,
		                   client->layer.mm);
	/* Input packet. */
	(void) knot_pkt_parse(client->query, 0);
	knot_layer_consume(&client->layer, client->query);

	client_set_state(client, CLIENT_PROCESS);

	return KNOT_EOK;
}

static int client_query_finnish(tcp_client_t *client)
{
	/* Reset after processing. */
	knot_layer_finish(&client->layer);

	/* Cleanup. */
	knot_pkt_free(&client->query);
	knot_pkt_free(&client->ans);

	mp_flush(client->layer.mm->ctx);
}

static void client_process(tcp_client_t *client)
{
	while (tcp_active_state(client->layer.state)) {
		knot_layer_produce(&client->layer, client->ans);
		/* Send, if response generation passed and wasn't ignored. */
		if (client->ans->size > 0 && tcp_send_state(client->layer.state)) {
			client_set_state(client, CLIENT_WRITE);
			return;
		}
	}
	client_query_finnish(client);

	client_set_state(client, CLIENT_READ);
}

static int client_write(tcp_client_t *client)
{
	rcu_read_lock();
	int timeout = 1000 * conf()->cache.srv_tcp_reply_timeout;
	rcu_read_unlock();

	knot_pkt_t *ans = client->ans;
	assert(ans != NULL);

	if (net_dns_tcp_send(client->fd, ans->wire, ans->size, timeout) != ans->size) {
		return KNOT_ECONNREFUSED;
	}
	client_set_state(client, CLIENT_PROCESS);
	return KNOT_EOK;
}



void tcp_loop(tcp_context_t *tcp)
{
	// POLL
	tcp->now = time_now();
	fdset_t *set = &tcp->set;
	int nfds = poll(set->pfd, set->n,tcp->process > 0 ? 0 : TCP_SWEEP_INTERVAL * 1000)
	 + tcp->process;

	/* Process events. */
	unsigned i = 0;
	while (i < set->n && nfds > 0) {
		bool should_close = false;
		int fd = set->pfd[i].fd;
		int revents = set->pfd[i].revents;
		
		if (i < tcp->client_threshold) {
			if (revents & (POLLIN)) {
				tcp_new_client(tcp, fd);
				--nfds;
			}
			++i;
			continue;
		}
		tcp_client_t *client = set->ctx[i];
		
		if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
			should_close = (i >= tcp->client_threshold);
			--nfds;
		}
		if (revents & (POLLOUT) && client->state == CLIENT_WRITE) {
			should_close = client_write(client) != KNOT_EOK;
			--nfds;
		}
		if (revents & (POLLIN)  && client->state == CLIENT_READ) {
			if (client_read(client) != KNOT_EOK) {
					should_close = true;
			}
			--nfds;
		}

		// PROCESS
		if (client->state == CLIENT_PROCESS) {
			client_process(client);
			if (client->state == CLIENT_WRITE && client->ans->size < 512) {
				// TRY_WRITE
				should_close = client_write(client) != KNOT_EOK;
			}
		}


		if (should_close) {
			close(fd);
			fdset_remove(set, i);
			((tcp_client_t *)set->ctx[i])->fdset_pos = i;
			tcp_client_free(client);
			continue;
		}
		

		++i;
	}
}

int tcp_master(dthread_t *thread)
{
	if (!thread || !thread->data) {
		return KNOT_EINVAL;
	}

	iohandler_t *handler = (iohandler_t *)thread->data;
	unsigned *iostate = &handler->thread_state[dt_get_id(thread)];

	int ret = KNOT_EOK;
	ref_t *ref = NULL;
	tcp_context_t tcp;
	memset(&tcp, 0, sizeof(tcp_context_t));

	tcp.server = handler->server;
	tcp.thread_id = handler->thread_id[dt_get_id(thread)];

	/* Prepare structures for bound sockets. */
	conf_val_t val = conf_get(conf(), C_SRV, C_LISTEN);
	fdset_init(&tcp.set, conf_val_count(&val) + CONF_XFERS);

	for(;;) {
		/* Check handler state. */
		if (unlikely(*iostate & ServerReload)) {
			*iostate &= ~ServerReload;

			/* Cancel client connections. */
			for (unsigned i = tcp.client_threshold; i < tcp.set.n; ++i) {
				tcp_client_t *client = tcp.set.ctx[i];
				if (client->state != CLIENT_READ) {
					client_query_finnish(client);
				}
				close(tcp.set.pfd[i].fd);
				tcp_client_free(client);
			}

			ref_release(ref);
			ref = server_set_ifaces(handler->server, &tcp.set, IO_TCP, tcp.thread_id);
			if (tcp.set.n == 0) {
				break; /* Terminate on zero interfaces. */
			}

			tcp.client_threshold = tcp.set.n;
		}

		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		tcp_loop(&tcp);
	}

	
	for (unsigned i = tcp.client_threshold; i < tcp.set.n; ++i) {
				tcp_client_t *client = tcp.set.ctx[i];
				if (client->state != CLIENT_READ) {
					client_query_finnish(client);
				}		
		close(tcp.set.pfd[i].fd);
		tcp_client_free(tcp.set.ctx[i]);
	}
	fdset_clear(&tcp.set);
	ref_release(ref);

	return ret;
}