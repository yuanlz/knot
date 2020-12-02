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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <sys/epoll.h>
#include "knot/common/fdset.h"
#include "contrib/time.h"
#include "libknot/errcode.h"

/* Realloc memory or return error (part of fdset_resize). */
#define MEM_RESIZE(tmp, p, n) \
	if ((tmp = realloc((p), (n) * sizeof(*p))) == NULL) \
		return KNOT_ENOMEM; \
	(p) = tmp;

static int fdset_resize(fdset_t *set, unsigned size)
{
	void *tmp = NULL;
	MEM_RESIZE(tmp, set->ctx, size);
	MEM_RESIZE(tmp, set->pfd, size);
	MEM_RESIZE(tmp, set->timeout, size);
	set->size = size;
	return KNOT_EOK;
}

int fdset_init(fdset_t *set, unsigned size)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	memset(set, 0, sizeof(fdset_t));
	return fdset_resize(set, size);
}

static int efdset_resize(efdset_t *set, unsigned size)
{
	void *tmp = NULL;
	MEM_RESIZE(tmp, set->ev_data, size);
	set->size = size;
	return KNOT_EOK;
}

int efdset_init(efdset_t *set, unsigned size)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	memset(set, 0, sizeof(fdset_t));
	set->epollfd = epoll_create1(0);
	return efdset_resize(set, size);
}

int fdset_clear(fdset_t* set)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	free(set->ctx);
	free(set->pfd);
	free(set->timeout);
	memset(set, 0, sizeof(fdset_t));
	return KNOT_EOK;
}

int efdset_clear(efdset_t* set)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}
	close(set->epollfd);
	free(set->ev_data);
	memset(set, 0, sizeof(fdset_t));
	return KNOT_EOK;
}

int fdset_add(fdset_t *set, int fd, unsigned events, void *ctx)
{
	if (set == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	/* Realloc needed. */
	if (set->n == set->size && fdset_resize(set, set->size + FDSET_INIT_SIZE))
		return KNOT_ENOMEM;

	/* Initialize. */
	int i = set->n++;
	set->pfd[i].fd = fd;
	set->pfd[i].events = events;
	set->pfd[i].revents = 0;
	set->ctx[i] = ctx;
	set->timeout[i] = 0;

	/* Return index to this descriptor. */
	return i;
}

int efdset_add(efdset_t *set, int fd, unsigned events, epoll_usr_data_fdtype_t type, void *ctx)
{
	if (set == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	/* Realloc needed. */
	if (set->n == set->size && efdset_resize(set, set->size + FDSET_INIT_SIZE))
		return KNOT_ENOMEM;

	/* Initialize. */
	int i = set->n++;
	struct epoll_event ev;
	efdset_data_t *data = &(set->ev_data[i]); //maybe will need alloc
	data->fd = fd;
	data->type = type;
	data->ctx = ctx;
	data->timeout = 0;
	ev.data.ptr = data;
	ev.events = events;
	epoll_ctl(set->epollfd, EPOLL_CTL_ADD, fd, &ev);

	/* Return index to this descriptor. */
	return i;
}

int fdset_remove(fdset_t *set, unsigned i)
{
	if (set == NULL || i >= set->n) {
		return KNOT_EINVAL;
	}

	/* Decrement number of elms. */
	--set->n;

	/* Nothing else if it is the last one.
	 * Move last -> i if some remain. */
	unsigned last = set->n; /* Already decremented */
	if (i < last) {
		set->pfd[i] = set->pfd[last];
		set->timeout[i] = set->timeout[last];
		set->ctx[i] = set->ctx[last];
	}

	return KNOT_EOK;
}

int efdset_remove(efdset_t *set, efdset_data_t *data)
{
	assert(data != NULL);
	unsigned i = data - set->ev_data;
	if (set == NULL || i >= set->n) {
		return KNOT_EINVAL;
	}

	/* Decrement number of elms. */
	--set->n;
	epoll_ctl(set->epollfd, EPOLL_CTL_DEL, data->fd, NULL);

	/* Nothing else if it is the last one.
	 * Move last -> i if some remain. */
	unsigned last = set->n; /* Already decremented */
	if (i < last) {
		set->ev_data[i] = set->ev_data[last];
		struct epoll_event new_ev;
		new_ev.data.ptr = &set->ev_data[i];
		new_ev.events = POLLIN;
		epoll_ctl(set->epollfd, EPOLL_CTL_MOD, set->ev_data[i].fd, &new_ev);
	}

	return KNOT_EOK;
}

int fdset_set_watchdog(fdset_t* set, int i, int interval)
{
	if (set == NULL || i >= set->n) {
		return KNOT_EINVAL;
	}

	/* Lift watchdog if interval is negative. */
	if (interval < 0) {
		set->timeout[i] = 0;
		return KNOT_EOK;
	}

	/* Update clock. */
	struct timespec now = time_now();

	set->timeout[i] = now.tv_sec + interval; /* Only seconds precision. */
	return KNOT_EOK;
}


int efdset_set_watchdog(efdset_t* set, int i, int interval)
{
	if (set == NULL || i >= set->n) {
		return KNOT_EINVAL;
	}

	/* Lift watchdog if interval is negative. */
	if (interval < 0) {
		set->ev_data[i].timeout = 0;
		return KNOT_EOK;
	}

	/* Update clock. */
	struct timespec now = time_now();

	set->ev_data[i].timeout = now.tv_sec + interval; /* Only seconds precision. */
	return KNOT_EOK;
}

int fdset_sweep(fdset_t* set, fdset_sweep_cb_t cb, void *data)
{
	if (set == NULL || cb == NULL) {
		return KNOT_EINVAL;
	}

	/* Get time threshold. */
	struct timespec now = time_now();

	unsigned i = 0;
	while (i < set->n) {

		/* Check sweep state, remove if requested. */
		if (set->timeout[i] > 0 && set->timeout[i] <= now.tv_sec) {
			if (cb(set, i, data) == FDSET_SWEEP) {
				if (fdset_remove(set, i) == KNOT_EOK)
					continue; /* Stay on the index. */
			}
		}

		/* Next descriptor. */
		++i;
	}

	return KNOT_EOK;
}

int efdset_sweep(efdset_t* set, fdset_sweep_cb_t cb, void *data)
{
	if (set == NULL || cb == NULL) {
		return KNOT_EINVAL;
	}

	/* Get time threshold. */
	struct timespec now = time_now();

	unsigned i = 0;
	while (i < set->n) {

		/* Check sweep state, remove if requested. */
		if (set->ev_data[i].timeout > 0 && set->ev_data[i].timeout <= now.tv_sec) {
			//TODO sweep
			if (cb(set, i, data) == FDSET_SWEEP) {
				if (efdset_remove(set, &(set->ev_data[i])) == KNOT_EOK)
					continue; /* Stay on the index. */
			}
		}

		/* Next descriptor. */
		++i;
	}

	return KNOT_EOK;
}
