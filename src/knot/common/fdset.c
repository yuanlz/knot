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

int fdset_remove_it(fdset_t *set, fdset_it_t *it)
{
	if (set == NULL || it == NULL) {
		return KNOT_EINVAL;
	}

	/* Decrement number of elms. */
	--set->n;

	/* Nothing else if it is the last one.
	 * Move last -> i if some remain. */
	unsigned last = set->n; /* Already decremented */
	unsigned int i = it->idx;
	if (i < last) {
		set->pfd[i] = set->pfd[last];
		set->timeout[i] = set->timeout[last];
		set->ctx[i] = set->ctx[last];
	}
	it->idx--;

	return KNOT_EOK;
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

int fdset_wait(fdset_t *set, fdset_it_t *it, unsigned offset, unsigned ev_size, int timeout)
{
	it->ctx = set;
	it->idx = offset;

	it->left = poll(&set->pfd[offset], ev_size, 1000 * timeout);
	while(it->left > 0 && set->pfd[it->idx].revents == 0) {
		it->idx++;
	}
	return it->left;
}

int fdset_set_watchdog(fdset_t* set, unsigned i, int interval)
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

int fdset_get_fd(fdset_t *set, unsigned i)
{
	if (set == NULL || i >= set->n) {
		return KNOT_EINVAL;
	}

	return set->pfd[i].fd;
}


unsigned fdset_get_length(fdset_t *set)
{
	return set->n;
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
			int fd = fdset_get_fd(set, i);
			if (cb(set, fd, data) == FDSET_SWEEP) {
				if (fdset_remove(set, i) == KNOT_EOK)
					continue; /* Stay on the index. */
			}
		}

		/* Next descriptor. */
		++i;
	}

	return KNOT_EOK;
}

void fdset_it_next(fdset_it_t *it)
{
	it->left--;
	if (it->left > 0) {
		do {
			it->idx++;
		} while (it->ctx->pfd[it->idx].revents == 0);
	}
}

int fdset_it_done(fdset_it_t *it)
{
	return it->left <= 0;
}


int fdset_it_get_fd(fdset_it_t *it)
{
	if (it == NULL) {
		return KNOT_EINVAL;
	}

	return it->ctx->pfd[it->idx].fd;
}

unsigned fdset_it_get_idx(fdset_it_t *it)
{
	assert(it);
	return it->idx;
}

int fdset_it_ev_is_poll(fdset_it_t *it)
{
	assert(it);
	return it->ctx->pfd[it->idx].revents & POLLIN;
}

int fdset_it_ev_is_err(fdset_it_t *it)
{
	assert(it);
	return it->ctx->pfd[it->idx].revents & (POLLERR|POLLHUP|POLLNVAL);
}