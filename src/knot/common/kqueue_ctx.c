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

#ifdef USE_KQUEUE

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <poll.h>
#include "knot/common/kqueue_ctx.h"
#include "contrib/time.h"
#include "libknot/errcode.h"

/* Realloc memory or return error (part of fdset_resize). */
#define MEM_RESIZE(tmp, p, n) \
	if ((tmp = realloc((p), (n) * sizeof(*p))) == NULL) \
		return KNOT_ENOMEM; \
	(p) = tmp;

static int kqueue_ctx_resize(kqueue_ctx_t *set, unsigned size)
{
	void *tmp = NULL;
	MEM_RESIZE(tmp, set->usrctx, size);
	MEM_RESIZE(tmp, set->timeout, size);
	MEM_RESIZE(tmp, set->ev, size);
	set->size = size;
	return KNOT_EOK;
}

int kqueue_ctx_init(kqueue_ctx_t *set, unsigned size)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	memset(set, 0, sizeof(kqueue_ctx_t));

	set->ctx = kqueue();
	if (set->ctx < 0) {
		return KNOT_ENOMEM;
	}
	
	return kqueue_ctx_resize(set, size);
}

int kqueue_ctx_clear(kqueue_ctx_t* set)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	free(set->usrctx);
	free(set->timeout);
	free(set->ev);
	set->n = 0;
	set->size = 0;
	set->ev = NULL;
	set->usrctx = NULL;
	set->timeout = NULL;

	return KNOT_EOK;
}

void kqueue_ctx_close(kqueue_ctx_t* set)
{
	close(set->ctx);
}

int kqueue_ctx_add(kqueue_ctx_t *set, int fd, unsigned events, void *ctx)
{
	if (set == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	if ((events & POLLIN) == 0) {
		return KNOT_ENOTSUP;
	}

	/* Realloc needed. */
	if (set->n == set->size && kqueue_ctx_resize(set, set->size + KQUEUE_CTX_INIT_SIZE))
		return KNOT_ENOMEM;

	/* Initialize. */
	int i = set->n++;
	EV_SET(&set->ev[i], fd, EVFILT_READ, EV_ADD|EV_DISABLE, 0, 0, (void*)(intptr_t)i);
	set->usrctx[i] = ctx;
	set->timeout[i] = 0;
	kevent(set->ctx, &set->ev[i], 1, NULL, 0, NULL);
	EV_SET(&set->ev[i], fd, EVFILT_READ, EV_ADD|EV_ENABLE|EV_DISPATCH, 0, 0, (void*)(intptr_t)i);
	
	return i;
}

int kqueue_ctx_wait(kqueue_ctx_t *set, struct kevent *ev, size_t offset, size_t ev_size, int timeout)
{
    struct timespec to = {
		.tv_sec = timeout,
		.tv_nsec = 0
	};
	kevent(set->ctx, &set->ev[offset], ev_size, NULL, 0, NULL);
	return kevent(set->ctx, NULL, 0, ev, ev_size, (timeout > 0) ? &to : NULL);
}

int kqueue_ctx_remove(kqueue_ctx_t *set, unsigned i)
{
	if (set == NULL || i >= set->n) {
		return KNOT_EINVAL;
	}

	/* Decrement number of elms. */
	--set->n;

	/* Nothing else if it is the last one.
	 * Move last -> i if some remain. */
	unsigned last = set->n; /* Already decremented */
	struct kevent update[2];
	int update_size = 0;
	EV_SET(&update[update_size++], set->ev[i].ident, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	if (i < last) {
		set->ev[i] = set->ev[last];
		set->timeout[i] = set->timeout[last];
		set->usrctx[i] = set->usrctx[last];
		EV_SET(&update[update_size++], set->ev[last].ident, EVFILT_READ, EV_ADD, 0, 0, (void*)(intptr_t)i);
	}
	kevent(set->ctx, update, update_size, NULL, 0, NULL);

	return KNOT_EOK;
}

int kqueue_ctx_set_watchdog(kqueue_ctx_t* set, int i, int interval)
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

int kqueue_ctx_sweep(kqueue_ctx_t* set, kqueue_ctx_sweep_cb_t cb, void *data)
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
			if (cb(set, i, data) == KQUEUE_CTX_SWEEP) {
				if (kqueue_ctx_remove(set, i) == KNOT_EOK)
					continue; /* Stay on the index. */
			}
		}

		/* Next descriptor. */
		++i;
	}

	return KNOT_EOK;
}

#endif