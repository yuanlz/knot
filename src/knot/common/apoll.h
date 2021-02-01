#pragma once

enum apoll_sweep_state {
	APOLL_CTX_KEEP,
	APOLL_CTX_SWEEP
};

#define USE_KQUEUE 1

#ifdef USE_EPOLL
	//TODO, maybe impossible to implement abstractly (or will just take a time)
	#define apoll_ctx_t fdset_t
	#define apoll_get_fd_from_idx(ctx, idx) ctx->ev[idx].data.fd
#elif USE_AIO
	#include "knot/common/aio_ctx.h"

	#define apoll_ctx_t aio_ctx_t
	#define apoll_ctx_init(ctx, size) aio_ctx_init(ctx, size)
	#define apoll_ctx_add(ctx, fd, ev, usr_ctx) aio_ctx_add(ctx, fd, ev, usr_ctx)
	#define apoll_ctx_remove(ctx, idx) aio_ctx_remove(set, idx)
	#define apoll_ctx_set_watchdog(ctx, idx, timeout) aio_ctx_set_watchdog(ctx, idx, timeout)
	#define apoll_ctx_wait(ctx, events, offset, len, timeout) aio_ctx_wait((ctx), events, offset, len, timeout)
	#define apoll_ctx_sweep(ctx, cb, data) aio_ctx_sweep(ctx, cb, data)
	#define apoll_ctx_close(ctx)
	#define apoll_ctx_clear(ctx) aio_ctx_clear(ctx)
	#define apoll_events_init(name, size) struct io_event name[size]
	#define apoll_get_fd_from_idx(ctx, idx) (ctx)->ev[idx].aio_fildes
	#define apoll_foreach(ctx, events, events_len, it) unsigned int _nevent = events_len > 0 ? (unsigned int)(events_len) : 0; \
		for (struct io_event *it = events; _nevent > 0; ++it)
	#define apoll_foreach_done() --_nevent
	#define apoll_it_idx(ctx, it) ((struct iocb *)it->obj - (ctx)->ev)
	#define apoll_it_events(it) ((struct iocb *)it->obj)->aio_buf
	#define apoll_it_event_poll(it) (((struct iocb *)((it)->obj))->aio_buf & (POLLIN))
	#define apoll_it_event_error(it) (((struct iocb *)((it)->obj))->aio_buf & (POLLERR|POLLHUP|POLLNVAL))
#elif USE_KQUEUE
	#include "knot/common/kqueue_ctx.h"

	#define apoll_ctx_t kqueue_ctx_t
	#define apoll_ctx_init(ctx, size) kqueue_ctx_init(ctx, size)
	#define apoll_ctx_add(ctx, fd, ev, usr_ctx) kqueue_ctx_add(ctx, fd, ev, usr_ctx)
	#define apoll_ctx_remove(ctx, idx) kqueue_ctx_remove(set, idx)
	#define apoll_ctx_set_watchdog(ctx, idx, timeout) kqueue_ctx_set_watchdog(ctx, idx, timeout)
	#define apoll_ctx_wait(ctx, events, offset, len, timeout) kqueue_ctx_wait((ctx), events, offset, len, timeout)
	#define apoll_ctx_sweep(ctx, cb, data) kqueue_ctx_sweep(ctx, cb, data)
	#define apoll_ctx_close(ctx) kqueue_ctx_close(ctx)
	#define apoll_ctx_clear(ctx) kqueue_ctx_clear(ctx)
	#define apoll_events_init(name, size) struct kevent name[size]
	#define apoll_get_fd_from_idx(ctx, idx) (ctx)->ev[idx].ident
	#define apoll_foreach(ctx, events, events_len, it) unsigned int _nevent = events_len; \
		for (struct kevent *it = events; _nevent > 0; ++it)
	#define apoll_foreach_done() --_nevent
	#define apoll_it_idx(ctx, it) ((unsigned int)(intptr_t)(it->udata))
	#define apoll_it_events(it) (it->filter)
	#define apoll_it_event_poll(it) ((it)->filter == EVFILT_READ && (it)->flags == 0)
	#define apoll_it_event_error(it) ((it)->filter == EVFILT_READ && (it)->flags & (EV_EOF|EV_ERROR))
#else // USE_POLL
	#include "knot/common/fdset.h"

	#define apoll_ctx_t fdset_t
	#define apoll_ctx_init(ctx, size) fdset_init(ctx, size)
	#define apoll_ctx_add(ctx, fd, ev, usr_ctx) fdset_add(ctx, fd, ev, usr_ctx)
	#define apoll_ctx_remove(ctx, idx) fdset_remove(set, idx)
	#define apoll_ctx_set_watchdog(ctx, idx, timeout) fdset_set_watchdog(ctx, idx, timeout)
	#define apoll_ctx_wait(ctx, events, offset, len, timeout) poll(events = &((ctx)->pfd[offset]), len, timeout * 1000)
	#define apoll_ctx_sweep(ctx, cb, data) fdset_sweep(ctx, cb, data)
	#define apoll_ctx_close(ctx)
	#define apoll_ctx_clear(ctx) fdset_clear(ctx)
	#define apoll_events_init(name, size) struct pollfd *name = NULL
	#define apoll_get_fd_from_idx(ctx, idx) (ctx)->pfd[idx].fd
	#define apoll_foreach(ctx, events, events_len, it) size_t _nevent = (size_t) events_len; \
		for(struct pollfd *it = events; _nevent > 0 && it < &((ctx)->pfd[(ctx)->n]); it = &((ctx)->pfd[i]))
	#define apoll_foreach_done() --_nevent
	#define apoll_it_idx(ctx, it) (it - (ctx)->pfd)
	#define apoll_it_events(it) it->revents
	#define apoll_it_event_poll(it) ((it)->revents & (POLLIN))
	#define apoll_it_event_error(it) ((it)->revents & (POLLERR|POLLHUP|POLLNVAL))
#endif