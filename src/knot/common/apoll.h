#pragma once

#define USE_POLL 1
#define USE_EPOLL 1
#define USE_AIO 1

#include "knot/common/fdset.h"
#ifdef USE_EPOLL
#include "knot/common/epoll_ctx.h"
#endif
#ifdef USE_AIO
#include "knot/common/aio_ctx.h"
#endif
	
enum apoll_sweep_state {
	APOLL_CTX_KEEP,
	APOLL_CTX_SWEEP
};

typedef union apoll_ctx {
	fdset_t poll;
#ifdef USE_EPOLL
	epoll_ctx_t epoll;
#endif
#ifdef USE_AIO
	aio_ctx_t aio;
#endif
} apoll_ctx_t;

typedef union apoll_it {
	fdset_it_t poll;
#ifdef USE_EPOLL
	epoll_it_t epoll;
#endif
#ifdef USE_AIO
	aio_it_t aio;
#endif
} apoll_it_t;

typedef int (*apoll_ctx_sweep_cb_t)(apoll_ctx_t *, int, void *);

typedef struct apoll_api {
	int (*ctx_init)(apoll_ctx_t *, unsigned);
	int (*ctx_add)(apoll_ctx_t *, int, unsigned int, void *);
	int (*ctx_remove)(apoll_ctx_t *, apoll_it_t *);
	int (*ctx_set_watchdog)(apoll_ctx_t *, unsigned, int);
	unsigned (*ctx_get_length)(apoll_ctx_t *);
	int (*ctx_get_fd)(apoll_ctx_t *, unsigned);
	void (*ctx_close)(apoll_ctx_t *);
	void (*ctx_clear)(apoll_ctx_t *);
	int (*ctx_poll)(apoll_ctx_t *, apoll_it_t *, unsigned, unsigned, int);
	int (*ctx_sweep)(apoll_ctx_t *, apoll_ctx_sweep_cb_t, void *);
	void (*it_next)(apoll_it_t *);
	int (*it_done)(apoll_it_t *);
	int (*it_get_fd)(apoll_it_t *);
	unsigned (*it_get_idx)(apoll_it_t *);
	int (*it_ev_is_pollin)(apoll_it_t *);
	int (*it_ev_is_error)(apoll_it_t *);
} apoll_api_t;


#ifdef USE_EPOLL	
	static int _epoll_ctx_init(apoll_ctx_t *ctx, unsigned size)
	{
		assert(ctx);
		return epoll_ctx_init(&ctx->epoll, size);
	}

	static int _epoll_ctx_add(apoll_ctx_t *ctx, int fd, unsigned events, void *usrctx)
	{
		assert(ctx);
		return epoll_ctx_add(&ctx->epoll, fd, events, usrctx);
	}

	static int _epoll_ctx_remove_it(apoll_ctx_t *ctx, apoll_it_t *it)
	{
		assert(ctx && it);
		return epoll_ctx_remove_it(&ctx->epoll, &it->epoll);
	}

	static int _epoll_ctx_set_watchdog(apoll_ctx_t *ctx, unsigned i, int interval)
	{
		assert(ctx);
		return epoll_ctx_set_watchdog(&ctx->epoll, i, interval);
	}

	static int _epoll_ctx_get_fd(apoll_ctx_t *ctx, unsigned i)
	{
		assert(ctx);
		return epoll_ctx_get_fd(&ctx->epoll, i);
	}

	static unsigned _epoll_ctx_get_length(apoll_ctx_t *ctx)
	{
		assert(ctx);
		return epoll_ctx_get_length(&ctx->epoll);
	}

	static void _epoll_ctx_close(apoll_ctx_t *ctx)
	{
		assert(ctx);
		epoll_ctx_close(&ctx->epoll);
	}

	static void _epoll_ctx_clear(apoll_ctx_t *ctx)
	{
		assert(ctx);
		epoll_ctx_clear(&ctx->epoll);
	}

	static int _epoll_ctx_wait(apoll_ctx_t *ctx, apoll_it_t *it, unsigned offset, unsigned ev_size, int timeout)
	{
		assert(ctx);
		return epoll_ctx_wait(&ctx->epoll, &it->epoll, offset, ev_size, timeout);
	}

	static int _epoll_ctx_sweep(apoll_ctx_t* ctx, apoll_ctx_sweep_cb_t cb, void *data)
	{
		assert(ctx);
		return epoll_ctx_sweep(&ctx->epoll, cb, data);
	}

	static void _epoll_it_next(apoll_it_t *it)
	{
		assert(it);
		epoll_it_next(&it->epoll);
	}

	static int _epoll_it_done(apoll_it_t *it)
	{
		assert(it);
		return epoll_it_done(&it->epoll);
	}

	static int _epoll_it_get_fd(apoll_it_t *it)
	{
		assert(it);
		return epoll_it_get_fd(&it->epoll);
	}

	static unsigned _epoll_it_get_idx(apoll_it_t *it)
	{
		assert(it);
		return epoll_it_get_idx(&it->epoll);
	}

	static int _epoll_it_ev_is_poll(apoll_it_t *it)
	{
		assert(it);
		return epoll_it_ev_is_poll(&it->epoll);
	}

	static int _epoll_it_ev_is_err(apoll_it_t *it)
	{
		assert(it);
		return epoll_it_ev_is_err(&it->epoll);
	}

	static const apoll_api_t epoll_api = {
		.ctx_init = _epoll_ctx_init,
		.ctx_add = _epoll_ctx_add,
		.ctx_remove = _epoll_ctx_remove_it,
		.ctx_set_watchdog = _epoll_ctx_set_watchdog,
		.ctx_get_fd = _epoll_ctx_get_fd,
		.ctx_get_length = _epoll_ctx_get_length,
		.ctx_close = _epoll_ctx_close,
		.ctx_clear = _epoll_ctx_clear,
		.ctx_poll = _epoll_ctx_wait,
		.ctx_sweep = _epoll_ctx_sweep,
		.it_next = _epoll_it_next,
		.it_done = _epoll_it_done,
		.it_get_fd = _epoll_it_get_fd,
		.it_get_idx = _epoll_it_get_idx,
		.it_ev_is_pollin = _epoll_it_ev_is_poll,
		.it_ev_is_error = _epoll_it_ev_is_err,
	};
#endif
#ifdef USE_AIO
	static int _aio_ctx_init(apoll_ctx_t *ctx, unsigned size)
	{
		assert(ctx);
		return aio_ctx_init(&ctx->aio, size);
	}

	static int _aio_ctx_add(apoll_ctx_t *ctx, int fd, unsigned events, void *usrctx)
	{
		assert(ctx);
		return aio_ctx_add(&ctx->aio, fd, events, usrctx);
	}

	static int _aio_ctx_remove_it(apoll_ctx_t *ctx, apoll_it_t *it)
	{
		assert(ctx && it);
		return aio_ctx_remove_it(&ctx->aio, &it->aio);
	}

	static int _aio_ctx_set_watchdog(apoll_ctx_t *ctx, unsigned i, int interval)
	{
		assert(ctx);
		return aio_ctx_set_watchdog(&ctx->aio, i, interval);
	}

	static int _aio_ctx_get_fd(apoll_ctx_t *ctx, unsigned i)
	{
		assert(ctx);
		return aio_ctx_get_fd(&ctx->aio, i);
	}

	static unsigned _aio_ctx_get_length(apoll_ctx_t *ctx)
	{
		assert(ctx);
		return aio_ctx_get_length(&ctx->aio);
	}

	static void _aio_ctx_close(apoll_ctx_t *ctx)
	{
		assert(ctx);
		aio_ctx_close(&ctx->aio);
	}

	static void _aio_ctx_clear(apoll_ctx_t *ctx)
	{
		assert(ctx);
		aio_ctx_clear(&ctx->aio);
	}

	static int _aio_ctx_wait(apoll_ctx_t *ctx, apoll_it_t *it, unsigned offset, unsigned ev_size, int timeout)
	{
		assert(ctx);
		return aio_ctx_wait(&ctx->aio, &it->aio, offset, ev_size, timeout);
	}

	static int _aio_ctx_sweep(apoll_ctx_t* ctx, apoll_ctx_sweep_cb_t cb, void *data)
	{
		assert(ctx);
		return aio_ctx_sweep(&ctx->aio, cb, data);
	}

	static void _aio_it_next(apoll_it_t *it)
	{
		assert(it);
		aio_it_next(&it->aio);
	}

	static int _aio_it_done(apoll_it_t *it)
	{
		assert(it);
		return aio_it_done(&it->aio);
	}

	static int _aio_it_get_fd(apoll_it_t *it)
	{
		assert(it);
		return aio_it_get_fd(&it->aio);
	}

	static unsigned _aio_it_get_idx(apoll_it_t *it)
	{
		assert(it);
		return aio_it_get_idx(&it->epoll);
	}

	static int _aio_it_ev_is_poll(apoll_it_t *it)
	{
		assert(it);
		return aio_it_ev_is_poll(&it->aio);
	}

	static int _aio_it_ev_is_err(apoll_it_t *it)
	{
		assert(it);
		return aio_it_ev_is_err(&it->aio);
	}

	#define apoll_it_idx(ctx, it) ((struct iocb *)it.ptr->obj - (ctx)->ev)

	static const apoll_api_t aio_poll_api = {
		.ctx_init = _aio_ctx_init,
		.ctx_add = _aio_ctx_add,
		.ctx_remove = _aio_ctx_remove_it,
		.ctx_set_watchdog = _aio_ctx_set_watchdog,
		.ctx_get_fd = _aio_ctx_get_fd,
		.ctx_get_length = _aio_ctx_get_length,
		.ctx_close = _aio_ctx_close,
		.ctx_clear = _aio_ctx_clear,
		.ctx_poll = _aio_ctx_wait,
		.ctx_sweep = _aio_ctx_sweep,
		.it_next = _aio_it_next,
		.it_done = _aio_it_done,
		.it_get_fd = _aio_it_get_fd,
		.it_get_idx = _aio_it_get_idx,
		.it_ev_is_pollin = _aio_it_ev_is_poll,
		.it_ev_is_error = _aio_it_ev_is_err,
	};
#endif
#ifdef USE_KQUEUE
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
#endif
#ifdef USE_POLL
	static int _poll_ctx_init(apoll_ctx_t *ctx, unsigned size)
	{
		assert(ctx);
		return fdset_init(&ctx->poll, size);
	}

	static int _poll_ctx_add(apoll_ctx_t *ctx, int fd, unsigned events, void *usrctx)
	{
		assert(ctx);
		return fdset_add(&ctx->poll, fd, events, usrctx);
	}

	static int _poll_ctx_remove_it(apoll_ctx_t *ctx, apoll_it_t *it)
	{
		assert(ctx && it);
		return fdset_remove_it(&ctx->poll, &it->poll);
	}

	static int _poll_ctx_set_watchdog(apoll_ctx_t *ctx, unsigned i, int interval)
	{
		assert(ctx);
		return fdset_set_watchdog(&ctx->poll, i, interval);
	}

	static int _poll_ctx_get_fd(apoll_ctx_t *ctx, unsigned i)
	{
		assert(ctx);
		return fdset_get_fd(&ctx->poll, i);
	}

	static unsigned _poll_ctx_get_length(apoll_ctx_t *ctx)
	{
		assert(ctx);
		return fdset_get_length(&ctx->poll);
	}

	static void _poll_ctx_close(apoll_ctx_t *ctx)
	{}

	static void _poll_ctx_clear(apoll_ctx_t *ctx)
	{
		assert(ctx);
		fdset_clear(&ctx->poll);
	}

	static int _poll_ctx_wait(apoll_ctx_t *ctx, apoll_it_t *it, unsigned offset, unsigned ev_size, int timeout)
	{
		assert(ctx);
		return fdset_wait(&ctx->poll, &it->poll, offset, ev_size, timeout);
	}

	static int _poll_ctx_sweep(apoll_ctx_t* ctx, apoll_ctx_sweep_cb_t cb, void *data)
	{
		assert(ctx);
		return fdset_sweep(&ctx->poll, cb, data);
	}

	static void _poll_it_next(apoll_it_t *it)
	{
		assert(it);
		fdset_it_next(&it->poll);
	}

	static int _poll_it_done(apoll_it_t *it)
	{
		assert(it);
		return fdset_it_done(&it->poll);
	}

	static int _poll_it_get_fd(apoll_it_t *it)
	{
		assert(it);
		return fdset_it_get_fd(&it->poll);
	}

	static int _poll_it_get_idx(apoll_it_t *it)
	{
		assert(it);
		return fdset_it_get_idx(&it->poll);
	}

	static int _poll_it_ev_is_poll(apoll_it_t *it)
	{
		assert(it);
		return fdset_it_ev_is_poll(&it->poll);
	}

	static int _poll_it_ev_is_err(apoll_it_t *it)
	{
		assert(it);
		return fdset_it_ev_is_err(&it->poll);
	}

	static const apoll_api_t unix_poll_api = {
		.ctx_init = _poll_ctx_init,
		.ctx_add = _poll_ctx_add,
		.ctx_remove = _poll_ctx_remove_it,
		.ctx_set_watchdog = _poll_ctx_set_watchdog,
		.ctx_get_fd = _poll_ctx_get_fd,
		.ctx_get_length = _poll_ctx_get_length,
		.ctx_close = _poll_ctx_close,
		.ctx_clear = _poll_ctx_clear,
		.ctx_poll = _poll_ctx_wait,
		.ctx_sweep = _poll_ctx_sweep,
		.it_next = _poll_it_next,
		.it_done = _poll_it_done,
		.it_get_fd = _poll_it_get_fd,
		.it_get_idx = _poll_it_get_idx,
		.it_ev_is_pollin = _poll_it_ev_is_poll,
		.it_ev_is_error = _poll_it_ev_is_err,
	};
#endif