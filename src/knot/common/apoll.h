#pragma once

enum apoll_sweep_state {
    APOLL_CTX_KEEP,
    APOLL_CTX_SWEEP
};

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
    #define apoll_ctx_wait(ctx, offset, len, timeout) aio_ctx_wait((ctx), events, offset, len, timeout)
    #define apoll_ctx_sweep(ctx, cb, data) aio_ctx_sweep(ctx, cb, data);
    #define apoll_ctx_clear(ctx) aio_ctx_clear(ctx)
    #define apoll_get_fd_from_idx(ctx, idx) (ctx)->ev[i].aio_fildes
    #define apoll_foreach(ctx) for (struct io_event *it = events; nfds > 0; ++it)
    #define apoll_it_idx(it) ((struct iocb *)it->obj - set->ev)
    #define apoll_it_events(it) ((struct iocb *)it->obj)->aio_buf
#elif USE_KQUEUES

#else // USE_POLL
    #include "knot/common/fdset.h"
    #define apoll_ctx_t fdset_t
    #define apoll_ctx_init(ctx, size) fdset_init(ctx, size)
    #define apoll_ctx_add(ctx, fd, ev, usr_ctx) fdset_add(ctx, fd, ev, usr_ctx)
    #define apoll_ctx_remove(ctx, idx) fdset_remove(set, idx)
    #define apoll_ctx_set_watchdog(ctx, idx, timeout) fdset_set_watchdog(ctx, idx, timeout)
    #define apoll_ctx_wait(ctx, offset, len, timeout) poll(&((ctx)->pfd[offset]), len, timeout * 1000)
    #define apoll_ctx_sweep(ctx, cb, data) fdset_sweep(ctx, cb, data);
    #define apoll_ctx_clear(ctx) fdset_clear(ctx)
    #define apoll_get_fd_from_idx(ctx, idx) (ctx)->pfd[idx].fd
    #define apoll_foreach(ctx) for(struct pollfd *it = &((ctx)->pfd[i]); nfds > 0 && i < (ctx)->n; it = &((ctx)->pfd[i]))
    #define apoll_it_idx(it) i
    #define apoll_it_events(it) it->revents
#endif