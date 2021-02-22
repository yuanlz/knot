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

/*!
 * \brief I/O multiplexing with context and timeouts for each fd.
 */

#pragma once

#ifdef USE_AIO

#include <stddef.h>
#include <signal.h>
#include <sys/time.h>
#include <linux/aio_abi.h>

#define AIO_INIT_SIZE 256 /* Resize step. */

/*! \brief Set of filedescriptors with associated context and timeouts. */
typedef struct aio_ctx {
	aio_context_t ctx;
	unsigned n;               /*!< Active fds. */
	unsigned size;            /*!< Array size (allocated). */
	struct iocb *ev;          /*!< Epoll event storage for each fd */
	void* *usrctx;            /*!< Context for each fd. */
	time_t *timeout;          /*!< Timeout for each fd (seconds precision). */
    unsigned recv_size;
    struct io_event *recv_ev;
} aio_ctx_t;

typedef struct aio_it {
    aio_ctx_t *ctx;
    int left;
    struct io_event *ptr;
} aio_it_t;

/*! \brief Mark-and-sweep state. */
enum aio_ctx_sweep_state {
	AIO_CTX_KEEP,
	AIO_CTX_SWEEP
};

/*! \brief Sweep callback (set, index, data) */
typedef enum aio_ctx_sweep_state (*aio_ctx_sweep_cb_t)(aio_ctx_t*, int, void*);

/*!
 * \brief Initialize fdset to given size.
 */
int aio_ctx_init(aio_ctx_t *set, unsigned size);

/*!
 * \brief Destroy FDSET.
 *
 * \retval 0 if successful.
 * \retval -1 on error.
 */
int aio_ctx_clear(aio_ctx_t* set);

void aio_ctx_close(aio_ctx_t* set);

/*!
 * \brief Add file descriptor to watched set.
 *
 * \param set Target set.
 * \param fd Added file descriptor.
 * \param events Mask of watched events.
 * \param ctx Context (optional).
 *
 * \retval index of the added fd if successful.
 * \retval -1 on errors.
 */
int aio_ctx_add(aio_ctx_t *set, int fd, unsigned events, void *ctx);

/*!
 * \brief Remove file descriptor from watched set.
 *
 * \param set Target set.
 * \param i Index of the removed fd.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int aio_ctx_remove_it(aio_ctx_t *set, aio_it_t *it);

int aio_ctx_wait(aio_ctx_t *ctx, aio_it_t *it, size_t offset, size_t ev_size, int timeout);

/*!
 * \brief Set file descriptor watchdog interval.
 *
 * Set time (interval from now) after which the associated file descriptor
 * should be sweeped (see fdset_sweep). Good example is setting a grace period
 * of N seconds between socket activity. If socket is not active within
 * <now, now + interval>, it is sweeped and potentially closed.
 *
 * \param set Target set.
 * \param i Index for the file descriptor.
 * \param interval Allowed interval without activity (seconds).
 *                 -1 disables watchdog timer
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int aio_ctx_set_watchdog(aio_ctx_t* set, int i, int interval);

int aio_ctx_get_fd(aio_ctx_t *ctx, unsigned i);

unsigned aio_ctx_get_length(aio_ctx_t *ctx);
/*!
 * \brief Sweep file descriptors with exceeding inactivity period.
 *
 * \param set Target set.
 * \param cb Callback for sweeped descriptors.
 * \param data Pointer to extra data.
 *
 * \retval number of sweeped descriptors.
 * \retval -1 on errors.
 */
int aio_ctx_sweep(aio_ctx_t* set, aio_ctx_sweep_cb_t cb, void *data);

void aio_it_next(aio_it_t *it);

int aio_it_done(aio_it_t *it);

void aio_it_commit(aio_it_t *it);

int aio_it_get_fd(aio_it_t *it);

unsigned aio_it_get_idx(aio_it_t *it);

int aio_it_ev_is_poll(aio_it_t *it);

int aio_it_ev_is_err(aio_it_t *it);

#endif