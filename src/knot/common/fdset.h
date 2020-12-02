/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stddef.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <signal.h>

#define FDSET_INIT_SIZE 256 /* Resize step. */

/*! \brief Set of filedescriptors with associated context and timeouts. */
typedef struct fdset {
	unsigned n;          /*!< Active fds. */
	unsigned size;       /*!< Array size (allocated). */
	void* *ctx;          /*!< Context for each fd. */
	struct pollfd *pfd;  /*!< poll state for each fd */
	time_t *timeout;     /*!< Timeout for each fd (seconds precision). */
} fdset_t;


typedef enum epoll_user_data_fdtype {
	CLIENT = 0,
	MASTER = 1
} epoll_usr_data_fdtype_t; 

typedef struct epoll_usr_data {
	unsigned fd;
	epoll_usr_data_fdtype_t type;
	time_t timeout;
	void* ctx;
} efdset_data_t;

/*! \brief Set of epoll filedescriptors with associated context and timeouts. */
typedef struct epoll_fdset {
	unsigned n;          /*!< Active fds. */
	unsigned size;       /*!< Array size (allocated). */
	int epollfd;
	efdset_data_t *ev_data;  /*!< epoll state data for each fd */
} efdset_t;

/*! \brief Mark-and-sweep state. */
enum fdset_sweep_state {
	FDSET_KEEP,
	FDSET_SWEEP
};

/*! \brief Sweep callback (set, index, data) */
typedef enum fdset_sweep_state (*fdset_sweep_cb_t)(fdset_t*, int, void*);

/*!
 * \brief Initialize fdset to given size.
 */
int fdset_init(fdset_t *set, unsigned size);

/*!
 * \brief Destroy FDSET.
 *
 * \retval 0 if successful.
 * \retval -1 on error.
 */
int fdset_clear(fdset_t* set);

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
int fdset_add(fdset_t *set, int fd, unsigned events, void *ctx);

/*!
 * \brief Remove file descriptor from watched set.
 *
 * \param set Target set.
 * \param i Index of the removed fd.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_remove(fdset_t *set, unsigned i);

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
int fdset_set_watchdog(fdset_t* set, int i, int interval);

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
int fdset_sweep(fdset_t* set, fdset_sweep_cb_t cb, void *data);

/*!
 * \brief Initialize fdset to given size.
 */
int efdset_init(efdset_t *set, unsigned size);
int efdset_clear(efdset_t* set);
int efdset_add(efdset_t *set, int fd, unsigned events, epoll_usr_data_fdtype_t type, void *ctx);
int efdset_set_watchdog(efdset_t* set, int i, int interval);
int efdset_remove(efdset_t *set, efdset_data_t *i);
int efdset_sweep(efdset_t* set, fdset_sweep_cb_t cb, void *data);