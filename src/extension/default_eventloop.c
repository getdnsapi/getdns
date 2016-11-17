/*
 * Copyright (c) 2013, NLNet Labs, Verisign, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the names of the copyright holders nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Verisign, Inc. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <poll.h>
#include <sys/resource.h>
#include "extension/default_eventloop.h"
#include "debug.h"
#include "types-internal.h"

static uint64_t get_now_plus(uint64_t amount)
{
	struct timeval tv;
	uint64_t       now;

	if (gettimeofday(&tv, NULL)) {
		perror("gettimeofday() failed");
		exit(EXIT_FAILURE);
	}
	now = tv.tv_sec * 1000000 + tv.tv_usec;

	return (now + amount * 1000) >= now
	      ? now + amount * 1000 : TIMEOUT_FOREVER;
}

static getdns_return_t
default_eventloop_schedule(getdns_eventloop *loop,
    int fd, uint64_t timeout, getdns_eventloop_event *event)
{
	_getdns_default_eventloop *default_loop  = (_getdns_default_eventloop *)loop;
	size_t i;

	DEBUG_SCHED( "%s(loop: %p, fd: %d, timeout: %"PRIu64", event: %p, max_fds: %d)\n"
	        , __FUNCTION__, loop, fd, timeout, event, default_loop->max_fds);

	if (!loop || !event)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (fd >= (int)default_loop->max_fds) {
		DEBUG_SCHED( "ERROR: fd %d >= max_fds: %d!\n"
		           , fd, default_loop->max_fds);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	if (fd >= 0 && !(event->read_cb || event->write_cb)) {
		DEBUG_SCHED("WARNING: fd event without "
		            "read or write cb!\n");
		fd = -1;
	}
	if (fd >= 0) {
#if defined(SCHED_DEBUG) && SCHED_DEBUG
		if (default_loop->fd_events[fd]) {
			if (default_loop->fd_events[fd] == event) {
				DEBUG_SCHED("WARNING: Event %p not cleared "
				            "before being rescheduled!\n"
				           , default_loop->fd_events[fd]);
			} else {
				DEBUG_SCHED("ERROR: A different event is "
				            "already present at fd slot: %p!\n"
				           , default_loop->fd_events[fd]);
			}
		}
#endif
		default_loop->fd_events[fd] = event;
		default_loop->fd_timeout_times[fd] = get_now_plus(timeout);
		event->ev = (void *)(intptr_t)(fd + 1);
		DEBUG_SCHED( "scheduled read/write at %d\n", fd);
		return GETDNS_RETURN_GOOD;
	}
	if (!event->timeout_cb) {
		DEBUG_SCHED("ERROR: fd < 0 without timeout_cb!\n");
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	if (event->read_cb) {
		DEBUG_SCHED("ERROR: timeout event with read_cb! Clearing.\n");
		event->read_cb = NULL;
	}
	if (event->write_cb) {
		DEBUG_SCHED("ERROR: timeout event with write_cb! Clearing.\n");
		event->write_cb = NULL;
	}
	for (i = 0; i < default_loop->max_timeouts; i++) {
		if (default_loop->timeout_events[i] == NULL) {
			default_loop->timeout_events[i] = event;
			default_loop->timeout_times[i] = get_now_plus(timeout);		
			event->ev = (void *)(intptr_t)(i + 1);
			DEBUG_SCHED( "scheduled timeout at %d\n", (int)i);
			return GETDNS_RETURN_GOOD;
		}
	}
	DEBUG_SCHED("ERROR: Out of timeout slots!\n");
	return GETDNS_RETURN_GENERIC_ERROR;
}

static getdns_return_t
default_eventloop_clear(getdns_eventloop *loop, getdns_eventloop_event *event)
{
	_getdns_default_eventloop *default_loop  = (_getdns_default_eventloop *)loop;
	ssize_t i;

	if (!loop || !event)
		return GETDNS_RETURN_INVALID_PARAMETER;

	DEBUG_SCHED( "%s(loop: %p, event: %p)\n", __FUNCTION__, loop, event);

	i = (intptr_t)event->ev - 1;
	if (i < 0 || i > default_loop->max_fds) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	if (event->timeout_cb && !event->read_cb && !event->write_cb) {
#if defined(SCHED_DEBUG) && SCHED_DEBUG
		if (default_loop->timeout_events[i] != event)
			DEBUG_SCHED( "ERROR: Different/wrong event present at "
			             "timeout slot: %p!\n"
			           , default_loop->timeout_events[i]);
#endif
		default_loop->timeout_events[i] = NULL;
	} else {
#if defined(SCHED_DEBUG) && SCHED_DEBUG
		if (default_loop->fd_events[i] != event)
			DEBUG_SCHED( "ERROR: Different/wrong event present at "
			             "fd slot: %p!\n"
			           , default_loop->fd_events[i]);
#endif
		default_loop->fd_events[i] = NULL;
	}
	event->ev = NULL;
	return GETDNS_RETURN_GOOD;
}

static void
default_eventloop_cleanup(getdns_eventloop *loop)
{
	_getdns_default_eventloop *default_loop  = (_getdns_default_eventloop *)loop;
	if (default_loop->fd_events)
		free(default_loop->fd_events);
	if (default_loop->fd_timeout_times)
		free(default_loop->fd_timeout_times);
	if (default_loop->timeout_events)
		free(default_loop->timeout_events);
	if (default_loop->timeout_times)
		free(default_loop->timeout_times);
}

static void
default_read_cb(int fd, getdns_eventloop_event *event)
{
#if !defined(SCHED_DEBUG) || !SCHED_DEBUG
	(void)fd;
#endif
	DEBUG_SCHED( "%s(fd: %d, event: %p)\n", __FUNCTION__, fd, event);
	event->read_cb(event->userarg);
}

static void
default_write_cb(int fd, getdns_eventloop_event *event)
{
#if !defined(SCHED_DEBUG) || !SCHED_DEBUG
	(void)fd;
#endif
	DEBUG_SCHED( "%s(fd: %d, event: %p)\n", __FUNCTION__, fd, event);
	event->write_cb(event->userarg);
}

static void
default_timeout_cb(int fd, getdns_eventloop_event *event)
{
#if !defined(SCHED_DEBUG) || !SCHED_DEBUG
	(void)fd;
#endif
	DEBUG_SCHED( "%s(fd: %d, event: %p)\n", __FUNCTION__, fd, event);
	event->timeout_cb(event->userarg);
}

static void
default_eventloop_run_once(getdns_eventloop *loop, int blocking)
{
	_getdns_default_eventloop *default_loop  = (_getdns_default_eventloop *)loop;

	int      fd, max_fd = -1;
	uint64_t now, timeout = TIMEOUT_FOREVER;
	size_t   i;
	int poll_timeout = 0;
	struct pollfd* pfds = NULL;
	int num_pfds = 0;
	
	if (!loop)
		return;
	
	now = get_now_plus(0);

	for (i = 0; i < default_loop->max_timeouts; i++) {
		if (!default_loop->timeout_events[i])
			continue;
		if (now > default_loop->timeout_times[i])
			default_timeout_cb(-1, default_loop->timeout_events[i]);
		else if (default_loop->timeout_times[i] < timeout)
			timeout = default_loop->timeout_times[i];
	}
	// first we count the number of fds that will be active
	for (fd = 0; fd < default_loop->max_fds; fd++) {
		if (!default_loop->fd_events[fd])
			continue;
		if (default_loop->fd_events[fd]->read_cb ||
		    default_loop->fd_events[fd]->write_cb)
			num_pfds++;
		if (fd > max_fd)
			max_fd = fd;
		if (default_loop->fd_timeout_times[fd] < timeout)
			timeout = default_loop->fd_timeout_times[fd];
	}

	if ((max_fd == -1 && timeout == (uint64_t)-1) || (num_pfds == 0))
		return;

	pfds = calloc(num_pfds, sizeof(struct pollfd));
	for (fd = 0, i=0; fd < default_loop->max_fds; fd++) {
		if (!default_loop->fd_events[fd])
			continue;
		if (default_loop->fd_events[fd]->read_cb) {
			pfds[i].fd = fd;
			pfds[i].events |= POLLIN;
		}	
		if (default_loop->fd_events[fd]->write_cb) {
			pfds[i].fd = fd;
			pfds[i].events |= POLLOUT;
		}
	}

	if (! blocking || now > timeout) {
		poll_timeout = 0;
	} else {
		poll_timeout = (timeout - now) * 1000; /* turn seconds in millseconds */
	}
	if (poll(pfds, num_pfds, poll_timeout) < 0) {
		perror("poll() failed");
		exit(EXIT_FAILURE);
	}
	now = get_now_plus(0);
	for (int i = 0; i < num_pfds; i++) {
		int fd = pfds[i].fd;
		if (default_loop->fd_events[fd] &&
		    default_loop->fd_events[fd]->read_cb &&
		    (pfds[i].revents & POLLIN))
			default_read_cb(fd, default_loop->fd_events[fd]);

		if (default_loop->fd_events[fd] &&
		    default_loop->fd_events[fd]->write_cb &&
		    (pfds[i].revents & POLLOUT))
			default_write_cb(fd, default_loop->fd_events[fd]);
	}
	if (pfds)
		free(pfds);
	for (int fd=0; fd < default_loop->max_fds; fd++) {
		if (default_loop->fd_events[fd] &&
		    default_loop->fd_events[fd]->timeout_cb &&
		    now > default_loop->fd_timeout_times[fd])
			default_timeout_cb(fd, default_loop->fd_events[fd]);
		i = fd;
		if (default_loop->timeout_events[i] &&
		    default_loop->timeout_events[i]->timeout_cb &&
		    now > default_loop->timeout_times[i])
			default_timeout_cb(-1, default_loop->timeout_events[i]);
	}
}

static void
default_eventloop_run(getdns_eventloop *loop)
{
	_getdns_default_eventloop *default_loop  = (_getdns_default_eventloop *)loop;
	size_t        i;

	if (!loop)
		return;

	i = 0;
	while (i < default_loop->max_timeouts) {
		if (default_loop->fd_events[i] || default_loop->timeout_events[i]) {
			default_eventloop_run_once(loop, 1);
			i = 0;
		} else {
			i++;
		}
	}
}

void
_getdns_default_eventloop_init(_getdns_default_eventloop *loop)
{
	static getdns_eventloop_vmt default_eventloop_vmt = {
		default_eventloop_cleanup,
		default_eventloop_schedule,
		default_eventloop_clear,
		default_eventloop_run,
		default_eventloop_run_once
	};

	(void) memset(loop, 0, sizeof(_getdns_default_eventloop));
	loop->loop.vmt = &default_eventloop_vmt;

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		loop->max_fds = rl.rlim_cur;
		loop->max_timeouts = loop->max_fds;
	} else {
		DEBUG_SCHED("ERROR: could not obtain RLIMIT_NOFILE from getrlimit()\n");
		loop->max_fds = 0;
		loop->max_timeouts = loop->max_fds;
	}
	if (loop->max_fds) {
		loop->fd_events = calloc(loop->max_fds, sizeof(getdns_eventloop_event *));
		loop->fd_timeout_times = calloc(loop->max_fds, sizeof(uint64_t));
	}
	if (loop->max_timeouts) {
		loop->timeout_events = calloc(loop->max_timeouts, sizeof(getdns_eventloop_event *));
		loop->timeout_times = calloc(loop->max_timeouts, sizeof(uint64_t));
	}
}
