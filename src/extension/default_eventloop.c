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

#ifndef USE_WINSOCK
#include <poll.h>
#endif
#include <sys/resource.h>
#include "extension/default_eventloop.h"
#include "debug.h"
#include "types-internal.h"

_getdns_eventloop_info *find_event(_getdns_eventloop_info** events, int id)
{
	_getdns_eventloop_info* ev;

	HASH_FIND_INT(*events, &id, ev);

	return ev;
}

void add_event(_getdns_eventloop_info** events, int id, _getdns_eventloop_info* ev)
{
	HASH_ADD_INT(*events, id, ev);
}

void delete_event(_getdns_eventloop_info** events, _getdns_eventloop_info* ev)
{
	HASH_DEL(*events, ev);
}

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
		_getdns_eventloop_info* fd_event = find_event(&default_loop->fd_events, fd);
#if defined(SCHED_DEBUG) && SCHED_DEBUG
		if (fd_event) {
			if (fd_event->event == event) {
				DEBUG_SCHED("WARNING: Event %p not cleared "
				            "before being rescheduled!\n"
				           , fd_event->event);
			} else {
				DEBUG_SCHED("ERROR: A different event is "
				            "already present at fd slot: %p!\n"
				           , fd_event->event);
			}
		}
#endif
		/* cleanup the old event if it exists */
		if (fd_event) {
			delete_event(&default_loop->fd_events, fd_event);
			free(fd_event);
		}
		fd_event = calloc(1, sizeof(_getdns_eventloop_info));
		fd_event->id = fd;
		fd_event->event = event;
		fd_event->timeout_time = get_now_plus(timeout);
		add_event(&default_loop->fd_events, fd, fd_event);
		event->ev = (void *) (intptr_t) fd + 1;

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
		_getdns_eventloop_info* timeout_event = NULL;
		if ((timeout_event = find_event(&default_loop->timeout_events, i)) == NULL) {
			timeout_event = calloc(1, sizeof(_getdns_eventloop_info));
			timeout_event->id = i;
			timeout_event->event = event;
			timeout_event->timeout_time = get_now_plus(timeout);
			add_event(&default_loop->timeout_events, i, timeout_event);
			event->ev = (void *) (intptr_t) i + 1;

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
		_getdns_eventloop_info* timeout_event = find_event(&default_loop->timeout_events, i);
#if defined(SCHED_DEBUG) && SCHED_DEBUG
		if (timeout_event && timeout_event->event != event)
			DEBUG_SCHED( "ERROR: Different/wrong event present at "
			             "timeout slot: %p!\n"
				     , timeout_event);
#endif
		if (timeout_event) {
			delete_event(&default_loop->timeout_events, timeout_event);
			free(timeout_event);
		}
	} else {
		_getdns_eventloop_info* fd_event = find_event(&default_loop->fd_events, i);
#if defined(SCHED_DEBUG) && SCHED_DEBUG
		if (fd_event && fd_event->event != event)
			DEBUG_SCHED( "ERROR: Different/wrong event present at "
			             "fd slot: %p!\n"
			           , fd_event);
#endif
		if (fd_event) {
			delete_event(&default_loop->fd_events, fd_event);
			free(fd_event);
		}
	}
	event->ev = NULL;
	return GETDNS_RETURN_GOOD;
}

static void
default_eventloop_cleanup(getdns_eventloop *loop)
{
	_getdns_default_eventloop *default_loop  = (_getdns_default_eventloop *)loop;
	HASH_CLEAR(hh, default_loop->fd_events);
	HASH_CLEAR(hh, default_loop->timeout_events);
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
	_getdns_eventloop_info *s, *tmp;
	uint64_t now, timeout = TIMEOUT_FOREVER;
	size_t   i=0;
	int poll_timeout = 0;
	struct pollfd* pfds = NULL;
	int num_pfds = 0;

	if (!loop)
		return;
	
	now = get_now_plus(0);

	HASH_ITER(hh, default_loop->timeout_events, s, tmp) {
		if (now > s->timeout_time)
			default_timeout_cb(-1, s->event);
		else if (s->timeout_time < timeout)
			timeout = s->timeout_time;
	}
	// first we count the number of fds that will be active
	HASH_ITER(hh, default_loop->fd_events, s, tmp) {
		if (s->event->read_cb ||
		    s->event->write_cb)
			num_pfds++;
		if (s->timeout_time < timeout)
			timeout = s->timeout_time;
	}

	if ((timeout == (uint64_t)-1) && (num_pfds == 0))
		return;

	pfds = calloc(num_pfds, sizeof(struct pollfd));
	i = 0;
	HASH_ITER(hh, default_loop->fd_events, s, tmp) {
		if (s->event->read_cb) {
			pfds[i].fd = s->id;
			pfds[i].events |= POLLIN;
		}	
		if (s->event->write_cb) {
			pfds[i].fd = s->id;
			pfds[i].events |= POLLOUT;
		}
		i++;
	}

	if (! blocking || now > timeout) {
		poll_timeout = 0;
	} else {
		poll_timeout = (timeout - now) * 1000; /* turn seconds into millseconds */
	}
#ifdef USE_WINSOCK
	if (WSAPoll(pfds, num_pfds, poll_timeout) < 0) {
#else	
	if (poll(pfds, num_pfds, poll_timeout) < 0) {
#endif
		perror("poll() failed");
		exit(EXIT_FAILURE);
	}
	now = get_now_plus(0);
	for (i = 0; i < num_pfds; i++) {
		int fd = pfds[i].fd;
		_getdns_eventloop_info* fd_event = find_event(&default_loop->fd_events, fd);
		if (fd_event &&
		    fd_event->event &&
		    fd_event->event->read_cb &&
		    (pfds[i].revents & POLLIN))
			default_read_cb(fd, fd_event->event);

		if (fd_event &&
		    fd_event->event &&
		    fd_event->event->write_cb &&
		    (pfds[i].revents & POLLOUT))
			default_write_cb(fd, fd_event->event);
	}
	if (pfds)
		free(pfds);
	HASH_ITER(hh, default_loop->fd_events, s, tmp) {
		if (s->event &&
		    s->event->timeout_cb &&
		    now > s->timeout_time)
			default_timeout_cb(s->id, s->event);
	}
	HASH_ITER(hh, default_loop->timeout_events, s, tmp) {
		if (s->event &&
		    s->event->timeout_cb &&
		    now > s->timeout_time)
			default_timeout_cb(s->id, s->event);
	}
}

static void
default_eventloop_run(getdns_eventloop *loop)
{
	_getdns_default_eventloop *default_loop  = (_getdns_default_eventloop *)loop;

	if (!loop)
		return;

	/* keep going until all the events are cleared */
	while (default_loop->fd_events && default_loop->timeout_events) {
		default_eventloop_run_once(loop, 1);
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
		loop->max_timeouts = loop->max_fds; /* this is somewhat arbitrary */
	} else {
		DEBUG_SCHED("ERROR: could not obtain RLIMIT_NOFILE from getrlimit()\n");
		loop->max_fds = 0;
		loop->max_timeouts = loop->max_fds;
	}
}
