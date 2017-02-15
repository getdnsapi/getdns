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

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#else
#include <poll.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#include "extension/poll_eventloop.h"
#include "debug.h"

static _getdns_eventloop_info *
find_event(_getdns_eventloop_info** events, int id)
{
	_getdns_eventloop_info* ev;

	HASH_FIND_INT(*events, &id, ev);

	return ev;
}

static void
add_event(struct mem_funcs *mf,
    _getdns_eventloop_info** events, int id, _getdns_eventloop_info* ev)
{
	DEBUG_SCHED("poll_eventloop: add_event with id %d\n", id);
	_getdns_eventloop_info* myevent = GETDNS_MALLOC(*mf, _getdns_eventloop_info);
	/* not necessary -- (void) memset(myevent, 0, sizeof(_getdns_eventloop_info)); */
	myevent->event = ev->event;
	myevent->id = id;
	myevent->timeout_time = ev->timeout_time;
	HASH_ADD_INT(*events, id, myevent);
}

static void
delete_event(struct mem_funcs *mf,
    _getdns_eventloop_info** events, _getdns_eventloop_info* ev)
{
	DEBUG_SCHED("poll_eventloop: delete_event with id %d\n", ev->id);
	HASH_DEL(*events, ev);
	GETDNS_FREE(*mf, ev);
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
poll_eventloop_schedule(getdns_eventloop *loop,
    int fd, uint64_t timeout, getdns_eventloop_event *event)
{
	_getdns_poll_eventloop *poll_loop  = (_getdns_poll_eventloop *)loop;
	struct mem_funcs *mf = &poll_loop->mf;
	size_t i;

	DEBUG_SCHED( "%s(loop: %p, fd: %d, timeout: %"PRIu64", event: %p, max_fds: %d)\n"
	        , __FUNC__, (void *)loop, fd, timeout, (void *)event, poll_loop->max_fds);

	if (!loop || !event)
		return GETDNS_RETURN_INVALID_PARAMETER;


#ifdef HAVE_GETRLIMIT
	if (fd >= (int)poll_loop->max_fds) {
		DEBUG_SCHED( "ERROR: fd %d >= max_fds: %d!\n"
		           , fd, poll_loop->max_fds);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
#endif
	if (fd >= 0 && !(event->read_cb || event->write_cb)) {
		DEBUG_SCHED("WARNING: fd event without "
		            "read or write cb!\n");
		fd = -1;
	}
	if (fd >= 0) {
		_getdns_eventloop_info* fd_event = find_event(&poll_loop->fd_events, fd);
#if defined(SCHED_DEBUG) && SCHED_DEBUG
		if (fd_event) {
			if (fd_event->event == event) {
				DEBUG_SCHED("WARNING: Event %p not cleared "
				            "before being rescheduled!\n"
				           , (void *)fd_event->event);
			} else {
				DEBUG_SCHED("ERROR: A different event is "
				            "already present at fd slot: %p!\n"
				           , (void *)fd_event->event);
			}
		}
#endif
		/* cleanup the old event if it exists */
		if (fd_event) {
			delete_event(mf, &poll_loop->fd_events, fd_event);
		}
		_getdns_eventloop_info fd_ev;
		event->ev = (void *) (intptr_t) (fd + 1);
		fd_ev.event = event;
		fd_ev.timeout_time = get_now_plus(timeout);
		add_event(mf, &poll_loop->fd_events, fd, &fd_ev);

		DEBUG_SCHED( "scheduled read/write at fd %d\n", fd);
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
	for (i = poll_loop->timeout_id + 1; i != poll_loop->timeout_id; i++) {
		if (find_event(&poll_loop->timeout_events, i) == NULL) {
			_getdns_eventloop_info timeout_ev;
			timeout_ev.event = event;
			timeout_ev.timeout_time = get_now_plus(timeout);
			add_event(mf, &poll_loop->timeout_events, i, &timeout_ev);
			event->ev = (void *) (intptr_t) (i + 1);

			DEBUG_SCHED( "scheduled timeout at slot %d\n", (int)i);
			return GETDNS_RETURN_GOOD;
		}
	}
	DEBUG_SCHED("ERROR: Out of timeout slots!\n");
	return GETDNS_RETURN_GENERIC_ERROR;
}

static getdns_return_t
poll_eventloop_clear(getdns_eventloop *loop, getdns_eventloop_event *event)
{
	_getdns_poll_eventloop *poll_loop  = (_getdns_poll_eventloop *)loop;
	struct mem_funcs *mf = &poll_loop->mf;
	ssize_t i;

	if (!loop || !event)
		return GETDNS_RETURN_INVALID_PARAMETER;

	DEBUG_SCHED( "%s(loop: %p, event: %p)\n", __FUNC__, (void *)loop, (void *)event);

	i = (intptr_t)event->ev - 1;
	if (i < 0
#ifdef HAVE_GETRLIMIT
			|| i > poll_loop->max_fds
#endif
			) {
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	if (event->timeout_cb && !event->read_cb && !event->write_cb) {
		_getdns_eventloop_info* timeout_event = find_event(&poll_loop->timeout_events, i);
#if defined(SCHED_DEBUG) && SCHED_DEBUG
		if (timeout_event && timeout_event->event != event)
			DEBUG_SCHED( "ERROR: Different/wrong event present at "
			             "timeout slot: %p!\n"
				     , (void *)timeout_event);

#endif
		if (timeout_event) {
			delete_event(mf, &poll_loop->timeout_events, timeout_event);
		}
	} else {
		_getdns_eventloop_info* fd_event = find_event(&poll_loop->fd_events, i);
#if defined(SCHED_DEBUG) && SCHED_DEBUG
		if (fd_event && fd_event->event != event)
			DEBUG_SCHED( "ERROR: Different/wrong event present at "
			             "fd slot: %p!\n"
			           , (void *)fd_event);
#endif
		if (fd_event) {
			delete_event(mf, &poll_loop->fd_events, fd_event);
		}
	}
	event->ev = NULL;
	return GETDNS_RETURN_GOOD;
}

static void
poll_eventloop_cleanup(getdns_eventloop *loop)
{
	_getdns_poll_eventloop *poll_loop  = (_getdns_poll_eventloop *)loop;
	struct mem_funcs *mf = &poll_loop->mf;

	if (poll_loop->pfds) {
		GETDNS_FREE(*mf, poll_loop->pfds);
		poll_loop->pfds = NULL;
		poll_loop->pfds_capacity = 0;
	}
	HASH_CLEAR(hh, poll_loop->fd_events);
	HASH_CLEAR(hh, poll_loop->timeout_events);
}

static void
poll_read_cb(int fd, getdns_eventloop_event *event)
{
#if !defined(SCHED_DEBUG) || !SCHED_DEBUG
	(void)fd;
#endif
	DEBUG_SCHED( "%s(fd: %d, event: %p)\n", __FUNC__, fd, (void *)event);
	event->read_cb(event->userarg);
}

static void
poll_write_cb(int fd, getdns_eventloop_event *event)
{
#if !defined(SCHED_DEBUG) || !SCHED_DEBUG
	(void)fd;
#endif
	DEBUG_SCHED( "%s(fd: %d, event: %p)\n", __FUNC__, fd, (void *)event);
	event->write_cb(event->userarg);
}

static void
poll_timeout_cb(int fd, getdns_eventloop_event *event)
{
#if !defined(SCHED_DEBUG) || !SCHED_DEBUG
	(void)fd;
#endif
	DEBUG_SCHED( "%s(fd: %d, event: %p)\n", __FUNC__, fd, (void *)event);
	event->timeout_cb(event->userarg);
}

static unsigned long up_pow2(unsigned long v)
{
	v--;
	v |= v >>  1;
	v |= v >>  2;
	v |= v >>  4;
	v |= v >>  8;
	v |= v >> 16;
	return v + 1;
}

static void
poll_eventloop_run_once(getdns_eventloop *loop, int blocking)
{
	_getdns_poll_eventloop *poll_loop  = (_getdns_poll_eventloop *)loop;
	struct mem_funcs *mf = &poll_loop->mf;
	_getdns_eventloop_info *s, *tmp;
	uint64_t now, timeout = TIMEOUT_FOREVER;
	size_t   i=0;
	int poll_timeout = 0;
	unsigned int num_pfds = 0;
	_getdns_eventloop_info* timeout_timeout_cbs = NULL;
	_getdns_eventloop_info* fd_timeout_cbs = NULL;

	if (!loop)
		return;

	now = get_now_plus(0);

	HASH_ITER(hh, poll_loop->timeout_events, s, tmp) {
		if (now > s->timeout_time)
			add_event(mf, &timeout_timeout_cbs, s->id, s);
		else if (s->timeout_time < timeout)
			timeout = s->timeout_time;
	}
	/* this is in case the timeout callback deletes the event
	   and thus messes with the iteration */
	HASH_ITER(hh, timeout_timeout_cbs, s, tmp) {
		getdns_eventloop_event* event = s->event;
		delete_event(mf, &timeout_timeout_cbs, s);
		poll_timeout_cb(-1, event);
	}
	/* first we count the number of fds that will be active */
	HASH_ITER(hh, poll_loop->fd_events, s, tmp) {
		if (s->event->read_cb ||
		    s->event->write_cb)
			num_pfds++;
		if (s->timeout_time < timeout)
			timeout = s->timeout_time;
	}

	if ((timeout == TIMEOUT_FOREVER) && (num_pfds == 0))
		return;

	if (num_pfds >= poll_loop->pfds_capacity) {
		poll_loop->pfds_capacity = up_pow2(num_pfds + 1);
		if (poll_loop->pfds) {
			poll_loop->pfds = GETDNS_XMALLOC(poll_loop->mf, struct pollfd, poll_loop->pfds_capacity);
		} else
			poll_loop->pfds = GETDNS_XREALLOC(poll_loop->mf, poll_loop->pfds, struct pollfd, poll_loop->pfds_capacity);
		if (poll_loop->pfds == 0) {
			poll_loop->pfds_capacity = 0;
			return;
		}
	}
	i = 0;
	HASH_ITER(hh, poll_loop->fd_events, s, tmp) {
		if (!s->event->read_cb && !s->event->write_cb)
			continue;
		poll_loop->pfds[i].fd = s->id;
		poll_loop->pfds[i].events = 0;
		poll_loop->pfds[i].revents = 0; /* <-- probably not needed */
		if (s->event->read_cb)
			poll_loop->pfds[i].events |= POLLIN;
		if (s->event->write_cb) 
			poll_loop->pfds[i].events |= POLLOUT;
		i++;
	}
	assert(i == num_pfds);

	if (timeout == TIMEOUT_FOREVER) {
		poll_timeout = -1;
	}
	else if (! blocking || now > timeout) {
		poll_timeout = 0;
	} else {
		poll_timeout = (timeout - now) / 1000; /* turn microseconds into milliseconds */
	}
#ifdef USE_WINSOCK
	if (WSAPoll(poll_loop->pfds, num_pfds, poll_timeout) < 0) {
#else	
	if (poll(poll_loop->pfds, num_pfds, poll_timeout) < 0) {
#endif
		perror("poll() failed");
		exit(EXIT_FAILURE);
	}
	now = get_now_plus(0);
	for (i = 0; i < num_pfds; i++) {
		int fd = poll_loop->pfds[i].fd;
		_getdns_eventloop_info* fd_event = find_event(&poll_loop->fd_events, fd);
		if (fd_event && fd_event->event) { 
			getdns_eventloop_event* event = fd_event->event;
			if (event->read_cb &&
			    (poll_loop->pfds[i].revents & POLLIN))
				poll_read_cb(fd, event);

			if (event->write_cb &&
			    (poll_loop->pfds[i].revents & POLLOUT))
				poll_write_cb(fd, event);
		}
	}
	HASH_ITER(hh, poll_loop->fd_events, s, tmp) {
		if (s->event &&
		    s->event->timeout_cb &&
		    now > s->timeout_time)
			add_event(mf, &fd_timeout_cbs, s->id, s);
	}
	/* this is in case the timeout callback deletes the event
	   and thus messes with the iteration */
	HASH_ITER(hh, fd_timeout_cbs, s, tmp) {
		int fd = s->id;
		getdns_eventloop_event* event = s->event;
		delete_event(mf, &fd_timeout_cbs, s);
		poll_timeout_cb(fd, event);
	}
	HASH_ITER(hh, poll_loop->timeout_events, s, tmp) {
		if (s->event &&
		    s->event->timeout_cb &&
		    now > s->timeout_time)
			add_event(mf, &timeout_timeout_cbs, s->id, s);
	}
	/* this is in case the timeout callback deletes the event
	   and thus messes with the iteration */
	HASH_ITER(hh, timeout_timeout_cbs, s, tmp) {
		getdns_eventloop_event* event = s->event;
		delete_event(mf, &timeout_timeout_cbs, s);
		poll_timeout_cb(-1, event);
	}

}

static void
poll_eventloop_run(getdns_eventloop *loop)
{
	_getdns_poll_eventloop *poll_loop  = (_getdns_poll_eventloop *)loop;

	if (!loop)
		return;

	/* keep going until all the events are cleared */
	while (poll_loop->fd_events || poll_loop->timeout_events) {
		poll_eventloop_run_once(loop, 1);
	}
}

void
_getdns_poll_eventloop_init(struct mem_funcs *mf, _getdns_poll_eventloop *loop)
{
#ifdef HAVE_GETRLIMIT
	struct rlimit rl;
#endif
	static getdns_eventloop_vmt poll_eventloop_vmt = {
		poll_eventloop_cleanup,
		poll_eventloop_schedule,
		poll_eventloop_clear,
		poll_eventloop_run,
		poll_eventloop_run_once
	};

	loop->loop.vmt = &poll_eventloop_vmt;
	loop->mf = *mf;

#ifdef HAVE_GETRLIMIT
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		loop->max_fds = rl.rlim_cur;
	} else {
		DEBUG_SCHED("ERROR: could not obtain RLIMIT_NOFILE from getrlimit()\n");
#endif
		loop->max_fds = 0;
#if HAVE_GETRLIMIT
	}
#endif
	loop->timeout_id = 0;
	loop->pfds = NULL;
	loop->pfds_capacity = 0;
	loop->fd_events = NULL;
	loop->timeout_events = NULL;
}
