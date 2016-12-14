/*
 * \file default_eventloop.h
 * @brief Build in default eventloop extension that uses select.
 *
 */
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
#ifndef DEFAULT_EVENTLOOP_H_
#define DEFAULT_EVENTLOOP_H_
#include "config.h"
#include "getdns/getdns.h"
#include "getdns/getdns_extra.h"
#include "util/uthash.h"

/* Eventloop based on poll */

typedef struct _getdns_eventloop_info {
	int			id;
	getdns_eventloop_event *event;
	uint64_t                timeout_time;
	UT_hash_handle		hh;
} _getdns_eventloop_info;

typedef struct _getdns_default_eventloop {
	getdns_eventloop        loop;
	int			max_fds;
	int			max_timeouts;
	_getdns_eventloop_info  *fd_events;
	_getdns_eventloop_info  *timeout_events;
} _getdns_default_eventloop;

void
_getdns_default_eventloop_init(_getdns_default_eventloop *loop);

#endif

