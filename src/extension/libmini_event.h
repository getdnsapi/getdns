/**
 *
 * \file libmini_event.h
 * @brief Build in default eventloop extension that uses select.
 *
 */
/*
 * Copyright (c) 2013, NLnet Labs, Verisign, Inc.
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

#ifndef _GETDNS_LIBMINI_EVENT_H_
#define _GETDNS_LIBMINI_EVENT_H_

#include "util/mini_event.h"
#include "types-internal.h"

typedef struct getdns_mini_event {
	getdns_eventloop          loop;
	time_t                    time_secs;
	struct timeval            time_tv;
	struct getdns_event_base *base;
	struct mem_funcs          mf;
} getdns_mini_event;

getdns_return_t
getdns_mini_event_init(getdns_context *context, getdns_mini_event *mini_event);

getdns_return_t
getdns_mini_event_create(getdns_context *ctxt, getdns_mini_event **mini_event);

void
getdns_mini_event_destroy(getdns_mini_event *mini_event);

/** Call timeouts handlers, and return how long to wait for next one or -1 */
void
getdns_mini_event_handle_timeouts(getdns_mini_event *ext, struct timeval *wait);

/** Call select and callbacks for that */
getdns_return_t
getdns_mini_event_handle_select(getdns_mini_event *ext, struct timeval* wait);

#endif /* _GETDNS_LIBMINI_EVENT_H_ */
