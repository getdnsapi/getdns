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

#include "config.h"
#ifndef USE_WINSOCK
#include "util/mini_event.h"
#else
#include "util/winsock_event.h"
#endif
#include "types-internal.h"

typedef struct _getdns_mini_event {
	getdns_eventloop           loop;
	time_t                     time_secs;
	struct timeval             time_tv;
	struct _getdns_event_base *base;
	size_t                     n_events;
	struct mem_funcs           mf;
} _getdns_mini_event;

getdns_return_t
_getdns_mini_event_init(getdns_context *context, _getdns_mini_event *mini_event);

getdns_return_t
_getdns_mini_event_create(getdns_context *ctxt, _getdns_mini_event **mini_event);

void
_getdns_mini_event_destroy(_getdns_mini_event *mini_event);

#endif /* _GETDNS_LIBMINI_EVENT_H_ */
