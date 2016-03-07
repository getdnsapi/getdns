/**
 *
 * /brief getdns core functions for synchronous use
 *
 * Originally taken from the getdns API description pseudo implementation.
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

#include <string.h>
#include "getdns/getdns.h"
#include "config.h"
#include "context.h"
#include "general.h"
#include "types-internal.h"
#include "util-internal.h"
#include "dnssec.h"

#include "stub.h"
#include "gldns/wire2str.h"

typedef struct getdns_sync_loop {
	_getdns_default_eventloop loop;
#ifdef HAVE_LIBUNBOUND
	getdns_eventloop_event ub_event;
#endif
	getdns_context        *context;
	int                    to_run;
	getdns_dict           *response;
} getdns_sync_loop;

static getdns_return_t
getdns_sync_loop_init(getdns_context *context, getdns_sync_loop *loop)
{
#ifdef HAVE_LIBUNBOUND
	getdns_eventloop *ext = &loop->loop.loop;
#endif

	loop->response = NULL;
	loop->to_run   = 1;
	loop->context  = context;

	_getdns_default_eventloop_init(&loop->loop);

#ifdef HAVE_LIBUNBOUND
#  ifndef USE_WINSOCK
	loop->ub_event.userarg    = loop->context;
	loop->ub_event.read_cb    = _getdns_context_ub_read_cb;
	loop->ub_event.write_cb   = NULL;
	loop->ub_event.timeout_cb = NULL;
	loop->ub_event.ev         = NULL;
#  endif
#  ifdef HAVE_UNBOUND_EVENT_API
	if (_getdns_ub_loop_enabled(&context->ub_loop)) {
		context->ub_loop.extension = ext;
	} else
#  endif
#  ifndef USE_WINSOCK
		return ext->vmt->schedule(ext, ub_fd(context->unbound_ctx),
		    TIMEOUT_FOREVER, &loop->ub_event);
#  else
		/* No sync full recursion requests on windows without 
		 * UNBOUND_EVENT_API because ub_fd() doesn't work on windows.
		 */
		; /* pass */
#  endif
#endif
	return GETDNS_RETURN_GOOD;
}

static void
getdns_sync_loop_cleanup(getdns_sync_loop *loop)
{
	getdns_eventloop *ext = &loop->loop.loop;

#if defined(HAVE_LIBUNBOUND) && !defined(USE_WINSOCK)
#  ifdef HAVE_UNBOUND_EVENT_API
	if (_getdns_ub_loop_enabled(&loop->context->ub_loop)) {
		loop->context->ub_loop.extension = loop->context->extension;
	} else
#  endif
		ext->vmt->clear(ext, &loop->ub_event);
#endif
	ext->vmt->cleanup(ext);
}

static void
getdns_sync_loop_run(getdns_sync_loop *loop)
{
	getdns_eventloop *ext = &loop->loop.loop;

	while (loop->to_run)
		ext->vmt->run_once(ext, 1);
	
	getdns_sync_loop_cleanup(loop);
}

static void
getdns_sync_cb(getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *response, void *userarg, getdns_transaction_t transaction_id)
{
	getdns_sync_loop *loop = (getdns_sync_loop *)userarg;

	assert(loop);

	loop->response = response;
	loop->to_run = 0;
}

getdns_return_t
getdns_general_sync(getdns_context *context, const char *name,
    uint16_t request_type, getdns_dict *extensions, getdns_dict **response)
{
	getdns_sync_loop loop;
	getdns_return_t r;

	if (!context || !name || !response)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if ((r = getdns_sync_loop_init(context, &loop)))
		return r;

	if ((r = _getdns_general_loop(context, &loop.loop.loop, name,
	    request_type, extensions, &loop, NULL, getdns_sync_cb, NULL))) {

		getdns_sync_loop_cleanup(&loop);
		return r;
	}
	getdns_sync_loop_run(&loop);
	
	return (*response = loop.response) ?
	    GETDNS_RETURN_GOOD : GETDNS_RETURN_GENERIC_ERROR;
}

getdns_return_t
getdns_address_sync(getdns_context *context, const char *name,
    getdns_dict *extensions, getdns_dict **response)
{
	getdns_sync_loop loop;
	getdns_return_t r;

	if (!context || !name || !response)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if ((r = getdns_sync_loop_init(context, &loop)))
		return r;

	if ((r = _getdns_address_loop(context, &loop.loop.loop, name,
	    extensions, &loop, NULL, getdns_sync_cb))) {

		getdns_sync_loop_cleanup(&loop);
		return r;
	}
	getdns_sync_loop_run(&loop);
	
	return (*response = loop.response) ?
	    GETDNS_RETURN_GOOD : GETDNS_RETURN_GENERIC_ERROR;
}

getdns_return_t
getdns_hostname_sync(getdns_context *context, getdns_dict *address,
    getdns_dict *extensions, getdns_dict **response)
{
	getdns_sync_loop loop;
	getdns_return_t r;

	if (!context || !address || !response)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if ((r = getdns_sync_loop_init(context, &loop)))
		return r;

	if ((r = _getdns_hostname_loop(context, &loop.loop.loop, address,
	    extensions, &loop, NULL, getdns_sync_cb))) {

		getdns_sync_loop_cleanup(&loop);
		return r;
	}
	getdns_sync_loop_run(&loop);
	
	return (*response = loop.response) ?
	    GETDNS_RETURN_GOOD : GETDNS_RETURN_GENERIC_ERROR;
}

getdns_return_t
getdns_service_sync(getdns_context *context, const char *name,
    getdns_dict *extensions, getdns_dict **response)
{
	getdns_sync_loop loop;
	getdns_return_t r;

	if (!context || !name || !response)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if ((r = getdns_sync_loop_init(context, &loop)))
		return r;

	if ((r = _getdns_service_loop(context, &loop.loop.loop, name,
	    extensions, &loop, NULL, getdns_sync_cb))) {

		getdns_sync_loop_cleanup(&loop);
		return r;
	}
	getdns_sync_loop_run(&loop);
	
	return (*response = loop.response) ?
	    GETDNS_RETURN_GOOD : GETDNS_RETURN_GENERIC_ERROR;
}

/* getdns_core_sync.c */
