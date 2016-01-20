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

#include "config.h"
#include "getdns/getdns.h"
#include "getdns/getdns_extra.h"


typedef struct getdns_sync_data {
	int                     to_run;
	getdns_callback_type_t  callback_type;
	getdns_dict            *response;
	getdns_transaction_t    transaction_id;
} getdns_sync_data;

static void
getdns_sync_cb(getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *response, void *userarg, getdns_transaction_t transaction_id)
{
	getdns_sync_data *data = (getdns_sync_data *)userarg;

	assert(data);
	assert(data->transaction_id == transaction_id);

	data->callback_type = callback_type;
	data->response = response;
	data->to_run = 0;
}

static getdns_return_t
_getdns_sync_run(
    getdns_context *context, getdns_sync_data *data, getdns_dict **response)
{
	data->to_run = 1;
	data->callback_type = (getdns_callback_type_t)0;
	data->response = NULL;

	while (data->to_run)
		getdns_context_process_async(context);

	return (*response = data->response) ?
	    GETDNS_RETURN_GOOD : GETDNS_RETURN_GENERIC_ERROR;
}

getdns_return_t
getdns_general_sync(getdns_context *context, const char *name,
    uint16_t request_type, getdns_dict *extensions, getdns_dict **response)
{
	getdns_sync_data data;
	getdns_return_t r;

	if (!context || !name || !response)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if ((r = getdns_general(context, name, request_type,
	    extensions, &data, &data.transaction_id, getdns_sync_cb)))
		return r;

	return _getdns_sync_run(context, &data, response);
}

getdns_return_t
getdns_address_sync(getdns_context *context, const char *name,
    getdns_dict *extensions, getdns_dict **response)
{
	getdns_sync_data data;
	getdns_return_t r;

	if (!context || !name || !response)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if ((r = getdns_address(context, name,
	    extensions, &data, &data.transaction_id, getdns_sync_cb)))
		return r;

	return _getdns_sync_run(context, &data, response);
}

getdns_return_t
getdns_hostname_sync(getdns_context *context, getdns_dict *address,
    getdns_dict *extensions, getdns_dict **response)
{
	getdns_sync_data data;
	getdns_return_t r;

	if (!context || !address|| !response)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if ((r = getdns_hostname(context, address,
	    extensions, &data, &data.transaction_id, getdns_sync_cb)))
		return r;

	return _getdns_sync_run(context, &data, response);
}

getdns_return_t
getdns_service_sync(getdns_context *context, const char *name,
    getdns_dict *extensions, getdns_dict **response)
{
	getdns_sync_data data;
	getdns_return_t r;

	if (!context || !name || !response)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if ((r = getdns_service(context, name,
	    extensions, &data, &data.transaction_id, getdns_sync_cb)))
		return r;

	return _getdns_sync_run(context, &data, response);
}

/* getdns_core_sync.c */
