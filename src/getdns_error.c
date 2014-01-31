/**
 * \file getdns_error.c
 * @brief getdns error code to string function
 *
 */

/*
 * Copyright (c) 2013, Versign, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the name of the <organization> nor the
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

#include <getdns/getdns.h>
#include <getdns/getdns_error.h>

getdns_lookup_table getdns_error_str[] = {
	{GETDNS_RETURN_GOOD, "Good"}
	,
	{GETDNS_RETURN_GENERIC_ERROR, "Generic error"}
	,
	{GETDNS_RETURN_BAD_DOMAIN_NAME, "Badly-formed domain name in first argument"}
	,
	{GETDNS_RETURN_BAD_CONTEXT, "Bad value for a context type"}
	,
	{GETDNS_RETURN_CONTEXT_UPDATE_FAIL, "Did not update the context"}
	,
	{GETDNS_RETURN_UNKNOWN_TRANSACTION,
            "An attempt was made to cancel a callback with a transaction_id that is not recognized"}
	,
	{GETDNS_RETURN_NO_SUCH_LIST_ITEM,
            "A helper function for lists had an index argument that was too high."}
	,
	{GETDNS_RETURN_NO_SUCH_DICT_NAME,
             "A helper function for dicts had a name argument that for a name that is not in the dict."}
	,
	{GETDNS_RETURN_WRONG_TYPE_REQUESTED,
             "A helper function was supposed to return a certain type for an item, but the wrong type was given."}
	,
	{GETDNS_RETURN_NO_SUCH_EXTENSION,
            "A name in the extensions dict is not a valid extension."}
	,
	{GETDNS_RETURN_EXTENSION_MISFORMAT,
            "One or more of the extensions is has a bad format."}
	,
	{GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED,
            "A query was made with a context that is using stub resolution and a DNSSEC extension specified."}
	,
    {GETDNS_RETURN_MEMORY_ERROR,
             "Unable to allocate the memory required."}
    ,
    {GETDNS_RETURN_INVALID_PARAMETER,
             GETDNS_RETURN_INVALID_PARAMETER_TEXT }
    ,
	{0, ""}
};

/*---------------------------------------- getdns_get_errorstr_by_id() */
/**
 * return error string from getdns return
 * heavily modeled on ldns ldns_get_errorstr_by_id
 * @param err getdns_return_t
 * @return string containing error message
 */

const char *
getdns_get_errorstr_by_id(uint16_t err)
{
	getdns_lookup_table *lt;

	lt = getdns_error_str;
	while (lt->name != 0) {
		if (lt->id == err)
			return lt->name;
		lt++;
	}
	return 0;
}

/* getdns_error.c */
