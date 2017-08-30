/*
 * capabilities.c - A DNS server for testing server capabilities
 *
 * Copyright (c) 2016, NLnet Labs. All rights reserved.
 * 
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <getdns/getdns_extra.h>
#include <stdio.h>
#include <string.h>


void handler(getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *request, void *userarg, getdns_transaction_t request_id)
{
	getdns_bindata *qname;
	char            ans_str[] = "Some answer";
	getdns_bindata  ans_bd = { sizeof(ans_str) - 1, (void *)ans_str };

	(void) userarg; (void)callback_type;

	if (getdns_dict_get_bindata(request, "/question/qname", &qname) ||
	    getdns_dict_set_bindata(request, "/answer/0/name", qname) ||
	    getdns_dict_set_int(request, "/answer/0/type", GETDNS_RRTYPE_TXT) ||
	    getdns_dict_set_int(request, "/header/tc", 1) ||
	    getdns_dict_set_bindata(request, "/answer/0/rdata/txt_strings/-", &ans_bd))
		fprintf(stderr, "Request init error\n");

	else if (qname->size >= 8 && qname->data[0] == 6 &&
	    qname->data[1] == 'c' && qname->data[2] == 'a' &&
	    qname->data[3] == 'n' && qname->data[4] == 'c' &&
	    qname->data[5] == 'e' && qname->data[6] == 'l') {

		(void) getdns_reply(context, NULL, request_id);
		getdns_dict_destroy(request);
		return;

	} else if (qname->size >= 6 && qname->data[0] == 4 &&
	    qname->data[1] == 'q' && qname->data[2] == 'u' &&
	    qname->data[3] == 'i' && qname->data[4] == 't') {

		(void) getdns_dict_set_int(request, "/header/tc", 0);
		(void) getdns_reply(context, request, request_id);
		(void) getdns_context_set_listen_addresses(context, NULL, NULL, NULL);
		getdns_dict_destroy(request);
		return;

	} else {
		if (getdns_reply(context, request, request_id))
			getdns_reply(context, NULL, request_id);
		getdns_dict_destroy(request);
		return;
	}
	getdns_dict_destroy(request);
	exit(EXIT_FAILURE);
}

int main()
{
	getdns_context   *context   = NULL;
	getdns_list      *listeners = NULL;
	getdns_dict      *address   = NULL;
	getdns_dict      *address2  = NULL;
	uint32_t          port1     = 18000;
	uint32_t          port2     = 18000;
	getdns_return_t   r;

	if ((r = getdns_str2list("[ 127.0.0.1:18000 ]", &listeners)) ||
	    (r = getdns_str2dict("127.0.0.1:18000", &address2)) ||
	    (r = getdns_list_get_dict(listeners, 0, &address)) ||
	    (r = getdns_context_create(&context, 0)))
		fprintf(stderr, "Error initializing: ");

	else while (++port1 < 18200 &&
	    !(r = getdns_dict_set_int(address, "port", port1)) &&
	     (r = getdns_context_set_listen_addresses(
			    context, listeners, NULL, handler)))
		; /* pass */

	if (!r && 
	   ((r = getdns_list_set_dict(listeners, 1, address2)) ||
	    (r = getdns_list_get_dict(listeners, 1, &address))))
		fprintf(stderr, "Error initializing 2nd address: ");

	if (r)	fprintf(stderr, "%s\n", getdns_get_errorstr_by_id(r));
	else {
		port2 = port1;
		while (++port2 < 18200 &&
		    !(r = getdns_dict_set_int(address, "port", port2)) &&
		     (r = getdns_context_set_listen_addresses(
				    context, listeners, NULL, handler)))
			; /* pass */

		fprintf(stdout, "%d\n", (int)port1);
		fprintf(stdout, "%d\n", (int)port2);
		fflush(stdout);
		getdns_context_run(context);
	}
	getdns_list_destroy(listeners);
	getdns_dict_destroy(address2);
	getdns_context_destroy(context);
	return r;
}
