/*
 * delaydns.c - A DNS proxy that adds delay to replies
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


static int n_requests = 0;

typedef struct transaction_t {
	getdns_transaction_t    request_id;
	getdns_dict            *request;

	getdns_context         *context;
	getdns_eventloop       *loop;
	getdns_eventloop_event  ev;
} transaction_t;


void delay_cb(void *userarg)
{
	transaction_t *trans = userarg;

	trans->loop->vmt->clear(trans->loop, &trans->ev);
	(void) getdns_reply(trans->context, trans->request, trans->request_id);
	getdns_dict_destroy(trans->request);
	free(trans);
	n_requests -= 1;
}

void handler(getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *request, void *userarg, getdns_transaction_t request_id)
{
	transaction_t  *trans = NULL;
	getdns_bindata *qname;
	char           nreq_str[255];
	getdns_bindata nreq_bd = { 0, (void *)nreq_str };

	(void) userarg; (void)callback_type;
	nreq_bd.size = snprintf(nreq_str, sizeof(nreq_str), "n_requests: %d", ++n_requests);

	if (getdns_dict_get_bindata(request, "/question/qname", &qname) ||
	    getdns_dict_set_bindata(request, "/answer/0/name", qname) ||
	    getdns_dict_set_int(request, "/answer/0/type", GETDNS_RRTYPE_TXT) ||
	    getdns_dict_set_bindata(request, "/answer/0/rdata/txt_strings/-", &nreq_bd))
		fprintf(stderr, "Request init error\n");

	else if (qname->size >= 6 && qname->data[0] == 4 &&
	    qname->data[1] == 'q' && qname->data[2] == 'u' &&
	    qname->data[3] == 'i' && qname->data[4] == 't') {

		(void) getdns_reply(context, request, request_id);
		(void) getdns_context_set_listen_addresses(context, NULL, NULL, NULL);
		getdns_dict_destroy(request);
		return;

	} else if (!(trans = malloc(sizeof(transaction_t))))
		perror("memerror");
	else {
		(void) memset(trans, 0, sizeof(transaction_t));
		trans->request_id = request_id;
		trans->request = request;
		trans->context = context;
		trans->ev.userarg = trans;
		trans->ev.timeout_cb = delay_cb;

		if (getdns_context_get_eventloop(context, &trans->loop)
		||  trans->loop->vmt->schedule(trans->loop, -1, 300, &trans->ev))
			fprintf(stderr, "Could not schedule delay\n");
		else	return;
	}
	getdns_dict_destroy(trans->request);
	if (trans) free(trans);
	exit(EXIT_FAILURE);
}

int main()
{
	getdns_context   *context   = NULL;
	getdns_list      *listeners = NULL;
	getdns_dict      *address   = NULL;
	uint32_t          port      = 18000;
	getdns_return_t   r;

	if ((r = getdns_str2list("[ 127.0.0.1:18000 ]", &listeners)) ||
	    (r = getdns_list_get_dict(listeners, 0, &address)) ||
	    (r = getdns_context_create(&context, 0)))
		fprintf(stderr, "Error initializing: ");

	else while (++port < 18200 &&
	    !(r = getdns_dict_set_int(address, "port", port)) &&
	     (r = getdns_context_set_listen_addresses(
			    context, listeners, NULL, handler)))
		; /* pass */

	if (r)	fprintf(stderr, "%s\n", getdns_get_errorstr_by_id(r));
	else {
		fprintf(stdout, "%d\n", (int)port);
		fflush(stdout);
		getdns_context_run(context);
	}
	getdns_list_destroy(listeners);
	getdns_context_destroy(context);
	return r;
}
