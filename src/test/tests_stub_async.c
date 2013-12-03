/**
 * \file
 * unit tests for getdns_dict helper routines, these should be used to
 * perform regression tests, output must be unchanged from canonical output
 * stored with the sources
 */
/* The MIT License (MIT)
 * Copyright (c) 2013 Verisign, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "testmessages.h"
#include <getdns/getdns.h>
#include <event2/event.h>

/* Set up the callback function, which will also do the processing of the results */
void
this_callbackfn(struct getdns_context_t *this_context,
    uint16_t this_callback_type,
    struct getdns_dict *this_response,
    void *this_userarg, getdns_transaction_t this_transaction_id)
{
	if (this_callback_type == GETDNS_CALLBACK_COMPLETE) {	/* This is a callback with data */
		char *res = getdns_pretty_print_dict(this_response);
		fprintf(stdout, "%s", res);
		getdns_dict_destroy(this_response);
		free(res);

	} else if (this_callback_type == GETDNS_CALLBACK_CANCEL)
		fprintf(stderr,
		    "The callback with ID %llu was cancelled. Exiting.",
		    (unsigned long long)this_transaction_id);
	else
		fprintf(stderr,
		    "The callback got a callback_type of %d. Exiting.",
		    this_callback_type);
}

int
main(int argc, char** argv)
{
	/* Create the DNS context for this call */
	struct getdns_context_t *this_context = NULL;
	getdns_return_t context_create_return =
	    getdns_context_create(&this_context, true);
	if (context_create_return != GETDNS_RETURN_GOOD) {
		fprintf(stderr, "Trying to create the context failed: %d",
		    context_create_return);
		return (GETDNS_RETURN_GENERIC_ERROR);
	}
	getdns_context_set_resolution_type(this_context, GETDNS_CONTEXT_STUB);

	getdns_context_set_timeout(this_context, 5000);
	/* Create an event base and put it in the context using the unknown function name */
	struct event_base *this_event_base;
	this_event_base = event_base_new();
	if (this_event_base == NULL) {
		fprintf(stderr, "Trying to create the event base failed.");
		return (GETDNS_RETURN_GENERIC_ERROR);
	}
	(void) getdns_extension_set_libevent_base(this_context,
	    this_event_base);
	/* Set up the getdns call */
	const char *this_name = argc > 1 ? argv[1] : "www.google.com";
	char *this_userarg = "somestring";	// Could add things here to help identify this call
	getdns_transaction_t this_transaction_id = 0;

	/* Make the call */
	getdns_return_t dns_request_return =
	    getdns_address(this_context, this_name,
	    NULL, this_userarg, &this_transaction_id, this_callbackfn);
	if (dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME) {
		fprintf(stderr, "A bad domain name was used: %s. Exiting.",
		    this_name);
		return (GETDNS_RETURN_GENERIC_ERROR);
	}
//    dns_request_return = getdns_service(this_context, this_name, NULL, this_userarg, &this_transaction_id,
//                                        this_callbackfn);
//    if (dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME)
//      {
//              fprintf(stderr, "A bad domain name was used: %s. Exiting.", this_name);
//              return(GETDNS_RETURN_GENERIC_ERROR);
//      }
	else {
		/* Call the event loop */
		event_base_dispatch(this_event_base);
		// TODO: check the return value above
	}
	/* Clean up */
	getdns_context_destroy(this_context);
	/* Assuming we get here, leave gracefully */
	exit(EXIT_SUCCESS);
}				/* main */

/* example-simple-answers.c */
