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

static void
print_response(getdns_dict * response)
{
	char *dict_str = getdns_pretty_print_dict(response);
	if (dict_str) {
		fprintf(stdout, "The packet %s\n", dict_str);
		free(dict_str);
	}
}

int
main()
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

	getdns_dict *response = NULL;
	getdns_return_t ret =
	    getdns_address_sync(this_context, "www.google.com", NULL, &response);

	if (ret != GETDNS_RETURN_GOOD || response == NULL) {
		fprintf(stderr, "Address sync returned error.\n");
		exit(EXIT_FAILURE);
	}
	print_response(response);
	getdns_dict_destroy(response);

	ret =
	    getdns_service_sync(this_context, "www.google.com", NULL, &response);
	if (ret != GETDNS_RETURN_GOOD || response == NULL) {
		fprintf(stderr, "Service sync returned error.\n");
		exit(EXIT_FAILURE);
	}
	print_response(response);
	getdns_dict_destroy(response);

	/* Clean up */
	getdns_context_destroy(this_context);
	/* Assuming we get here, leave gracefully */
	exit(EXIT_SUCCESS);
}				/* main */

/* example-simple-answers.c */
