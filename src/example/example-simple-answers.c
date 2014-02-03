/**
 *
 * \file example-simple-answers.c
 * @brief example using getdns to resolve a simple query
 *
 * Originally taken from the getdns API description pseudo implementation.
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getdns_libevent.h>

#define UNUSED_PARAM(x) ((void)(x))

/* Set up the callback function, which will also do the processing of the results */
void this_callbackfn(struct getdns_context *this_context,
                     uint16_t     this_callback_type,
                     struct getdns_dict *this_response, 
                     void *this_userarg,
                     getdns_transaction_t this_transaction_id)
{
	getdns_return_t         this_ret;
	uint32_t this_error;
	size_t   num_addresses;
	struct   getdns_list    *just_the_addresses_ptr;
	struct   getdns_dict    *this_address;
	struct   getdns_bindata *this_address_data;
    size_t   rec_count;
    char     *this_address_str;

	UNUSED_PARAM(this_userarg);
	UNUSED_PARAM(this_context);

	if (this_callback_type == GETDNS_CALLBACK_COMPLETE)  /* This is a callback with data */
	{
		/* Be sure the search returned something */

		this_ret = getdns_dict_get_int(this_response, "status", &this_error);
        if (this_ret != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr, "The dictionary does not contain \"status\" (this shouldn't have happened).  Exiting\n");
			getdns_dict_destroy(this_response);
			return;
        }

		if (this_error != GETDNS_RESPSTATUS_GOOD)
		{
			fprintf(stderr, "The search had no results, and a return value of %d. Exiting.\n", this_error);
			getdns_dict_destroy(this_response);
			return;
		}

		this_ret = getdns_dict_get_list(this_response, "just_address_answers", &just_the_addresses_ptr);
		if (this_ret != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr, "The dict does not contain \"just_address_answers\" (this shouldn't have happened), and returned %d. Exiting.\n", this_ret);
			getdns_dict_destroy(this_response);
			return;
		}

		this_ret = getdns_list_get_length(just_the_addresses_ptr, &num_addresses);
        if (this_ret != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr, "The address list is invalid (this shouldn't have happened).  Exiting\n");
			getdns_dict_destroy(this_response);
			return;
        }

        if (num_addresses == 0)
			fprintf(stderr, "The address list has 0 records. Exiting\n");

		/* Go through each record */
		for (rec_count = 0; rec_count < num_addresses; ++rec_count)
		{
			this_ret = getdns_list_get_dict(just_the_addresses_ptr, rec_count, &this_address);
            if(this_ret != GETDNS_RETURN_GOOD)
            {
			    fprintf(stderr, "Record %d is invalid (this shouldn't have happened).  skipping.\n", (int) rec_count);
			    continue;
            }

			/* Just print the address */
			this_ret = getdns_dict_get_bindata(this_address, "address_data", &this_address_data);
            if(this_ret != GETDNS_RETURN_GOOD)
            {
                fprintf(stderr, "Record %d does not contain \"address_data\" (this shouldn't happen), skipping\n", (int) rec_count);
            }
            else
            {
			    this_address_str = getdns_display_ip_address(this_address_data);
			    printf("The address is %s\n", this_address_str);
			    free(this_address_str);
            }
		}
	}
	else if (this_callback_type == GETDNS_CALLBACK_CANCEL)
		fprintf(stderr, "The callback with ID %"PRIu64" was cancelled. Exiting.\n", this_transaction_id);
	else
		fprintf(stderr, "The callback got a callback_type of %d. Exiting.\n", this_callback_type);

	getdns_dict_destroy(this_response);
} /* this_callbackfn */

/*---------------------------------------- main */
int
main(int argc, char *argv[])
{
    char   *this_name    = "www.example.com";
	char   *this_userarg = "somestring";
    int    dispatch_return;
    int    exitval       = EXIT_SUCCESS;
	struct getdns_context *this_context = NULL;
	struct event_base     *this_event_base;
    getdns_return_t       dns_request_return;
	getdns_transaction_t  this_transaction_id;
    getdns_return_t       context_create_return;

    if(argc > 1)
        this_name = argv[1];

    printf("resolving %s\n", this_name);

	/* Create the DNS context for this call, use OS configs such as resolv.conf */

	context_create_return = getdns_context_create(&this_context, 1);
	if (context_create_return != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "Trying to create the context failed: %d", context_create_return);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}

	/* Create an event base and put it in the context using the unknown function name */

	this_event_base = event_base_new();
	if (this_event_base == NULL)
	{
		fprintf(stderr, "Trying to create the event base failed.\n");
		getdns_context_destroy(this_context);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}
	getdns_extension_set_libevent_base(this_context, this_event_base);

	/* Set up the getdns call */

	this_transaction_id = 0;

	/* Make the call */

	dns_request_return = getdns_address(this_context, this_name,
		NULL, this_userarg, &this_transaction_id, this_callbackfn);
	if (dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME)
	{
		fprintf(stderr, "A bad domain name was used: %s. Exiting.\n", this_name);
        exitval = GETDNS_RETURN_GENERIC_ERROR;
	}
	else
	{
		/* Call the event loop */

		dispatch_return = event_base_dispatch(this_event_base);

        if(dispatch_return < 0)
		    fprintf(stderr, "event_base_dispatch() failed, returned %d\n", dispatch_return);
	}

	/* Clean up */

	event_base_free(this_event_base);
	getdns_context_destroy(this_context);

	return exitval;
} /* main */

/* example-simple-answers.c */
