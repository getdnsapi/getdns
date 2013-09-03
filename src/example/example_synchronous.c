/* example-synchronous.c
 *
 * Originally taken from the getdns API description pseudo implementation.
 *
 * The MIT License (MIT)
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
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getdns/getdns.h>

int
main()
{
	getdns_return_t         context_create_return;
	struct getdns_list      *just_the_addresses_ptr;
	size_t                  *num_addresses_ptr = NULL;
	size_t                  rec_count;
    struct getdns_dict      *this_address;
    struct getdns_bindata   *this_address_data;
    struct getdns_context_t *this_context      = NULL;
	uint32_t                *this_error        = NULL;
	struct getdns_dict      *this_extensions   = NULL;
	const char              *this_name         = "www.example.com";
	uint8_t                 this_request_type  = GETDNS_RRTYPE_A;
	struct getdns_dict      *this_response     = NULL;
	uint32_t                this_response_length;
	getdns_return_t         this_ret;

	/* Create the DNS context for this call */
	context_create_return = getdns_context_create(&this_context, true);
	if (context_create_return != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "Trying to create the context failed: %d", context_create_return);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}

	/* Set up the getdns_sync_request call */
	/* Get the A and AAAA records */
	this_extensions = getdns_dict_create();
	this_ret = getdns_dict_set_int(this_extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE);
	if (this_ret != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "Trying to set an extension do both IPv4 and IPv6 failed: %d", this_ret);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}

	/* Make the call */
	getdns_return_t dns_request_return = getdns_general_sync(this_context, this_name, this_request_type,
		this_extensions, &this_response_length, &this_response);
	if (dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME)
	{
		fprintf(stderr, "A bad domain name was used: %s. Exiting.", this_name);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}
	else
	{
		/* Be sure the search returned something */
		this_ret = getdns_dict_get_int(this_response, "status", this_error);  // Ignore any error
		if (this_error && (*this_error != GETDNS_RESPSTATUS_GOOD))  // If the search didn't return "good"
		{
			fprintf(stderr, "The search had no results, and a return value of %d. Exiting.", *this_error);
			return(GETDNS_RETURN_GENERIC_ERROR);
		}
		this_ret = getdns_dict_get_list(this_response, "just_address_answers", &just_the_addresses_ptr);  // Ignore any error
		this_ret = getdns_list_get_length(just_the_addresses_ptr, num_addresses_ptr);  // Ignore any error
		/* Go through each record */
        if (num_addresses_ptr)  {
            for (rec_count = 0; rec_count <= *num_addresses_ptr; ++rec_count )
            {
                this_ret = getdns_list_get_dict(just_the_addresses_ptr, rec_count, &this_address);  // Ignore any error
                /* Just print the address */
                this_ret = getdns_dict_get_bindata(this_address, "address_data", &this_address_data); // Ignore any error
                printf("The address is %s", getdns_display_ip_address(this_address_data));
            }
        }
	}

	/* Clean up */
	getdns_context_destroy(this_context);
	getdns_free_sync_request_memory(this_response); 

	exit(EXIT_SUCCESS);
} /* main */

/* example-synchronous.c */
