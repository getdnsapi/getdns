/**
 * \file
 * unit tests for getdns_dict helper routines, these should be used to
 * perform regression tests, output must be unchanged from canonical output
 * stored with the sources
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


#include "config.h"
#ifdef HAVE_EVENT2_EVENT_H
#  include <event2/event.h>
#else
#  include <event.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "testmessages.h"
#include <getdns/getdns.h>
#include <getdns/getdns_ext_libevent.h>

getdns_return_t create_root_trustanchor_list(struct getdns_list **tas)
{
	static const struct getdns_bindata root_dname = { 1, (uint8_t *) "" };
	static const int                   root_key_tag = 19036;
	static const int                   root_algorithm = 8;
	static const int                   root_digest_type = 2;
	static const struct getdns_bindata root_digest = { 32, (uint8_t *)
	    "\x49\xaa\xc1\x1d\x7b\x6f\x64\x46\x70\x2e\x54\xa1\x60\x73\x71\x60"
	    "\x7a\x1a\x41\x85\x52\x00\xfd\x2c\xe1\xcd\xde\x32\xf2\x4e\x8f\xb5"
	};

	getdns_return_t r = GETDNS_RETURN_GOOD;
	struct getdns_dict *ta;
	struct getdns_dict *rdata;

	if (! tas)
		return GETDNS_RETURN_INVALID_PARAMETER;

	ta = getdns_dict_create();
	if (! ta)
		return GETDNS_RETURN_MEMORY_ERROR;
	do {
		r = getdns_dict_set_bindata(ta, "name",
		    (struct getdns_bindata *)&root_dname);
		if (r != GETDNS_RETURN_GOOD)
			break;

		r = getdns_dict_set_int(ta, "type", GETDNS_RRTYPE_DS);
		if (r != GETDNS_RETURN_GOOD)
			break;

		rdata = getdns_dict_create();
		if (! rdata) {
			r = GETDNS_RETURN_MEMORY_ERROR;
			break;
		}
		do {
			r = getdns_dict_set_int(rdata,
			    "key_tag", root_key_tag);
			if (r != GETDNS_RETURN_GOOD)
				break;

			r = getdns_dict_set_int(rdata,
			    "algorithm", root_algorithm);
			if (r != GETDNS_RETURN_GOOD)
				break;

			r = getdns_dict_set_int(rdata,
			    "digest_type", root_digest_type);
			if (r != GETDNS_RETURN_GOOD)
				break;

			r = getdns_dict_set_bindata(rdata,
			    "digest", (struct getdns_bindata *)&root_digest);
			if (r != GETDNS_RETURN_GOOD)
				break;

			r = getdns_dict_set_dict(ta, "rdata", rdata);
		} while(0);

		getdns_dict_destroy(rdata);
		if (r != GETDNS_RETURN_GOOD)
			break;

		*tas = getdns_list_create();
		if (! *tas) {
			r = GETDNS_RETURN_MEMORY_ERROR;
			break;
		}
		r = getdns_list_set_dict(*tas, 0, ta);
		if (r == GETDNS_RETURN_GOOD)
			return r;

		getdns_list_destroy(*tas);
	} while(0);
	getdns_dict_destroy(ta);
	return r;
}

/* Set up the callback function, which will also do the processing of the results */
void
this_callbackfn(struct getdns_context *context,
    getdns_callback_type_t callback_type,
    struct getdns_dict *response, void *userarg,
    getdns_transaction_t transaction_id)
{
	struct getdns_list *validation_chain;
	struct getdns_list *trust_anchors;
	struct getdns_list *replies_tree;
	size_t replies_tree_length, i;
	struct getdns_dict *reply;
	struct getdns_list *answer;
	size_t answer_length;
	getdns_return_t r;

	do {
		if (callback_type == GETDNS_CALLBACK_CANCEL) {
			fprintf(stderr,
			    "The callback with ID %llu was cancelled.\n",
			    (long long unsigned int)transaction_id);
			break;
		} else if (callback_type != GETDNS_CALLBACK_COMPLETE) {
			fprintf(stderr,
			    "The callback got a callback_type of %d.\n",
			    callback_type);
			break;
		}
		r = getdns_dict_get_list(response,
		    "validation_chain", &validation_chain);
		if (r != GETDNS_RETURN_GOOD) {
			fprintf(stderr,
			    "Could not get \"validation_chain\" from response:"
			    " %d\n", r);
			break;
		}
		r = getdns_dict_get_list(response, "replies_tree", &replies_tree);
		if (r != GETDNS_RETURN_GOOD) {
			fprintf(stderr,
			    "Could not get \"replies_tree\" from response:"
			    " %d\n", r);
			break;
		}
		r = getdns_list_get_length(replies_tree, &replies_tree_length);
		if (r != GETDNS_RETURN_GOOD) {
			fprintf(stderr,
			    "Could not get length of the replies_tree:"
			    " %d\n", r);
			break;
		}
		r = create_root_trustanchor_list(&trust_anchors);
		if (r != GETDNS_RETURN_GOOD) {
			fprintf(stderr,
			    "Error in creating trust_anchor:"
			    " %d\n", r);
			break;
		}
		for (i = 0; i < replies_tree_length; i++) {
			r = getdns_list_get_dict(replies_tree, i, &reply);
			if (r != GETDNS_RETURN_GOOD) {
				fprintf(stderr,
				    "Could not get \"reply\" from replies_tree:"
				    " %d\n", r);
				break;
			}
			r = getdns_dict_get_list(reply, "answer", &answer);
			if (r != GETDNS_RETURN_GOOD) {
				fprintf(stderr,
				    "Could not get \"answer\" from reply:"
				    " %d\n", r);
				break;
			}
			r = getdns_list_get_length(answer, &answer_length);
			if (r != GETDNS_RETURN_GOOD) {
				fprintf(stderr,
				    "Could not get length of answer list:"
				    " %d\n", r);
				break;
			}
			if (answer_length == 0)
				continue;

			r = getdns_validate_dnssec(answer,
			    validation_chain, trust_anchors);
			printf("getdns_validate_dnssec returned: %d\n", r);
		}
		getdns_list_destroy(trust_anchors);
	} while (0);
	//printf("%s\n", getdns_pretty_print_dict(response));
	getdns_dict_destroy(response);
	(void) event_base_loopexit((struct event_base *)userarg, NULL);
}

int
main(int argc, char** argv)
{
	/* Create the DNS context for this call */
	struct getdns_context *this_context = NULL;
	getdns_return_t context_create_return =
	    getdns_context_create(&this_context, 1);
	if (context_create_return != GETDNS_RETURN_GOOD) {
		fprintf(stderr, "Trying to create the context failed: %d",
		    context_create_return);
		return (GETDNS_RETURN_GENERIC_ERROR);
	}
	getdns_context_set_timeout(this_context, 5000);
	struct getdns_dict * this_extensions = getdns_dict_create();
	getdns_return_t this_ret = getdns_dict_set_int(this_extensions,
	    "dnssec_return_validation_chain", GETDNS_EXTENSION_TRUE);
	if (this_ret != GETDNS_RETURN_GOOD) {
		fprintf(stderr, "Setting extension "
		    "\"dnssec_return_validation_chain\" failed: %d\n", this_ret);
		getdns_dict_destroy(this_extensions);
		getdns_context_destroy(this_context);
		return (GETDNS_RETURN_GENERIC_ERROR);
        }

	/* Create an event base and put it in the context using the unknown function name */
	struct event_base *this_event_base;
	this_event_base = event_base_new();
	if (this_event_base == NULL) {
		fprintf(stderr, "Trying to create the event base failed.");
		getdns_dict_destroy(this_extensions);
		getdns_context_destroy(this_context);
		return (GETDNS_RETURN_GENERIC_ERROR);
	}
	(void) getdns_extension_set_libevent_base(this_context,
	    this_event_base);
	/* Set up the getdns call */
	const char *this_name = argc > 1 ? argv[1] : "www.example.com";
	getdns_transaction_t this_transaction_id = 0;

	/* Make the call */
	getdns_return_t dns_request_return = getdns_address(
	    this_context, this_name, this_extensions,
	    this_event_base, &this_transaction_id, this_callbackfn);
	if (dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME) {
		fprintf(stderr, "A bad domain name was used: %s. Exiting.",
		    this_name);
		getdns_dict_destroy(this_extensions);
		getdns_context_destroy(this_context);
		event_base_free(this_event_base);
		return (GETDNS_RETURN_GENERIC_ERROR);
	}
	else {
		/* Call the event loop */
		event_base_dispatch(this_event_base);
		// TODO: check the return value above
	}
	/* Clean up */
	getdns_dict_destroy(this_extensions);
	getdns_context_destroy(this_context);
	/* we have to destroy the event base after the context, because
	 * the context has to re-register its sockets from the eventbase,
	 * who has to communicate this to the system event-mechanism. */
	event_base_free(this_event_base);
	/* Assuming we get here, leave gracefully */
	exit(EXIT_SUCCESS);
}				/* main */

/* example-simple-answers.c */
