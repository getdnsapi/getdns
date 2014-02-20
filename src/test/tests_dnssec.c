/**
 * \file
 * unit tests for getdns_dict helper routines, these should be used to
 * perform regression tests, output must be unchanged from canonical output
 * stored with the sources
 */

/*
 * Copyright (c) 2013, NLNet Labs, Versign, Inc.
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

/* Set up the callback function, which will also do the processing of the results */
void
callbackfn(struct getdns_context *context,
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
		trust_anchors = getdns_root_trust_anchor(NULL);
		if (! trust_anchors) {
			fprintf(stderr,
			    "No root trust anchor present:"
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
	getdns_dict_destroy(response);
	(void) event_base_loopexit((struct event_base *)userarg, NULL);
}

int
main(int argc, char** argv)
{
	const char *name = argc > 1 ? argv[1] : "www.example.com";
	struct getdns_context *context;
	struct getdns_dict *extensions;
	struct event_base *event_base = NULL;
	getdns_transaction_t transaction_id = 0;
	getdns_return_t r;
       
	r = getdns_context_create(&context, 1);
	if (r != GETDNS_RETURN_GOOD) {
		fprintf(stderr, "Create context failed: %d", r);
		return r;
	}
	r = getdns_context_set_timeout(context, 5000);
	if (r != GETDNS_RETURN_GOOD) {
		fprintf(stderr, "Set timeout failed: %d", r);
		goto done_destroy_context;
	}
	extensions = getdns_dict_create();
	if (! extensions) {
		fprintf(stderr, "Could not create extensions dict\n");
		r = GETDNS_RETURN_MEMORY_ERROR;
		goto done_destroy_context;
	}
	r = getdns_dict_set_int(extensions, "dnssec_return_validation_chain",
	   GETDNS_EXTENSION_TRUE);
	if (r != GETDNS_RETURN_GOOD) {
		fprintf(stderr, "Could not set extension "
		    "\"dnssec_return_validation_chain\": %d\n", r);
		goto done_destroy_extensions;
        }

	/* Create an event base and put it in the context  */
	event_base = event_base_new();
	if (event_base == NULL) {
		fprintf(stderr, "Trying to create the event base failed.");
		r = GETDNS_RETURN_GENERIC_ERROR;
		goto done_destroy_extensions;
	}
	(void) getdns_extension_set_libevent_base(context, event_base);

	/* Make the call */
	r = getdns_address(context, name, extensions, event_base,
	    &transaction_id, callbackfn);
	if (r == GETDNS_RETURN_BAD_DOMAIN_NAME) {
		fprintf(stderr, "Bad domain name: %s.", name);
		goto done_destroy_extensions;
	}
	/* Call the event loop */
	event_base_dispatch(event_base);

	/* Clean up */
done_destroy_extensions:
	getdns_dict_destroy(extensions);
done_destroy_context:
	getdns_context_destroy(context);

	/* Event base must be destroyed after the context, because
	 * the context has to re-register its sockets from the eventbase,
	 * who has to communicate this to the system event-mechanism.
	 */
	if (event_base)
		event_base_free(event_base);

	return r;
}
