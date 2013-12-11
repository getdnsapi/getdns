#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getdns_libevent.h>

#define UNUSED_PARAM(x) ((void)(x))

/* Set up the callback function, which will also do the processing of the results */
void this_callbackfn(struct getdns_context *this_context,
                     getdns_return_t this_callback_type,
                     struct getdns_dict *this_response, 
                     void *this_userarg,
                     getdns_transaction_t this_transaction_id)
{
	UNUSED_PARAM(this_userarg);  /* Not looking at the userarg for this example */
	UNUSED_PARAM(this_context);  /* Not looking at the context for this example */
	getdns_return_t this_ret;  /* Holder for all function returns */
	if (this_callback_type == GETDNS_CALLBACK_COMPLETE)  /* This is a callback with data */
	{
		/* Be sure the search returned something */
		uint32_t this_error;
		this_ret = getdns_dict_get_int(this_response, "status", &this_error);  // Ignore any error
		if (this_error != GETDNS_RESPSTATUS_GOOD)  // If the search didn't return "good"
		{
			fprintf(stderr, "The search had no results, and a return value of %d. Exiting.\n", this_error);
			getdns_dict_destroy(this_response);
			return;
		}
		/* Find all the answers returned */
		struct getdns_list * these_answers;
		this_ret = getdns_dict_get_list(this_response, "replies_tree", &these_answers);
		if (this_ret == GETDNS_RETURN_NO_SUCH_DICT_NAME)
		{
			fprintf(stderr, "Weird: the response had no error, but also no replies_tree. Exiting.\n");
			getdns_dict_destroy(this_response);
			return;
		}
		size_t num_answers;
		this_ret = getdns_list_get_length(these_answers, &num_answers);
		/* Go through each answer */
		for ( size_t rec_count = 0; rec_count < num_answers; ++rec_count )
		{
			struct getdns_dict * this_record;
			this_ret = getdns_list_get_dict(these_answers, rec_count, &this_record);  // Ignore any error
			/* Get the answer section */
			struct getdns_list * this_answer;
			this_ret = getdns_dict_get_list(this_record, "answer", &this_answer);  // Ignore any error
			/* Get each RR in the answer section */
			size_t num_rrs;
			this_ret = getdns_list_get_length(this_answer, &num_rrs);
			for ( size_t rr_count = 0; rr_count < num_rrs; ++rr_count )
			{
				struct getdns_dict *this_rr = NULL;
				this_ret = getdns_list_get_dict(this_answer, rr_count, &this_rr);  // Ignore any error
				/* Get the RDATA */
				struct getdns_dict * this_rdata = NULL;
				this_ret = getdns_dict_get_dict(this_rr, "rdata", &this_rdata);  // Ignore any error
				/* Get the RDATA type */
				uint32_t this_type;
				this_ret = getdns_dict_get_int(this_rr, "type", &this_type);  // Ignore any error
				/* If it is type A or AAAA, print the value */
				if (this_type == GETDNS_RRTYPE_A)
				{
					struct getdns_bindata * this_a_record = NULL;
					this_ret = getdns_dict_get_bindata(this_rdata, "ipv4_address", &this_a_record);
					if (this_ret == GETDNS_RETURN_NO_SUCH_DICT_NAME)
					{
						fprintf(stderr, "Weird: the A record at %d in record at %d had no address. Exiting.\n",
							(int) rr_count, (int) rec_count);
						getdns_dict_destroy(this_response);
						return;
					}
					char *this_address_str = getdns_display_ip_address(this_a_record);
					printf("The IPv4 address is %s\n", this_address_str);
					free(this_address_str);
				}
				else if (this_type == GETDNS_RRTYPE_AAAA)
				{
					struct getdns_bindata * this_aaaa_record = NULL;
					this_ret = getdns_dict_get_bindata(this_rdata, "ipv6_address", &this_aaaa_record);
					if (this_ret == GETDNS_RETURN_NO_SUCH_DICT_NAME)
					{
						fprintf(stderr, "Weird: the AAAA record at %d in record at %d had no address. Exiting.\n",
							(int) rr_count, (int) rec_count);
						getdns_dict_destroy(this_response);
						return;
					}
					char *this_address_str = getdns_display_ip_address(this_aaaa_record);
					printf("The IPv6 address is %s\n", this_address_str);
					free(this_address_str);
				}
			}
		}
	}
	else if (this_callback_type == GETDNS_CALLBACK_CANCEL)
		fprintf(stderr, "The callback with ID %"PRIu64" was cancelled. Exiting.\n", this_transaction_id);
	else
		fprintf(stderr, "The callback got a callback_type of %d. Exiting.\n", this_callback_type);
	getdns_dict_destroy(this_response);
}

int main()
{
	/* Create the DNS context for this call */
	struct getdns_context *this_context = NULL;
	getdns_return_t context_create_return = getdns_context_create(&this_context, 1);
	if (context_create_return != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "Trying to create the context failed: %d\n", context_create_return);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}
	/* Create an event base and put it in the context using the unknown function name */
	struct event_base *this_event_base;
	this_event_base = event_base_new();
	if (this_event_base == NULL)
	{
		fprintf(stderr, "Trying to create the event base failed.\n");
		getdns_context_destroy(this_context);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}
	(void)getdns_extension_set_libevent_base(this_context, this_event_base);
	/* Set up the getdns call */
	const char * this_name  = "www.example.com";
	char* this_userarg = "somestring"; // Could add things here to help identify this call
	getdns_transaction_t this_transaction_id = 0;

	/* Make the call */
	getdns_return_t dns_request_return = getdns_address(this_context, this_name,
		NULL, this_userarg, &this_transaction_id, this_callbackfn);
	if (dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME)
	{
		fprintf(stderr, "A bad domain name was used: %s. Exiting.\n", this_name);
		event_base_free(this_event_base);
		getdns_context_destroy(this_context);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}
	else
	{
		/* Call the event loop */
		int dispatch_return = event_base_dispatch(this_event_base);
		UNUSED_PARAM(dispatch_return);
		// TODO: check the return value above
	}
	/* Clean up */
	event_base_free(this_event_base);
	getdns_context_destroy(this_context);
	/* Assuming we get here, leave gracefully */
	exit(EXIT_SUCCESS);
}
