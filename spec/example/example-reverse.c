#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getdns_libevent.h>

#define UNUSED_PARAM(x) ((void)(x))

/* Set up the callback function, which will also do the processing of the results */
void this_callbackfn(getdns_context *this_context,
                     getdns_callback_type_t this_callback_type,
                     getdns_dict *this_response, 
                     void *this_userarg,
                     getdns_transaction_t this_transaction_id)
{
	getdns_return_t this_ret;  /* Holder for all function returns */
	UNUSED_PARAM(this_userarg);  /* Not looking at the userarg for this example */
	UNUSED_PARAM(this_context);  /* Not looking at the context for this example */
	UNUSED_PARAM(this_ret); /* Set, but not read */
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
		getdns_list *replies_tree;
		this_ret = getdns_dict_get_list(this_response, "replies_tree", &replies_tree);  // Ignore any error
		size_t num_replies;
		this_ret = getdns_list_get_length(replies_tree, &num_replies);  // Ignore any error
		/* Go through each reply */
		for ( size_t reply_count = 0; reply_count < num_replies; ++reply_count)
		{
			getdns_dict * this_reply;
			this_ret = getdns_list_get_dict(replies_tree, reply_count, &this_reply);  // Ignore any error
			/* Just print the address */
			getdns_list* reply_answers;
			this_ret = getdns_dict_get_list(this_reply, "answer", &reply_answers); // Ignore any error
			size_t num_answers;
			this_ret = getdns_list_get_length(reply_answers, &num_answers);  // Ignore any error
			/* Go through each answer */
			for ( size_t answer_count = 0; answer_count < num_answers; ++answer_count)
			{
				getdns_dict * this_rr;
				this_ret = getdns_list_get_dict(reply_answers, answer_count, &this_rr);
				/* Get the RDATA type */
				uint32_t this_type;
				this_ret = getdns_dict_get_int(this_rr, "type", &this_type);  // Ignore any error
				if (this_type == GETDNS_RRTYPE_PTR)
				{
					getdns_dict *this_rdata;
					this_ret = getdns_dict_get_dict(this_rr, "rdata", &this_rdata);  // Ignore any error

					getdns_bindata * this_dname;
					this_ret = getdns_dict_get_bindata(this_rdata, "rdata_raw", &this_dname);
					char *this_dname_str;
				       	this_ret = getdns_convert_dns_name_to_fqdn(this_dname, &this_dname_str); // Ignore any error
					printf("The dname is %s\n", this_dname_str);
					free(this_dname_str);
				}
			}

		}
	}
	else if (this_callback_type == GETDNS_CALLBACK_CANCEL)
		fprintf(stderr, "The callback with ID %"PRIu64" was cancelled. Exiting.", this_transaction_id);
	else
		fprintf(stderr, "The callback got a callback_type of %d. Exiting.", this_callback_type);
	getdns_dict_destroy(this_response);
}

int main()
{
	/* Create the DNS context for this call */
	getdns_context *this_context = NULL;
	getdns_return_t context_create_return = getdns_context_create(&this_context, 1);
	if (context_create_return != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "Trying to create the context failed: %d", context_create_return);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}
	/* Create an event base and put it in the context using the unknown function name */
	struct event_base *this_event_base;
	this_event_base = event_base_new();
	if (this_event_base == NULL)
	{
		fprintf(stderr, "Trying to create the event base failed.");
		getdns_context_destroy(this_context);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}
	(void)getdns_extension_set_libevent_base(this_context, this_event_base);
	/* Set up the getdns call */
	getdns_dict * this_addr_to_look_up = getdns_dict_create();
	// TODO: check the return value above
	getdns_bindata this_type = { 4, (void *)"IPv4" };
	getdns_return_t this_ret = getdns_dict_set_bindata(this_addr_to_look_up, "address_type", &this_type);
	UNUSED_PARAM(this_ret);
	getdns_bindata this_ipv4_addr = { 4, (void *)"\x08\x08\x08\x08" };
	this_ret = getdns_dict_set_bindata(this_addr_to_look_up, "address_data", &this_ipv4_addr);
	char* this_userarg = "somestring"; // Could add things here to help identify this call
	getdns_transaction_t this_transaction_id = 0;

	/* Make the call */
	getdns_return_t dns_request_return = getdns_hostname(this_context, this_addr_to_look_up,
		NULL, this_userarg, &this_transaction_id, this_callbackfn);
	if (dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME)
	{
		char *ip_address_str = getdns_display_ip_address(&this_ipv4_addr);

		fprintf(stderr, "A bad IP address was used: %s. Exiting.\n", ip_address_str);
		free(ip_address_str);
		getdns_dict_destroy(this_addr_to_look_up);
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
	getdns_dict_destroy(this_addr_to_look_up);
	event_base_free(this_event_base);
	getdns_context_destroy(this_context);
	/* Assuming we get here, leave gracefully */
	exit(EXIT_SUCCESS);
}
