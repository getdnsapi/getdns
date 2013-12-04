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
	UNUSED_PARAM(this_userarg);  /* Not looking at the userarg for this example */
	UNUSED_PARAM(this_context);  /* Not looking at the context for this example */
	getdns_return_t this_ret;  /* Holder for all function returns */
	if (this_callback_type == GETDNS_CALLBACK_COMPLETE)  /* This is a callback with data */
	{
		/* Be sure the search returned something */
		uint32_t * this_error = NULL;
		this_ret = getdns_dict_get_int(this_response, "status", this_error);  // Ignore any error
		if (*this_error != GETDNS_RESPSTATUS_GOOD)  // If the search didn't return "good"
		{
			fprintf(stderr, "The search had no results, and a return value of %d. Exiting.", *this_error);
			return;
		}
		struct getdns_list * just_the_addresses_ptr;
		this_ret = getdns_dict_get_list(this_response, "just_address_answers", &just_the_addresses_ptr);
		if (this_ret != GETDNS_RETURN_GOOD)  // This check is really not needed, but prevents a compiler error under "pedantic"
		{
			fprintf(stderr, "Trying to get the answers failed: %d", this_ret);
			return;
		}
		size_t * num_addresses_ptr = NULL;
		this_ret = getdns_list_get_length(just_the_addresses_ptr, num_addresses_ptr);  // Ignore any error
		/* Go through each record */
		for ( size_t rec_count = 0; rec_count <= *num_addresses_ptr; ++rec_count )
		{
			struct getdns_dict * this_address;
			this_ret = getdns_list_get_dict(just_the_addresses_ptr, rec_count, &this_address);  // Ignore any error
			/* Just print the address */
			struct getdns_bindata * this_address_data;
			this_ret = getdns_dict_get_bindata(this_address, "address_data", &this_address_data); // Ignore any error
			printf("The address is %s", getdns_display_ip_address(this_address_data));
		}
	}
	else if (this_callback_type == GETDNS_CALLBACK_CANCEL)
		fprintf(stderr, "The callback with ID %"PRIu64" was cancelled. Exiting.", this_transaction_id);
	else
		fprintf(stderr, "The callback got a callback_type of %d. Exiting.", this_callback_type);
}

int main()
{
	/* Create the DNS context for this call */
	struct getdns_context *this_context = NULL;
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
		fprintf(stderr, "A bad domain name was used: %s. Exiting.", this_name);
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
	getdns_context_destroy(this_context);
	/* Assuming we get here, leave gracefully */
	exit(EXIT_SUCCESS);
}
