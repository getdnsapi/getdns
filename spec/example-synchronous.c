#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getdns_core_only.h>

int main()
{
	getdns_return_t this_ret;  /* Holder for all function returns */
	/* Create the DNS context for this call */
	struct getdns_context *this_context = NULL;
	getdns_return_t context_create_return = getdns_context_create(&this_context, 1);
	if (context_create_return != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "Trying to create the context failed: %d", context_create_return);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}
	/* Set up the getdns_sync_request call */
	const char * this_name  = "www.example.com";
	uint8_t this_request_type = GETDNS_RRTYPE_A;
	/* Get the A and AAAA records */
	struct getdns_dict * this_extensions = getdns_dict_create();
	this_ret = getdns_dict_set_int(this_extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE);
	if (this_ret != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "Trying to set an extension do both IPv4 and IPv6 failed: %d", this_ret);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}
	struct getdns_dict * this_response = NULL;

	/* Make the call */
	getdns_return_t dns_request_return = getdns_general_sync(this_context, this_name, this_request_type,
		this_extensions, &this_response);
	if (dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME)
	{
		fprintf(stderr, "A bad domain name was used: %s. Exiting.", this_name);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}
	else
	{
		/* Be sure the search returned something */
		uint32_t * this_error = NULL;
		this_ret = getdns_dict_get_int(this_response, "status", this_error);  // Ignore any error
		if (*this_error != GETDNS_RESPSTATUS_GOOD)  // If the search didn't return "good"
		{
			fprintf(stderr, "The search had no results, and a return value of %d. Exiting.", *this_error);
			return(GETDNS_RETURN_GENERIC_ERROR);
		}
		struct getdns_list * just_the_addresses_ptr;
		this_ret = getdns_dict_get_list(this_response, "just_address_answers", &just_the_addresses_ptr);  // Ignore any error
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
	/* Clean up */
	getdns_context_destroy(this_context);
	getdns_dict_destroy(this_response); 
	/* Assuming we get here, leave gracefully */
	exit(EXIT_SUCCESS);
}
