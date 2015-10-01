#include <stdio.h>
#include <getdns_core_only.h>

int main()
{
	getdns_return_t  r;
	getdns_context  *context  = NULL;
	getdns_dict     *response = NULL;
	uint32_t         status;
	getdns_list     *just_address_answers;
	size_t           length, i;

	/* Create the DNS context for this call */
	if ((r = getdns_context_create(&context, 1)))
		fprintf(stderr, "Trying to create the context failed");

	else if ((r = getdns_address_sync(context, "example.com", NULL, &response)))
		fprintf(stderr, "Error scheduling synchronous request");

	else if ((r = getdns_dict_get_int(response, "status", &status)))
		fprintf(stderr, "Could not get \"status\" from reponse");

	else if (status != GETDNS_RESPSTATUS_GOOD)
		fprintf(stderr, "The search had no results, and a return value of %zu.\n", status);

	else if ((r = getdns_dict_get_list(response, "just_address_answers", &just_address_answers)))
		fprintf(stderr, "Could not get \"just_address_answers\" from reponse");

	else if ((r = getdns_list_get_length(just_address_answers, &length)))
		fprintf(stderr, "Could not get just_address_answers\' length");

	else for (i = 0; i < length && r == GETDNS_RETURN_GOOD; i++) {
		getdns_dict    *address;
		getdns_bindata *address_data;
		char           *address_str;

		if ((r = getdns_list_get_dict(just_address_answers, i, &address)))
			fprintf(stderr, "Could not get address %zu from just_address_answers", i);

		else if ((r = getdns_dict_get_bindata(address, "address_data", &address_data)))
			fprintf(stderr, "Could not get \"address_data\" from address");

		else if (!(address_str = getdns_display_ip_address(address_data))) {
			fprintf(stderr, "Could not convert address to string");
			r = GETDNS_RETURN_MEMORY_ERROR;
		}
		else {
			printf("The address is %s\n", address_str);
			free(address_str);
		}
	}
	/* Clean up */
	if (response)
		getdns_dict_destroy(response); 

	if (context)
		getdns_context_destroy(context);

	if (r) {
		fprintf(stderr, ": %d\n", r);
		exit(EXIT_FAILURE);
	}
	/* Assuming we get here, leave gracefully */
	exit(EXIT_SUCCESS);
}
