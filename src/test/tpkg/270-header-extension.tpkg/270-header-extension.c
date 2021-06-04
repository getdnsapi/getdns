#include <stdio.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

/* Example setting header bits to do a direct authoritative query */

int main()
{
	getdns_return_t r;
	getdns_context *ctx = NULL;
	getdns_dict *extensions = NULL;
	getdns_list *upstreams = NULL;
	getdns_dict *response = NULL;
	uint32_t value;
	char *str;

	if ((r = getdns_context_create(&ctx, 1)))
		fprintf(stderr, "Could not create context");

	else if ((r = getdns_context_set_resolution_type(ctx, GETDNS_RESOLUTION_STUB)))	
		fprintf(stderr, "Could not set stub mode");

	else if ((r = getdns_str2list("[ 185.49.140.60 ]", &upstreams)))
		fprintf(stderr, "Could not make upstreams list");

	else if ((r = getdns_context_set_upstream_recursive_servers(ctx, upstreams)))	
		fprintf(stderr, "Could not set upstreams list");

	else if ((r = getdns_str2dict("{ header: { rd: 0 }"
	                              ", add_opt_parameters: { do_bit: 1 }"
				      "}", &extensions)))
		fprintf(stderr, "Could not create extensions");

	else if ((r = getdns_general_sync(ctx, "bogus.nlnetlabs.nl.", GETDNS_RRTYPE_TXT, extensions, &response)))
		fprintf(stderr, "Could not do lookup");

	else if ((r = getdns_dict_get_int(response, "status", &value)))
		fprintf(stderr, "Could not get status from response");

	else if (value != GETDNS_RESPSTATUS_GOOD) {
		fprintf(stderr, "response['status'] != GETDNS_RESPSTATUS_GOOD: %s"
		              , getdns_get_errorstr_by_id(value));
		r = GETDNS_RETURN_GENERIC_ERROR;

	} else if ((r = getdns_dict_get_int(response, "/replies_tree/0/header/rd", &value)))
		fprintf(stderr, "Could not get RD bit from header");

	else if (value != 0) {
		fprintf(stderr, "RD bit != 0");
		r = GETDNS_RETURN_GENERIC_ERROR;

	} else if ((r = getdns_dict_get_int(response, "/replies_tree/0/header/ancount", &value)))
		fprintf(stderr, "Could not get ANCOUNT from header");

	else if (value != 2) {
		fprintf(stderr, "ANCOUNT != 2");
		r = GETDNS_RETURN_GENERIC_ERROR;

	} else if ((r = getdns_dict_set_int(extensions, "/header/opcode", GETDNS_OPCODE_STATUS)))
		fprintf(stderr, "Could not set opcode");

	else if ((r = getdns_general_sync(ctx, "bogus.nlnetlabs.nl.", GETDNS_RRTYPE_TXT, extensions, &response)))
		fprintf(stderr, "Could not do lookup");

	else if ((r = getdns_dict_remove_name(response, "replies_full")))
		fprintf(stderr, "Could not remove response['replies_full']");

	else if ((r = getdns_dict_remove_name(response, "/replies_tree/0/header/id")))
		fprintf(stderr, "Could not remove ID from response");

	else if (!(str = getdns_pretty_print_dict(response)))
		fprintf(stderr, "Could not pretty print dict");

	else if(printf("%s\n", str), free(str), 0)
		;

	if (response)
		getdns_dict_destroy(response);
	if (upstreams)
		getdns_list_destroy(upstreams);
	if (extensions)
		getdns_dict_destroy(extensions);
	if (ctx)
		getdns_context_destroy(ctx);

	if (r) {
		fprintf(stderr, ": %s\n", getdns_get_errorstr_by_id(r));
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}
