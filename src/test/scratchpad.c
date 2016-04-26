#include <stdio.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

/* Example setting header bits to do a direct authoritative query */

int main()
{
	getdns_return_t r;
	getdns_context *ctx = NULL;
	getdns_dict *extensions = NULL;
	getdns_bindata ipv4 = { 4, (uint8_t*)"IPv4" };
	/* 185.49.141.37 */
	getdns_bindata nsip = { 4, (uint8_t*)"\xb9\x31\x8d\x25" };
	getdns_dict *upstream = NULL;
	getdns_list *upstreams = NULL;
	getdns_dict *response = NULL;
	char *str;

	if ((r = getdns_context_create(&ctx, 1)))
		fprintf(stderr, "Could not create context");

	else if (!(extensions = getdns_dict_create_with_context(ctx))) {
		fprintf(stderr, "Could not create dictionary");
		r = GETDNS_RETURN_MEMORY_ERROR;

	} else if ((r = getdns_dict_set_int(extensions, "/header/cd", 1)))
		fprintf(stderr, "Could not set CD bit");

	else if ((r = getdns_dict_set_int(extensions, "/header/rd", 0)))
		fprintf(stderr, "Could not set RD bit");

	else if ((r = getdns_dict_set_int(extensions, "/add_opt_parameters/do_bit", 1)))
		fprintf(stderr, "Could not set qtype");

	else if (!(str = getdns_pretty_print_dict(extensions)))
		fprintf(stderr, "Could not pretty print dict");

	else if(printf("extensions: %s\n", str), free(str), 0)
		;

	else if (!(upstream = getdns_dict_create_with_context(ctx))) {
		fprintf(stderr, "Could not create upstream dictionary");
		r = GETDNS_RETURN_MEMORY_ERROR;

	} else if ((r = getdns_dict_set_bindata(upstream, "address_type", &ipv4)))
		fprintf(stderr, "Could set \"address_type\"");

	else if ((r = getdns_dict_set_bindata(upstream, "address_data", &nsip)))
		fprintf(stderr, "Could set \"address_data\"");

	else if (!(upstreams = getdns_list_create_with_context(ctx))) {
		fprintf(stderr, "Could not create upstreams list");
		r = GETDNS_RETURN_MEMORY_ERROR;

	} else if ((r = getdns_list_set_dict(upstreams, 0, upstream)))
		fprintf(stderr, "Could not append upstream to upstreams list");

	else if ((r = getdns_context_set_resolution_type(ctx, GETDNS_RESOLUTION_STUB)))	
		fprintf(stderr, "Could not set stub mode");

	else if ((r = getdns_context_set_upstream_recursive_servers(ctx, upstreams)))	
		fprintf(stderr, "Could not set upstreams list");

	else if ((r = getdns_address_sync(ctx, "getdnsapi.net", extensions, &response)))
		fprintf(stderr, "Could not do address lookup");

	else if (!(str = getdns_pretty_print_dict(response)))
		fprintf(stderr, "Could not pretty print dict");

	else if(printf("response: %s\n", str), free(str), 0)
		;

	if (response)
		getdns_dict_destroy(response);
	if (upstreams)
		getdns_list_destroy(upstreams);
	if (upstream)
		getdns_dict_destroy(upstream);
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
