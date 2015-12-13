#include <stdio.h>
#include <ctype.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

#define FAIL(...) do { \
	fprintf(stderr, "ERROR in %s:%d, ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\n"); \
	exit(EXIT_FAILURE); \
	} while (0)

#define FAIL_r(function_name) FAIL( "%s returned %d: %s", function_name \
                                  , (int)r, getdns_get_errorstr_by_id(r));

void print_dict(getdns_dict *rr_dict)
{
	char *str = getdns_pretty_print_dict(rr_dict);
	printf("%s\n", str);
	free(str);
}

void print_wire(uint8_t *wire, size_t wire_len)
{
	size_t pos, i;

	for (pos = 0; pos < wire_len; pos += 16) {
		printf("%.4zx", pos);
		for (i = 0; i < 16; i++) {
			if (i % 8 == 0)
				printf(" ");
			if (pos + i < wire_len)
				printf(" %.2x", (int)wire[pos + i]);
			else
				printf("   ");
		}
		printf(" ");
		for (i = 0; i < 16; i++) {
			if (i % 8 == 0)
				printf(" ");
			if (pos + i < wire_len && isprint(wire[pos + i]))
				printf("%c", wire[pos + i]);
			else
				printf(".");
		}
		printf("\n");
	}
}


int main()
{
	getdns_return_t r;
	getdns_dict    *rr_dict;
	getdns_bindata *dns_name;
	getdns_bindata  address = { 4, "\xb9\x31\x8d\x25" };
	getdns_bindata  nothing = { 8, "\x07nothing" };
	char           *str;
	uint8_t         wire_buf[4096], *wire = wire_buf, *end_of_wire;
	size_t          wire_len = sizeof(wire_buf);

	if ((r = getdns_str2rr_dict(
	    "some.domain.tld. 60 CH TXT \"first string\" second \"and third\"",
	    &rr_dict, NULL, 3600)))
		FAIL_r("getdns_str2rr_dict");

	print_dict(rr_dict);

	if ((r = getdns_rr_dict2wire(rr_dict, wire, &wire_len)))
		FAIL_r("getdns_rr_dict2wire");

	print_wire(wire, wire_len);

	if ((r = getdns_dict_remove_name(rr_dict, "/rdata/rdata_raw")))
		FAIL_r("getdns_dict_remove_name");

	print_dict(rr_dict);

	if ((r = getdns_rr_dict2wire(rr_dict, wire, &wire_len)))
		FAIL_r("getdns_rr_dict2wire");

	print_wire(wire, wire_len);

	getdns_dict_destroy(rr_dict);

	wire += wire_len;
	wire_len = sizeof(wire_buf) - (wire - wire_buf);

	if (!(rr_dict = getdns_dict_create()))
		FAIL("getdns_dict_create returned NULL");

	if ((r = getdns_convert_fqdn_to_dns_name("www.getdnsapi.net", &dns_name)))
		FAIL_r("getdns_convert_fqdn_to_dns_name");

	r = getdns_dict_set_bindata(rr_dict, "name", dns_name);
	free(dns_name->data);
	free(dns_name);
	if (r)
		FAIL_r("getdns_dict_set_bindata");

	if ((r = getdns_dict_set_int(rr_dict, "type", GETDNS_RRTYPE_A)))
		FAIL_r("getdns_dict_set_int");

	if ((r = getdns_dict_set_bindata(rr_dict, "/rdata/ipv4_address", &address)))
		FAIL_r("getdns_dict_set_int");

	if ((r = getdns_rr_dict2str(rr_dict, &str)))
		FAIL_r("getdns_rr_dict2str");

	printf("\n%s\n", str);

	if ((r = getdns_rr_dict2wire(rr_dict, wire, &wire_len)))
		FAIL_r("getdns_rr_dict2wire");

	getdns_dict_destroy(rr_dict);
	print_wire(wire, wire_len);

	wire += wire_len;
	wire_len = sizeof(wire_buf) - (wire - wire_buf);

	/* Parse over wire data, convert to string via dict, and print */
	end_of_wire = wire;
	wire = wire_buf;
	wire_len = end_of_wire - wire;

	exit(EXIT_SUCCESS);
}
