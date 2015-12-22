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
	getdns_bindata  fourth  = { 11, "last string" };
	size_t          length;
	getdns_list    *list;
	char           *str;
	uint8_t        *wire;
	size_t          wire_len;


	/* Convert string to rr_dict
	 */
	if ((r = getdns_str2rr_dict(
	    "some.domain.tld. 60 IN TXT \"first string\" second \"and third\"",
	    &rr_dict, NULL, 3600)))
		FAIL_r("getdns_str2rr_dict");


	/* Add a fourth text element.
	 */
	if ((r = getdns_dict_set_bindata(rr_dict, "/rdata/txt_strings/-", &fourth)))
		FAIL_r("getdns_list_set_bindata");

	print_dict(rr_dict);


	/* Convert to wireformat from rdata_raw.
	 * Added fourth list element should NOT show.
	 */
	wire = NULL;
	if ((r = getdns_rr_dict2wire(rr_dict, &wire, &wire_len)))
		FAIL_r("getdns_rr_dict2wire");

	print_wire(wire, wire_len);
	free(wire);


	/* Convert to wireformat from parsing rdata fields.
	 * Added fourth list element should show.
	 */
	if ((r = getdns_dict_remove_name(rr_dict, "/rdata/rdata_raw")))
		FAIL_r("getdns_dict_remove_name");

	printf("\nremoved \"/rdata/rdata_raw\":\n\n");

	if ((r = getdns_rr_dict2wire(rr_dict, &wire, &wire_len)))
		FAIL_r("getdns_rr_dict2wire");

	print_wire(wire, wire_len);
	free(wire);


	/* Remove second and third string elements and show text format.
	 */
	if ((r = getdns_dict_remove_name(rr_dict, "/rdata/txt_strings/1")))
		FAIL_r("getdns_dict_remove_name");
	if ((r = getdns_dict_remove_name(rr_dict, "/rdata/txt_strings/1")))
		FAIL_r("getdns_dict_remove_name");

	if ((r = getdns_rr_dict2str(rr_dict, &str)))
		FAIL_r("getdns_rr_dict2str");

	printf("\n%s", str);
	free(str);


	/* Remove all string elements and show text format.
	 */
	if ((r = getdns_dict_remove_name(rr_dict, "/rdata/txt_strings/0")))
		FAIL_r("getdns_dict_remove_name");
	if ((r = getdns_dict_remove_name(rr_dict, "/rdata/txt_strings/0")))
		FAIL_r("getdns_dict_remove_name");

	if ((r = getdns_rr_dict2str(rr_dict, &str)))
		FAIL_r("getdns_rr_dict2str");

	printf("%s", str);
	free(str);

	getdns_dict_destroy(rr_dict);

	/* Construct rr_dict and convert to string
	 */
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
	free(str);

	if ((r = getdns_rr_dict2wire(rr_dict, &wire, &wire_len)))
		FAIL_r("getdns_rr_dict2wire");

	getdns_dict_destroy(rr_dict);
	print_wire(wire, wire_len);
	free(wire);


	/* Convert RR with special rdata fields and repeating last element 
	 * from string to rr_dict
	 */
	if ((r = getdns_str2rr_dict(
	    "hip2 IN HIP 2 200100107B1A74DF365639CC39F1D578 AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D rvs1.example.com. rvs2.example.com.",
	    &rr_dict, "nlnetlabs.nl", 3600)))
		FAIL_r("getdns_str2rr_dict");

	if ((r = getdns_dict_remove_name(rr_dict, "/rdata/rdata_raw")))
		FAIL_r("getdns_dict_remove_name");

	printf("\n");
	print_dict(rr_dict);

	/* Convert RR with special rdata fields and repeating last element
	 * back to string.
	 */
	if ((r = getdns_rr_dict2str(rr_dict, &str)))
		FAIL_r("getdns_rr_dict2str");

	printf("%s", str);
	free(str);


	/* Convert RR with special rdata fields without repeating last element
	 * to string.
	 */
	if ((r = getdns_dict_remove_name(rr_dict, "/rdata/rendezvous_servers")))
		FAIL_r("getdns_dict_remove_name");

	if ((r = getdns_dict_get_bindata(rr_dict, "name", &dns_name)))
		FAIL_r("getdns_dict_get_bindata");

	dns_name->data[4] = '0';

	if ((r = getdns_rr_dict2str(rr_dict, &str)))
		FAIL_r("getdns_rr_dict2str");

	printf("%s\n", str);
	free(str);
	getdns_dict_destroy(rr_dict);


	/* Convert RR with repeat block from string to rr_dict
	 */
	if ((r = getdns_str2rr_dict(
	    "apl APL 1:192.168.42.0/26 1:192.168.42.64/26 !1:192.168.42.128/25  1:224.0.0.0/4  2:FF00:0:0:0:0:0:0:0/8",
	    &rr_dict, "net-dns.org", 3600)))
		FAIL_r("getdns_str2rr_dict");

	if ((r = getdns_dict_remove_name(rr_dict, "/rdata/rdata_raw")))
		FAIL_r("getdns_dict_remove_name");

	print_dict(rr_dict);


	/* Convert repeat block from rr_dict back to string.
	 */
	if ((r = getdns_rr_dict2str(rr_dict, &str)))
		FAIL_r("getdns_rr_dict2str");

	printf("%s", str);
	free(str);
	getdns_dict_destroy(rr_dict);


	exit(EXIT_SUCCESS);
}
