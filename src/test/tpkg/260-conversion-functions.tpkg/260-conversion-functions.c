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

void print_list(getdns_list *rr_list)
{
	char *str = getdns_pretty_print_list(rr_list);
	printf("%s\n", str);
	free(str);
}

void print_json_list(getdns_list *rr_list, int pretty)
{
        char *str = getdns_print_json_list(rr_list, pretty);
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


int main(int argc, char const * const argv[])
{
	getdns_return_t r;
	getdns_dict    *rr_dict;
	getdns_bindata *dns_name;
	getdns_bindata  address = { 4, "\xb9\x31\x8d\x25" };
	getdns_bindata  fourth  = { 11, "last string" };
	size_t          length;
	char           *str;
	uint8_t        *wire, *prev_wire;
	size_t          wire_len;
	getdns_list    *rr_list;
	FILE           *in;
	uint8_t         wire_buf[8200];
	size_t          i;
	size_t          uavailable;
	int             available;
	char            str_buf[10000];
	int             str_len = sizeof(str_buf);

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

	if (!(in = fopen(argv[1], "r")))
		FAIL("Could not fopen %s\n", argv[1]);

	if ((r = getdns_fp2rr_list(in, &rr_list, NULL, 0)))
		FAIL_r("getdns_fp2rr_list");

	fclose(in);

	print_list(rr_list);
	print_json_list(rr_list, 1);


	/* Fill the wire_buf with wireformat RR's in rr_list
	 * wire_buf is too small for last two rr's.
	 */
	wire = wire_buf;
	available = sizeof(wire_buf);

	for (i = 0; !(r = getdns_list_get_dict(rr_list, i, &rr_dict)); i++) {
		prev_wire = wire;
		if ((r = getdns_rr_dict2wire_scan(rr_dict,&wire,&available))) {
			if (r == GETDNS_RETURN_NEED_MORE_SPACE) {
				printf("record %.3zu, available buffer space: "
				       "%d\n", i, available);

				/* The buffer was too small to fit the wire-
				 * format representation.  available now holds
				 * a negative number.  the wire pointer is this
				 * much beyond the end of the buffer space.
				 *
				 * If we would add available to wire, wire
				 * would be positioned at the end of the buffer
				 * but would not be positioned at a clean RR
				 * border.  Therefore we have to remember the
				 * previous position of wire, so we can reset
				 * it at the end of the wireformat representa-
				 * tion of the previously converted rr_dict.
				 */
				wire = prev_wire;
				break;
			}
			else
				FAIL_r("getdns_rr_dict2wire_scan");
		}
		printf("record %3zu, available buffer space: "
		       "%d\n", i, available);
		fflush(stdout);
	}
	if (r == GETDNS_RETURN_NO_SUCH_LIST_ITEM)
		r = GETDNS_RETURN_GOOD;

	getdns_list_destroy(rr_list);

	/* Now scan over the wireformat buffer and convert to rr_dicts again.
	 * Then fill a string buffer with those rr_dicts.
	 */
	available = wire - wire_buf;
	if (available < 0) {
		fprintf(stderr, "Negative sized buffer!\n");
		exit(EXIT_FAILURE);
	}
	uavailable = available;
	wire = wire_buf;

	str = str_buf;
	str_len = sizeof(str_buf);

	while (uavailable > 0 && str_len > 0) {
		rr_dict = NULL;
		if ((r = getdns_wire2rr_dict_scan(
		    (const uint8_t **)&wire, &uavailable, &rr_dict)))
			FAIL_r("getdns_wire2rr_dict_scan");
		
		if ((r = getdns_rr_dict2str_scan(rr_dict, &str, &str_len)))
			FAIL_r("getdns_rr_dict2str_scan");

		getdns_dict_destroy(rr_dict);
	}
	*str = 0;

	/* Print the entire buffer */
	printf("%s", str_buf);

	exit(EXIT_SUCCESS);
}
