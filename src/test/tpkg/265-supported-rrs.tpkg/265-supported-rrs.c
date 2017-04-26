#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>
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
	getdns_list    *rr_list;
	FILE           *in;
	uint8_t        wirebuf[16384];
	uint8_t        *bufptr = wirebuf;
	int            bufsz = sizeof(wirebuf);
	int            msgsz;
	size_t         rr_list_len;
	getdns_dict    *rr_dict;
	size_t         i;
	getdns_dict    *msg_dict;
	char           *msg_str;

	if (!(in = fopen(argv[1], "r")))
		FAIL("Could not fopen %s\n", argv[1]);

	if ((r = getdns_fp2rr_list(in, &rr_list, NULL, 0)))
		FAIL_r("getdns_fp2rr_list");

	fclose(in);

	print_list(rr_list);

	if ((r = getdns_list_get_length(rr_list, &rr_list_len)))
		FAIL_r("getdns_list_get_length");

	*bufptr++ = 0; *bufptr++ = 0;
	*bufptr++ = 0; *bufptr++ = 0;
	*bufptr++ = 0; *bufptr++ = 0;
	*(uint16_t *)bufptr = htons((uint16_t)rr_list_len); bufptr += 2;
	*bufptr++ = 0; *bufptr++ = 0;
	*bufptr++ = 0; *bufptr++ = 0;
	bufsz -= 12;

	for (i = 0; i < rr_list_len; i++) {
		if ((r = getdns_list_get_dict(rr_list, i, &rr_dict)))
			FAIL_r("getdns_list_get_dict");

		if ((r = getdns_dict_remove_name(rr_dict, "/rdata/rdata_raw")))
			FAIL_r("getdns_dict_remove_name");

		if ((r = getdns_rr_dict2wire_scan(rr_dict, &bufptr, &bufsz))) {
			char *rr_dict_str = getdns_pretty_print_dict(rr_dict);
			fprintf(stderr, "getdns_rr_dict2wire_scan failed: %s"
					" with rr_dict %s\n"
			              , getdns_get_errorstr_by_id(r)
				      , rr_dict_str );
			free(rr_dict_str);
		}

		/* printf("bufptr: %p, bufsz: %d\n", bufptr, bufsz); */
	}
	msgsz = sizeof(wirebuf) - bufsz;

	if ((r = getdns_wire2msg_dict(wirebuf, msgsz, &msg_dict)))
		FAIL_r("getdns_wire2msg_dict");

	if ((r = getdns_msg_dict2str(msg_dict, &msg_str)))
		FAIL_r("getdns_msg_dict2str");

	printf("%s\n", msg_str);

	free(msg_str);
	getdns_dict_destroy(msg_dict);
	getdns_list_destroy(rr_list);
	exit(EXIT_SUCCESS);
}
