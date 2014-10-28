/*
 * Copyright (c) 2013, NLNet Labs, Verisign, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the names of the copyright holders nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Verisign, Inc. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

int my_get_rrtype(const char *t);

void
print_usage(FILE *out, const char *progname)
{
	fprintf(out, "usage: %s [@<server>] [+extension] [<name>] [<type>]\n",
	    progname);
	fprintf(out, "options:\n");
	fprintf(out, "\t-a\tPerform asynchronous resolution "
	    "(default = synchronous)\n");
	fprintf(out, "\t-A\taddress lookup\n");
	fprintf(out, "\t-b <bufsize>\tSet edns0 max_udp_payload size\n");
	fprintf(out, "\t-D\tSet edns0 do bit\n");
	fprintf(out, "\t-d\tclear edns0 do bit\n");
	fprintf(out, "\t-G\tgeneral lookup\n");
	fprintf(out, "\t-H\thostname lookup\n");
	fprintf(out, "\t-h\tPrint this help\n");
	fprintf(out, "\t-i\tPrint api information\n");
	fprintf(out, "\t-I\tInteractive mode (> 1 queries on same context)\n");
	fprintf(out, "\t-r\tSet recursing resolution type\n");
	fprintf(out, "\t-s\tSet stub resolution type (default = recursing)\n");
	fprintf(out, "\t-S\tservice lookup\n");
	fprintf(out, "\t-t <timeout>\tSet timeout in miliseconds\n");
	fprintf(out, "\t-T\tSet transport to TCP only\n");
	fprintf(out, "\t-O\tSet transport to TCP only keep connections open\n");
	fprintf(out, "\t-u\tSet transport to UDP with TCP fallback\n");
	fprintf(out, "\t-U\tSet transport to UDP only\n");
}

getdns_dict *
ipaddr_dict(getdns_context *context, char *ipstr)
{
	getdns_dict *r = getdns_dict_create_with_context(context);
	char *s = strchr(ipstr, '%'), *scope_id_str = "";
	char *p = strchr(ipstr, '@'), *portstr = "";
	uint8_t buf[sizeof(struct in6_addr)];
	getdns_bindata addr;

	addr.data = buf;

	if (!r) return NULL;
	if (s) {
		*s = 0;
		scope_id_str = s + 1;
	}
	if (p) {
		*p = 0;
		portstr = p + 1;
	}
	if (strchr(ipstr, ':')) {
		getdns_dict_util_set_string(r, "address_type", "IPv6");
		addr.size = 16;
		(void) inet_pton(AF_INET6, ipstr, buf);
	} else {
		getdns_dict_util_set_string(r, "address_type", "IPv4");
		addr.size = 4;
		(void) inet_pton(AF_INET, ipstr, buf);
	}
	getdns_dict_set_bindata(r, "address_data", &addr);
	if (*portstr)
		getdns_dict_set_int(r, "port", (int32_t)atoi(portstr));
	if (*scope_id_str)
		getdns_dict_util_set_string(r, "scope_id", scope_id_str);

	return r;
}

void callback(getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *response, void *userarg, getdns_transaction_t trans_id)
{
	getdns_dict **response_ptr = (getdns_dict **)userarg;

	if (response)
		*response_ptr = response;
}

int
main(int argc, char **argv)
{
	const char *the_root = ".";
	const char *name = the_root;
	getdns_context *context;
	getdns_dict *extensions;
	getdns_dict *response = NULL;
	char *response_str;
	getdns_return_t r;
	uint16_t request_type = GETDNS_RRTYPE_NS;
	size_t i;
	char *arg, *c, *endptr;
	int t, timeout, edns0_size;
	getdns_list *upstream_list;
	size_t upstream_count = 0;
	int print_api_info = 0, async = 0, interactive = 0;
	enum { GENERAL, ADDRESS, HOSTNAME, SERVICE } calltype = GENERAL;

	if ((r = getdns_context_create(&context, 1))) {
		fprintf(stderr, "Create context failed: %d\n", r);
		return r;
	}
	upstream_list = getdns_list_create_with_context(context);
	if (!upstream_list) {
		fprintf(stderr, "Could not create upstream list\n");
		r = GETDNS_RETURN_MEMORY_ERROR;
		goto done_destroy_context;
	}
	extensions = getdns_dict_create();
	if (! extensions) {
		fprintf(stderr, "Could not create extensions dict\n");
		r = GETDNS_RETURN_MEMORY_ERROR;
		goto done_destroy_context;
	}

	for (i = 1; i < argc; i++) {
		arg = argv[i];
		if ((t = my_get_rrtype(arg)) >= 0) {
			request_type = t;
			continue;

		} else if (arg[0] == '+') {
			if ((r = getdns_dict_set_int(extensions, arg+1,
			    GETDNS_EXTENSION_TRUE))) {
				fprintf(stderr, "Could not set extension "
				    "\"%s\": %d\n", argv[i], r);
				goto done_destroy_extensions;
			}
			continue;

		} else if (arg[0] == '@') {
			getdns_dict *upstream = ipaddr_dict(context, arg + 1);
			if (upstream)
				getdns_list_set_dict(upstream_list,
				    upstream_count++, upstream);
			continue;
		} else if (arg[0] != '-') {
			if (name == the_root) {
				name = arg;
				continue;
			}
			fprintf(stderr, "More than one <name> given\n");
			print_usage(stderr, argv[0]);
			return -1;
		}
		for (c = arg+1; *c; c++) {
			switch (*c) {
			case 'a':
				async = 1;
				break;
			case 'A':
				calltype = ADDRESS;
				break;
			case 'b':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "max_udp_payload_size "
					    "expected after -b\n");
					return -1;
				}
				edns0_size = strtol(argv[i], &endptr, 10);
				if (*endptr || edns0_size < 0) {
					fprintf(stderr, "positive "
					    "numeric max_udp_payload_size "
					    "expected after -b\n");
					return -1;
				}
				getdns_context_set_edns_maximum_udp_payload_size(
				    context, (uint16_t) edns0_size);
				goto next;
			case 'D':
				(void) getdns_context_set_edns_do_bit(context, 1);
				break;
			case 'd':
				(void) getdns_context_set_edns_do_bit(context, 0);
				break;
			case 'G':
				calltype = GENERAL;
				break;
			case 'H':
				calltype = HOSTNAME;
				break;
			case 'h':
				print_usage(stdout, argv[0]);
				return 0;
			case 'i':
				print_api_info = 1;
				break;
			case 'I':
				interactive = 1;
				break;
			case 'r':
				getdns_context_set_resolution_type(
				    context,
				    GETDNS_RESOLUTION_RECURSING);
				break;
			case 's':
				getdns_context_set_resolution_type(
				    context, GETDNS_RESOLUTION_STUB);
				break;
			case 'S':
				calltype = SERVICE;
				break;
			case 't':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "ttl expected "
					    "after -t\n");
					return -1;
				}
				timeout = strtol(argv[i], &endptr, 10);
				if (*endptr || timeout < 0) {
					fprintf(stderr, "positive "
					    "numeric ttl expected "
					    "after -t\n");
					return -1;
				}
				getdns_context_set_timeout(
					context, timeout);
				goto next;
			case 'T':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_TCP_ONLY);
				break;
			case 'O':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN);
				break;
			case 'u':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP);
				break;
			case 'U':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_UDP_ONLY);
				break;


			default:
				fprintf(stderr, "Unknown option "
				    "\"%c\"\n", *c);
				return -1;
			}
		}
next:		;
	}
	if (upstream_count &&
	    (r = getdns_context_set_upstream_recursive_servers(
	    context, upstream_list))) {
		fprintf(stderr, "Error setting upstream recursive servers\n");
		goto done_destroy_extensions;
	}
	if (print_api_info) {
		fprintf(stdout, "%s\n", getdns_pretty_print_dict(
		    getdns_context_get_api_information(context)));
		return 0;
	}
	/* Make the call */
	do {
		char line[1024], *token;
		if (interactive) {
			fprintf(stdout, "> ");
			if (!fgets(line, 1024, stdin) || !*line)
				break;

			token = strtok(line, " \t\f\n\r");
			if (! token)
				continue;

			do 	if ((t = my_get_rrtype(token)) >= 0)
					request_type = t;
				else
					name = token;
			while ((token = strtok(NULL, " \t\f\n\r")));
		}
		if (async) {
			switch (calltype) {
			case GENERAL:
				r = getdns_general(context, name, request_type,
				    extensions, &response, NULL, callback);
				break;
			case ADDRESS:
				r = getdns_address(context, name,
				    extensions, &response, NULL, callback);
				break;
			case SERVICE:
				r = getdns_service(context, name,
				    extensions, &response, NULL, callback);
				break;
			default:
				r = GETDNS_RETURN_GENERIC_ERROR;
				break;
			}
			if (r)
				goto done_destroy_extensions;

			getdns_context_run(context);
		} else {
			switch (calltype) {
			case GENERAL:
				r = getdns_general_sync(context, name,
				    request_type, extensions, &response);
				break;
			case ADDRESS:
				r = getdns_address_sync(context, name,
				    extensions, &response);
				break;
			case SERVICE:
				r = getdns_service_sync(context, name,
				    extensions, &response);
				break;
			default:
				r = GETDNS_RETURN_GENERIC_ERROR;
				break;
			}
			if (r)
				goto done_destroy_extensions;
		}
		if ((response_str = getdns_pretty_print_dict(response))) {
			fprintf(stdout, "%s\n", response_str);
			free(response_str);
		} else {
			r = GETDNS_RETURN_MEMORY_ERROR;
			fprintf(stderr, "Could not print response\n");
		}
	} while (interactive);

	/* Clean up */
done_destroy_extensions:
	getdns_dict_destroy(extensions);
done_destroy_context:
	if (upstream_list) getdns_list_destroy(upstream_list);
	if (response) getdns_dict_destroy(response);
	getdns_context_destroy(context);

	if (r)
		fprintf(stderr, "An error occurred: %d\n", r);
	return r;
}

int get_rrtype(const char *t) {
	switch (t[0]) {
	case 'A':
	case 'a': switch (t[1]) {
	          case '\0': return GETDNS_RRTYPE_A;
	          case '6': return GETDNS_RRTYPE_A6;
	          case 'A':
	          case 'a': /* before "AA", final "AA" (GETDNS_RRTYPE_AAAA) */
	                    if ((t[2]|0x20) == 'a' && (t[3]|0x20) == 'a' && t[4] == '\0')
	                              return GETDNS_RRTYPE_AAAA;
	                    return -1;
	          case 'F':
	          case 'f': /* before "AF", final "SDB" (GETDNS_RRTYPE_AFSDB) */
	                    if ((t[2]|0x20) == 's' && (t[3]|0x20) == 'd' && (t[4]|0x20) == 'b' && t[5] == '\0')
	                              return GETDNS_RRTYPE_AFSDB;
	                    return -1;
	          case 'P':
	          case 'p': /* before "AP", final "L" (GETDNS_RRTYPE_APL) */
	                    if ((t[2]|0x20) == 'l' && t[3] == '\0')
	                              return GETDNS_RRTYPE_APL;
	                    return -1;
	          case 'T':
	          case 't': /* before "AT", final "MA" (GETDNS_RRTYPE_ATMA) */
	                    if ((t[2]|0x20) == 'm' && (t[3]|0x20) == 'a' && t[4] == '\0')
	                              return GETDNS_RRTYPE_ATMA;
	                    return -1;
	          case 'X':
	          case 'x': /* before "AX", final "FR" (GETDNS_RRTYPE_AXFR) */
	                    if ((t[2]|0x20) == 'f' && (t[3]|0x20) == 'r' && t[4] == '\0')
	                              return GETDNS_RRTYPE_AXFR;
	                    return -1;
	          default : return -1;
	          };
	case 'C':
	case 'c': switch (t[1]) {
	          case 'A':
	          case 'a': /* before "CA", final "A" (GETDNS_RRTYPE_CAA) */
	                    if ((t[2]|0x20) == 'a' && t[3] == '\0')
	                              return GETDNS_RRTYPE_CAA;
	                    return -1;
	          case 'D':
	          case 'd': switch (t[2]) {
	                    case 'N':
	                    case 'n': /* before "CDN", final "SKEY" (GETDNS_RRTYPE_CDNSKEY) */
	                              if ((t[3]|0x20) == 's' && (t[4]|0x20) == 'k' && (t[5]|0x20) == 'e' && (t[6]|0x20) == 'y' && t[7] == '\0')
	                                        return GETDNS_RRTYPE_CDNSKEY;
	                              return -1;
	                    case 'S':
	                    case 's': return GETDNS_RRTYPE_CDS;
	                    default : return -1;
	                    };
	          case 'E':
	          case 'e': /* before "CE", final "RT" (GETDNS_RRTYPE_CERT) */
	                    if ((t[2]|0x20) == 'r' && (t[3]|0x20) == 't' && t[4] == '\0')
	                              return GETDNS_RRTYPE_CERT;
	                    return -1;
	          case 'N':
	          case 'n': /* before "CN", final "AME" (GETDNS_RRTYPE_CNAME) */
	                    if ((t[2]|0x20) == 'a' && (t[3]|0x20) == 'm' && (t[4]|0x20) == 'e' && t[5] == '\0')
	                              return GETDNS_RRTYPE_CNAME;
	                    return -1;
	          default : return -1;
	          };
	case 'D':
	case 'd': switch (t[1]) {
	          case 'H':
	          case 'h': /* before "DH", final "CID" (GETDNS_RRTYPE_DHCID) */
	                    if ((t[2]|0x20) == 'c' && (t[3]|0x20) == 'i' && (t[4]|0x20) == 'd' && t[5] == '\0')
	                              return GETDNS_RRTYPE_DHCID;
	                    return -1;
	          case 'L':
	          case 'l': /* before "DL", final "V" (GETDNS_RRTYPE_DLV) */
	                    if ((t[2]|0x20) == 'v' && t[3] == '\0')
	                              return GETDNS_RRTYPE_DLV;
	                    return -1;
	          case 'N':
	          case 'n': switch (t[2]) {
	                    case 'A':
	                    case 'a': /* before "DNA", final "ME" (GETDNS_RRTYPE_DNAME) */
	                              if ((t[3]|0x20) == 'm' && (t[4]|0x20) == 'e' && t[5] == '\0')
	                                        return GETDNS_RRTYPE_DNAME;
	                              return -1;
	                    case 'S':
	                    case 's': /* before "DNS", final "KEY" (GETDNS_RRTYPE_DNSKEY) */
	                              if ((t[3]|0x20) == 'k' && (t[4]|0x20) == 'e' && (t[5]|0x20) == 'y' && t[6] == '\0')
	                                        return GETDNS_RRTYPE_DNSKEY;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'S':
	          case 's': return GETDNS_RRTYPE_DS;
	          default : return -1;
	          };
	case 'E':
	case 'e': switch (t[1]) {
	          case 'I':
	          case 'i': /* before "EI", final "D" (GETDNS_RRTYPE_EID) */
	                    if ((t[2]|0x20) == 'd' && t[3] == '\0')
	                              return GETDNS_RRTYPE_EID;
	                    return -1;
	          case 'U':
	          case 'u': /* before "EU", next "I" */
	                    if ((t[2]|0x20) != 'i')
	                              return -1;
	                    switch (t[3]) {
	                    case '4': /* before "EUI4", final "8" (GETDNS_RRTYPE_EUI48) */
	                              if (t[4] == '8' && t[5] == '\0')
	                                        return GETDNS_RRTYPE_EUI48;
	                              return -1;
	                    case '6': /* before "EUI6", final "4" (GETDNS_RRTYPE_EUI64) */
	                              if (t[4] == '4' && t[5] == '\0')
	                                        return GETDNS_RRTYPE_EUI64;
	                              return -1;
	                    default : return -1;
	                    };
	          default : return -1;
	          };
	case 'G':
	case 'g': switch (t[1]) {
	          case 'I':
	          case 'i': /* before "GI", final "D" (GETDNS_RRTYPE_GID) */
	                    if ((t[2]|0x20) == 'd' && t[3] == '\0')
	                              return GETDNS_RRTYPE_GID;
	                    return -1;
	          case 'P':
	          case 'p': /* before "GP", final "OS" (GETDNS_RRTYPE_GPOS) */
	                    if ((t[2]|0x20) == 'o' && (t[3]|0x20) == 's' && t[4] == '\0')
	                              return GETDNS_RRTYPE_GPOS;
	                    return -1;
	          default : return -1;
	          };
	case 'H':
	case 'h': /* before "H", next "I" */
	          if ((t[1]|0x20) != 'i')
	                    return -1;
	          switch (t[2]) {
	          case 'N':
	          case 'n': /* before "HIN", final "FO" (GETDNS_RRTYPE_HINFO) */
	                    if ((t[3]|0x20) == 'f' && (t[4]|0x20) == 'o' && t[5] == '\0')
	                              return GETDNS_RRTYPE_HINFO;
	                    return -1;
	          case 'P':
	          case 'p': return GETDNS_RRTYPE_HIP;
	          default : return -1;
	          };
	case 'I':
	case 'i': switch (t[1]) {
	          case 'P':
	          case 'p': /* before "IP", final "SECKEY" (GETDNS_RRTYPE_IPSECKEY) */
	                    if ((t[2]|0x20) == 's' && (t[3]|0x20) == 'e' && (t[4]|0x20) == 'c' && (t[5]|0x20) == 'k' && (t[6]|0x20) == 'e' && (t[7]|0x20) == 'y' && t[8] == '\0')
	                              return GETDNS_RRTYPE_IPSECKEY;
	                    return -1;
	          case 'S':
	          case 's': /* before "IS", final "DN" (GETDNS_RRTYPE_ISDN) */
	                    if ((t[2]|0x20) == 'd' && (t[3]|0x20) == 'n' && t[4] == '\0')
	                              return GETDNS_RRTYPE_ISDN;
	                    return -1;
	          case 'X':
	          case 'x': /* before "IX", final "FR" (GETDNS_RRTYPE_IXFR) */
	                    if ((t[2]|0x20) == 'f' && (t[3]|0x20) == 'r' && t[4] == '\0')
	                              return GETDNS_RRTYPE_IXFR;
	                    return -1;
	          default : return -1;
	          };
	case 'K':
	case 'k': switch (t[1]) {
	          case 'E':
	          case 'e': /* before "KE", final "Y" (GETDNS_RRTYPE_KEY) */
	                    if ((t[2]|0x20) == 'y' && t[3] == '\0')
	                              return GETDNS_RRTYPE_KEY;
	                    return -1;
	          case 'X':
	          case 'x': return GETDNS_RRTYPE_KX;
	          default : return -1;
	          };
	case 'L':
	case 'l': switch (t[1]) {
	          case '3': /* before "L3", final "2" (GETDNS_RRTYPE_L32) */
	                    if (t[2] == '2' && t[3] == '\0')
	                              return GETDNS_RRTYPE_L32;
	                    return -1;
	          case '6': /* before "L6", final "4" (GETDNS_RRTYPE_L64) */
	                    if (t[2] == '4' && t[3] == '\0')
	                              return GETDNS_RRTYPE_L64;
	                    return -1;
	          case 'O':
	          case 'o': /* before "LO", final "C" (GETDNS_RRTYPE_LOC) */
	                    if ((t[2]|0x20) == 'c' && t[3] == '\0')
	                              return GETDNS_RRTYPE_LOC;
	                    return -1;
	          case 'P':
	          case 'p': return GETDNS_RRTYPE_LP;
	          default : return -1;
	          };
	case 'M':
	case 'm': switch (t[1]) {
	          case 'A':
	          case 'a': /* before "MA", next "IL" */
	                    if ((t[2]|0x20) != 'i' && (t[3]|0x20) != 'l')
	                              return -1;
	                    switch (t[4]) {
	                    case 'A':
	                    case 'a': return GETDNS_RRTYPE_MAILA;
	                    case 'B':
	                    case 'b': return GETDNS_RRTYPE_MAILB;
	                    default : return -1;
	                    };
	          case 'B':
	          case 'b': return GETDNS_RRTYPE_MB;
	          case 'D':
	          case 'd': return GETDNS_RRTYPE_MD;
	          case 'F':
	          case 'f': return GETDNS_RRTYPE_MF;
	          case 'G':
	          case 'g': return GETDNS_RRTYPE_MG;
	          case 'I':
	          case 'i': /* before "MI", final "NFO" (GETDNS_RRTYPE_MINFO) */
	                    if ((t[2]|0x20) == 'n' && (t[3]|0x20) == 'f' && (t[4]|0x20) == 'o' && t[5] == '\0')
	                              return GETDNS_RRTYPE_MINFO;
	                    return -1;
	          case 'R':
	          case 'r': return GETDNS_RRTYPE_MR;
	          case 'X':
	          case 'x': return GETDNS_RRTYPE_MX;
	          default : return -1;
	          };
	case 'N':
	case 'n': switch (t[1]) {
	          case 'A':
	          case 'a': /* before "NA", final "PTR" (GETDNS_RRTYPE_NAPTR) */
	                    if ((t[2]|0x20) == 'p' && (t[3]|0x20) == 't' && (t[4]|0x20) == 'r' && t[5] == '\0')
	                              return GETDNS_RRTYPE_NAPTR;
	                    return -1;
	          case 'I':
	          case 'i': switch (t[2]) {
	                    case 'D':
	                    case 'd': return GETDNS_RRTYPE_NID;
	                    case 'M':
	                    case 'm': /* before "NIM", final "LOC" (GETDNS_RRTYPE_NIMLOC) */
	                              if ((t[3]|0x20) == 'l' && (t[4]|0x20) == 'o' && (t[5]|0x20) == 'c' && t[6] == '\0')
	                                        return GETDNS_RRTYPE_NIMLOC;
	                              return -1;
	                    case 'N':
	                    case 'n': /* before "NIN", final "FO" (GETDNS_RRTYPE_NINFO) */
	                              if ((t[3]|0x20) == 'f' && (t[4]|0x20) == 'o' && t[5] == '\0')
	                                        return GETDNS_RRTYPE_NINFO;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'S':
	          case 's': switch (t[2]) {
	                    case '\0': return GETDNS_RRTYPE_NS;
	                    case 'A':
	                    case 'a': /* before "NSA", final "P" (GETDNS_RRTYPE_NSAP) */
	                              if ((t[3]|0x20) == 'p' && t[4] == '\0')
	                                        return GETDNS_RRTYPE_NSAP;
	                              return -1;
	                    case 'E':
	                    case 'e': /* before "NSE", final "C3PARAM" (GETDNS_RRTYPE_NSEC3PARAM) */
	                              if ((t[3]|0x20) == 'c' && t[4] == '3' && (t[5]|0x20) == 'p' && (t[6]|0x20) == 'a' && (t[7]|0x20) == 'r' && (t[8]|0x20) == 'a' && (t[9]|0x20) == 'm' && t[10] == '\0')
	                                        return GETDNS_RRTYPE_NSEC3PARAM;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'U':
	          case 'u': /* before "NU", final "LL" (GETDNS_RRTYPE_NULL) */
	                    if ((t[2]|0x20) == 'l' && (t[3]|0x20) == 'l' && t[4] == '\0')
	                              return GETDNS_RRTYPE_NULL;
	                    return -1;
	          case 'X':
	          case 'x': /* before "NX", final "T" (GETDNS_RRTYPE_NXT) */
	                    if ((t[2]|0x20) == 't' && t[3] == '\0')
	                              return GETDNS_RRTYPE_NXT;
	                    return -1;
	          default : return -1;
	          };
	case 'O':
	case 'o': /* before "O", next "P" */
	          if ((t[1]|0x20) != 'p')
	                    return -1;
	          switch (t[2]) {
	          case 'E':
	          case 'e': /* before "OPE", final "NPGPKEY" (GETDNS_RRTYPE_OPENPGPKEY) */
	                    if ((t[3]|0x20) == 'n' && (t[4]|0x20) == 'p' && (t[5]|0x20) == 'g' && (t[6]|0x20) == 'p' && (t[7]|0x20) == 'k' && (t[8]|0x20) == 'e' && (t[9]|0x20) == 'y' && t[10] == '\0')
	                              return GETDNS_RRTYPE_OPENPGPKEY;
	                    return -1;
	          case 'T':
	          case 't': return GETDNS_RRTYPE_OPT;
	          default : return -1;
	          };
	case 'P':
	case 'p': switch (t[1]) {
	          case 'T':
	          case 't': /* before "PT", final "R" (GETDNS_RRTYPE_PTR) */
	                    if ((t[2]|0x20) == 'r' && t[3] == '\0')
	                              return GETDNS_RRTYPE_PTR;
	                    return -1;
	          case 'X':
	          case 'x': return GETDNS_RRTYPE_PX;
	          default : return -1;
	          };
	case 'R':
	case 'r': switch (t[1]) {
	          case 'K':
	          case 'k': /* before "RK", final "EY" (GETDNS_RRTYPE_RKEY) */
	                    if ((t[2]|0x20) == 'e' && (t[3]|0x20) == 'y' && t[4] == '\0')
	                              return GETDNS_RRTYPE_RKEY;
	                    return -1;
	          case 'P':
	          case 'p': return GETDNS_RRTYPE_RP;
	          case 'R':
	          case 'r': /* before "RR", final "SIG" (GETDNS_RRTYPE_RRSIG) */
	                    if ((t[2]|0x20) == 's' && (t[3]|0x20) == 'i' && (t[4]|0x20) == 'g' && t[5] == '\0')
	                              return GETDNS_RRTYPE_RRSIG;
	                    return -1;
	          case 'T':
	          case 't': return GETDNS_RRTYPE_RT;
	          default : return -1;
	          };
	case 'S':
	case 's': switch (t[1]) {
	          case 'I':
	          case 'i': switch (t[2]) {
	                    case 'G':
	                    case 'g': return GETDNS_RRTYPE_SIG;
	                    case 'N':
	                    case 'n': /* before "SIN", final "K" (GETDNS_RRTYPE_SINK) */
	                              if ((t[3]|0x20) == 'k' && t[4] == '\0')
	                                        return GETDNS_RRTYPE_SINK;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'O':
	          case 'o': /* before "SO", final "A" (GETDNS_RRTYPE_SOA) */
	                    if ((t[2]|0x20) == 'a' && t[3] == '\0')
	                              return GETDNS_RRTYPE_SOA;
	                    return -1;
	          case 'P':
	          case 'p': /* before "SP", final "F" (GETDNS_RRTYPE_SPF) */
	                    if ((t[2]|0x20) == 'f' && t[3] == '\0')
	                              return GETDNS_RRTYPE_SPF;
	                    return -1;
	          case 'R':
	          case 'r': /* before "SR", final "V" (GETDNS_RRTYPE_SRV) */
	                    if ((t[2]|0x20) == 'v' && t[3] == '\0')
	                              return GETDNS_RRTYPE_SRV;
	                    return -1;
	          case 'S':
	          case 's': /* before "SS", final "HFP" (GETDNS_RRTYPE_SSHFP) */
	                    if ((t[2]|0x20) == 'h' && (t[3]|0x20) == 'f' && (t[4]|0x20) == 'p' && t[5] == '\0')
	                              return GETDNS_RRTYPE_SSHFP;
	                    return -1;
	          default : return -1;
	          };
	case 'T':
	case 't': switch (t[1]) {
	          case 'A':
	          case 'a': /* before "TA", final "LINK" (GETDNS_RRTYPE_TALINK) */
	                    if ((t[2]|0x20) == 'l' && (t[3]|0x20) == 'i' && (t[4]|0x20) == 'n' && (t[5]|0x20) == 'k' && t[6] == '\0')
	                              return GETDNS_RRTYPE_TALINK;
	                    return -1;
	          case 'K':
	          case 'k': /* before "TK", final "EY" (GETDNS_RRTYPE_TKEY) */
	                    if ((t[2]|0x20) == 'e' && (t[3]|0x20) == 'y' && t[4] == '\0')
	                              return GETDNS_RRTYPE_TKEY;
	                    return -1;
	          case 'L':
	          case 'l': /* before "TL", final "SA" (GETDNS_RRTYPE_TLSA) */
	                    if ((t[2]|0x20) == 's' && (t[3]|0x20) == 'a' && t[4] == '\0')
	                              return GETDNS_RRTYPE_TLSA;
	                    return -1;
	          case 'S':
	          case 's': /* before "TS", final "IG" (GETDNS_RRTYPE_TSIG) */
	                    if ((t[2]|0x20) == 'i' && (t[3]|0x20) == 'g' && t[4] == '\0')
	                              return GETDNS_RRTYPE_TSIG;
	                    return -1;
	          case 'X':
	          case 'x': /* before "TX", final "T" (GETDNS_RRTYPE_TXT) */
	                    if ((t[2]|0x20) == 't' && t[3] == '\0')
	                              return GETDNS_RRTYPE_TXT;
	                    return -1;
	          default : return -1;
	          };
	case 'U':
	case 'u': switch (t[1]) {
	          case 'I':
	          case 'i': switch (t[2]) {
	                    case 'D':
	                    case 'd': return GETDNS_RRTYPE_UID;
	                    case 'N':
	                    case 'n': /* before "UIN", final "FO" (GETDNS_RRTYPE_UINFO) */
	                              if ((t[3]|0x20) == 'f' && (t[4]|0x20) == 'o' && t[5] == '\0')
	                                        return GETDNS_RRTYPE_UINFO;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'N':
	          case 'n': /* before "UN", final "SPEC" (GETDNS_RRTYPE_UNSPEC) */
	                    if ((t[2]|0x20) == 's' && (t[3]|0x20) == 'p' && (t[4]|0x20) == 'e' && (t[5]|0x20) == 'c' && t[6] == '\0')
	                              return GETDNS_RRTYPE_UNSPEC;
	                    return -1;
	          case 'R':
	          case 'r': /* before "UR", final "I" (GETDNS_RRTYPE_URI) */
	                    if ((t[2]|0x20) == 'i' && t[3] == '\0')
	                              return GETDNS_RRTYPE_URI;
	                    return -1;
	          default : return -1;
	          };
	case 'W':
	case 'w': /* before "W", final "KS" (GETDNS_RRTYPE_WKS) */
	          if ((t[1]|0x20) == 'k' && (t[2]|0x20) == 's' && t[3] == '\0')
	                    return GETDNS_RRTYPE_WKS;
	          return -1;
	case 'X':
	case 'x': /* before "X", final "25" (GETDNS_RRTYPE_X25) */
	          if (t[1] == '2' && t[2] == '5' && t[3] == '\0')
	                    return GETDNS_RRTYPE_X25;
	          return -1;
	default : return -1;
	};
}

int my_get_rrtype(const char *t)
{
	int r = get_rrtype(t);
	char *endptr;

	if (r >= 0)
		return r;
	if (strncasecmp(t, "type", 4) == 0 && t[4] != '\0') {
		r = (int) strtol(t+4, &endptr, 10);
		if (*endptr != '\0')
			r = -1;
	}
	return r;
}

