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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

static int quiet = 0;
static int batch_mode = 0;
static char *query_file = NULL;
static int json = 0;
static char *the_root = ".";
static char *name;
static getdns_context *context;
static getdns_dict *extensions;
static uint16_t request_type = GETDNS_RRTYPE_NS;
static int timeout, edns0_size;
static int async = 0, interactive = 0;
static enum { GENERAL, ADDRESS, HOSTNAME, SERVICE } calltype = GENERAL;

int get_rrtype(const char *t);

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
		if (inet_pton(AF_INET6, ipstr, buf) <= 0) {
			getdns_dict_destroy(r);
			return NULL;
		}
	} else {
		getdns_dict_util_set_string(r, "address_type", "IPv4");
		addr.size = 4;
		if (inet_pton(AF_INET, ipstr, buf) <= 0) {
			getdns_dict_destroy(r);
			return NULL;
		}
	}
	getdns_dict_set_bindata(r, "address_data", &addr);
	if (*portstr)
		getdns_dict_set_int(r, "port", (int32_t)atoi(portstr));
	if (*scope_id_str)
		getdns_dict_util_set_string(r, "scope_id", scope_id_str);

	return r;
}

void
print_usage(FILE *out, const char *progname)
{
	fprintf(out, "usage: %s [@<server>] [+extension] [<name>] [<type>]\n",
	    progname);
	fprintf(out, "options:\n");
	fprintf(out, "\t-a\tPerform asynchronous resolution "
	    "(default = synchronous)\n");
	fprintf(out, "\t-A\taddress lookup (<type> is ignored)\n");
	fprintf(out, "\t-b <bufsize>\tSet edns0 max_udp_payload size\n");
	fprintf(out, "\t-D\tSet edns0 do bit\n");
	fprintf(out, "\t-d\tclear edns0 do bit\n");
	fprintf(out, "\t-F <filename>\tread the queries from the specified file\n");
	fprintf(out, "\t-G\tgeneral lookup\n");
	fprintf(out, "\t-H\thostname lookup. (<name> must be an IP address; <type> is ignored)\n");
	fprintf(out, "\t-h\tPrint this help\n");
	fprintf(out, "\t-i\tPrint api information\n");
	fprintf(out, "\t-I\tInteractive mode (> 1 queries on same context)\n");
	fprintf(out, "\t-j\tOutput json response dict\n");
	fprintf(out, "\t-J\tPretty print json response dict\n");
	fprintf(out, "\t-p\tPretty print response dict\n");
	fprintf(out, "\t-r\tSet recursing resolution type\n");
	fprintf(out, "\t-s\tSet stub resolution type (default = recursing)\n");
	fprintf(out, "\t-S\tservice lookup (<type> is ignored)\n");
	fprintf(out, "\t-t <timeout>\tSet timeout in miliseconds\n");
	fprintf(out, "\t-T\tSet transport to TCP only\n");
	fprintf(out, "\t-O\tSet transport to TCP only keep connections open\n");
	fprintf(out, "\t-L\tSet transport to TLS only keep connections open\n");
	fprintf(out, "\t-E\tSet transport to TLS with TCP fallback only keep connections open\n");
	fprintf(out, "\t-R\tSet transport to STARTTLS with TCP fallback only keep connections open\n");
	fprintf(out, "\t-u\tSet transport to UDP with TCP fallback\n");
	fprintf(out, "\t-U\tSet transport to UDP only\n");
	fprintf(out, "\t-B\tBatch mode. Schedule all messages before processing responses.\n");
	fprintf(out, "\t-q\tQuiet mode - don't print response\n");
}

void callback(getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *response, void *userarg, getdns_transaction_t trans_id)
{
	char *response_str;

	if (callback_type == GETDNS_CALLBACK_COMPLETE) {
		/* This is a callback with data */;
		if (!quiet && (response_str = json ?
		    getdns_print_json_dict(response, json == 1)
		  : getdns_pretty_print_dict(response))) {

			fprintf(stdout, "ASYNC response:\n%s\n", response_str);
			free(response_str);
		}
		fprintf(stderr,
			"The callback with ID %llu  was successfull.\n",
			(unsigned long long)trans_id);

	} else if (callback_type == GETDNS_CALLBACK_CANCEL)
		fprintf(stderr,
			"The callback with ID %llu was cancelled. Exiting.\n",
			(unsigned long long)trans_id);
	else
		fprintf(stderr,
			"The callback got a callback_type of %d. Exiting.\n",
			callback_type);

	getdns_dict_destroy(response);
	response = NULL;
}

#define CONTINUE ((getdns_return_t)-2)

static getdns_return_t set_cookie(getdns_dict *exts, char *cookie)
{
	uint8_t data[40];
	size_t i;
	getdns_return_t r = GETDNS_RETURN_GENERIC_ERROR;
	getdns_bindata bindata;

	getdns_dict *opt_parameters = getdns_dict_create();
	getdns_list *options = getdns_list_create();
	getdns_dict *option = getdns_dict_create();

	if (*cookie == '=')
		cookie++;

	for (i = 0; i < 40 && *cookie; i++) {
		if (*cookie >= '0' && *cookie <= '9')
			data[i] = (uint8_t)(*cookie - '0') << 4;
		else if (*cookie >= 'a' && *cookie <= 'f')
			data[i] = (uint8_t)(*cookie - 'a' + 10) << 4;
		else if (*cookie >= 'A' && *cookie <= 'F')
			data[i] = (uint8_t)(*cookie - 'A' + 10) << 4;
		else
			goto done;
		cookie++;
		if (*cookie >= '0' && *cookie <= '9')
			data[i] |= (uint8_t)(*cookie - '0');
		else if (*cookie >= 'a' && *cookie <= 'f')
			data[i] |= (uint8_t)(*cookie - 'a' + 10);
		else if (*cookie >= 'A' && *cookie <= 'F')
			data[i] |= (uint8_t)(*cookie - 'A' + 10);
		else
			goto done;
		cookie++;;
	}
	bindata.data = data;
	bindata.size = i;
	if ((r = getdns_dict_set_int(option, "option_code", 65001)))
		goto done;
	if ((r = getdns_dict_set_bindata(option, "option_data", &bindata)))
		goto done;
	if ((r = getdns_list_set_dict(options, 0, option)))
		goto done;
	if ((r = getdns_dict_set_list(opt_parameters, "options", options)))
		goto done;
	r = getdns_dict_set_dict(exts, "add_opt_parameters", opt_parameters);
done:
	getdns_dict_destroy(option);
	getdns_list_destroy(options);
	getdns_dict_destroy(opt_parameters);
	return r;
}

getdns_return_t parse_args(int argc, char **argv)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	size_t i;
	char *arg, *c, *endptr;
	int t, print_api_info = 0;
	getdns_list *upstream_list = NULL;
	size_t upstream_count = 0;

	for (i = 1; i < argc; i++) {
		arg = argv[i];
		if ((t = get_rrtype(arg)) >= 0) {
			request_type = t;
			continue;

		} else if (arg[0] == '+') {
			if (arg[1] == 's' && arg[2] == 'i' && arg[3] == 't' &&
			   (arg[4] == '=' || arg[4] == '\0')) {
				if ((r = set_cookie(extensions, arg+4))) {
					fprintf(stderr, "Could not set cookie:"
					    " %d", r);
					break;
				}
			} else if ((r = getdns_dict_set_int(extensions, arg+1,
			    GETDNS_EXTENSION_TRUE))) {
				fprintf(stderr, "Could not set extension "
				    "\"%s\": %d\n", argv[i], r);
				break;
			}
			continue;

		} else if (arg[0] == '@') {
			getdns_dict *upstream = ipaddr_dict(context, arg + 1);
			if (upstream) {
				if (!upstream_list &&
				    !(upstream_list =
				    getdns_list_create_with_context(context))){
					fprintf(stderr, "Could not create upstream list\n");
					return GETDNS_RETURN_MEMORY_ERROR;
				}
				getdns_list_set_dict(upstream_list,
				    upstream_count++, upstream);
			}
			continue;
		} else if (arg[0] != '-') {
			name = arg;
			continue;
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
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				edns0_size = strtol(argv[i], &endptr, 10);
				if (*endptr || edns0_size < 0) {
					fprintf(stderr, "positive "
					    "numeric max_udp_payload_size "
					    "expected after -b\n");
					return GETDNS_RETURN_GENERIC_ERROR;
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
			case 'F':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "file name expected "
					    "after -F\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				query_file = argv[i];
				interactive = 1;
				break;
			case 'G':
				calltype = GENERAL;
				break;
			case 'H':
				calltype = HOSTNAME;
				break;
			case 'h':
				print_usage(stdout, argv[0]);
				return CONTINUE;
			case 'i':
				print_api_info = 1;
				break;
			case 'I':
				interactive = 1;
				break;
			case 'j':
				json = 2;
				break;
			case 'J':
				json = 1;
				break;
			case 'p':
				json = 0;
			case 'q':
				quiet = 1;
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
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				timeout = strtol(argv[i], &endptr, 10);
				if (*endptr || timeout < 0) {
					fprintf(stderr, "positive "
					    "numeric ttl expected "
					    "after -t\n");
					return GETDNS_RETURN_GENERIC_ERROR;
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
			case 'L':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_TLS_ONLY_KEEP_CONNECTIONS_OPEN);
				break;
			case 'E':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_TLS_FIRST_AND_FALL_BACK_TO_TCP_KEEP_CONNECTIONS_OPEN);
				break;
			case 'R':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_STARTTLS_FIRST_AND_FALL_BACK_TO_TCP_KEEP_CONNECTIONS_OPEN);
				break;
			case 'u':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP);
				break;
			case 'U':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_UDP_ONLY);
				break;
			case 'B':
				batch_mode = 1;
			break;


			default:
				fprintf(stderr, "Unknown option "
				    "\"%c\"\n", *c);
				for (i = 0; i < argc; i++)
					fprintf(stderr, "%d: \"%s\"\n", (int)i, argv[i]);
				return GETDNS_RETURN_GENERIC_ERROR;
			}
		}
next:		;
	}
	if (r)
		return r;
	if (upstream_count &&
	    (r = getdns_context_set_upstream_recursive_servers(
	    context, upstream_list))) {
		fprintf(stderr, "Error setting upstream recursive servers\n");
	}
	if (print_api_info) {
		fprintf(stdout, "%s\n", getdns_pretty_print_dict(
		    getdns_context_get_api_information(context)));
		return CONTINUE;
	}
	return r;
}

int
main(int argc, char **argv)
{
	getdns_dict *response = NULL;
	char *response_str;
	getdns_return_t r;
	getdns_dict *address = NULL;
	FILE *fp = NULL;

	name = the_root;
	if ((r = getdns_context_create(&context, 1))) {
		fprintf(stderr, "Create context failed: %d\n", r);
		return r;
	}
	extensions = getdns_dict_create();
	if (! extensions) {
		fprintf(stderr, "Could not create extensions dict\n");
		r = GETDNS_RETURN_MEMORY_ERROR;
		goto done_destroy_context;
	}
	if ((r = parse_args(argc, argv)))
		goto done_destroy_context;

	if (query_file) {
		fp = fopen(query_file, "rt");
		if (fp == NULL) {
			fprintf(stderr, "Could not open query file: %s\n", query_file);
			goto done_destroy_context;
		}
	}

	/* Make the call */
	do {
		char line[1024], *token, *linev[256];
		int linec;
		if (interactive) {
			if (!query_file) {
				fprintf(stdout, "> ");
				if (!fgets(line, 1024, stdin) || !*line)
					break;
			} else {
				if (!fgets(line, 1024, fp) || !*line)
					break;
				fprintf(stdout,"Found query: %s", line);
			}

			linev[0] = argv[0];
			linec = 1;
			if ( ! (token = strtok(line, " \t\f\n\r")))
				continue;
			do linev[linec++] = token;
			while (linec < 256 &&
			    (token = strtok(NULL, " \t\f\n\r")));
			if ((r = parse_args(linec, linev))) {
				if (r == CONTINUE)
					continue;
				else
					goto done_destroy_context;
			}

		}
		if (calltype == HOSTNAME &&
		    !(address = ipaddr_dict(context, name))) {
			fprintf(stderr, "Could not convert \"%s\" "
			                "to an IP address", name);
			continue;
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
			case HOSTNAME:
				r = getdns_hostname(context, address,
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
			if (!batch_mode) 
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
			case HOSTNAME:
				r = getdns_hostname_sync(context, address,
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
			if (!quiet) {
				if ((response_str = json ?
				    getdns_print_json_dict(response, json == 1)
				  : getdns_pretty_print_dict(response))) {

					fprintf( stdout, "SYNC response:\n%s\n"
					       , response_str);
					free(response_str);
				} else {
					r = GETDNS_RETURN_MEMORY_ERROR;
					fprintf( stderr
					       , "Could not print response\n");
				}
			} else if (r == GETDNS_RETURN_GOOD)
				fprintf(stdout, "Response code was: GOOD\n");
			else if (interactive)
				fprintf(stderr, "An error occurred: %d\n", r);
		}
	} while (interactive);

	if (batch_mode) 
		getdns_context_run(context);

	/* Clean up */
done_destroy_extensions:
	getdns_dict_destroy(extensions);
done_destroy_context:
	if (response) getdns_dict_destroy(response);
	getdns_context_destroy(context);

	if (fp)
		fclose(fp);

	if (r == CONTINUE)
		return 0;
	if (r)
		fprintf(stderr, "An error occurred: %d\n", r);
	return r;
}

int get_rrtype(const char *t) {
	char *endptr;
	int r;

	switch (t[0]) {
	case 'A':
	case 'a': switch (t[1]) {
	          case '\0': return GETDNS_RRTYPE_A;
	          case '6': if (t[2] == '\0') return GETDNS_RRTYPE_A6;
                            return -1;
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
	                    case 's': if (t[3] == '\0') return GETDNS_RRTYPE_CDS;
	                              return -1;
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
	          case 's': if (t[2] == '\0') return GETDNS_RRTYPE_DS;
	                    return -1;
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
	          case 'p': if (t[3] == '\0') return GETDNS_RRTYPE_HIP;
	                    return -1;
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
	          case 'x': if (t[2] == '\0') return GETDNS_RRTYPE_KX;
	                    return -1;
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
	          case 'p': if (t[2] == '\0') return GETDNS_RRTYPE_LP;
	                    return -1;
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
	                    case 'a': if (t[5] == '\0') return GETDNS_RRTYPE_MAILA;
	                              return -1;
	                    case 'B':
	                    case 'b': if (t[5] == '\0') return GETDNS_RRTYPE_MAILB;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'B':
	          case 'b': if (t[2] == '\0') return GETDNS_RRTYPE_MB;
                            return -1;
	          case 'D':
	          case 'd': if (t[2] == '\0') return GETDNS_RRTYPE_MD;
                            return -1;
	          case 'F':
	          case 'f': if (t[2] == '\0') return GETDNS_RRTYPE_MF;
                            return -1;
	          case 'G':
	          case 'g': if (t[2] == '\0') return GETDNS_RRTYPE_MG;
                            return -1;
	          case 'I':
	          case 'i': /* before "MI", final "NFO" (GETDNS_RRTYPE_MINFO) */
	                    if ((t[2]|0x20) == 'n' && (t[3]|0x20) == 'f' && (t[4]|0x20) == 'o' && t[5] == '\0')
	                              return GETDNS_RRTYPE_MINFO;
	                    return -1;
	          case 'R':
	          case 'r': if (t[2] == '\0') return GETDNS_RRTYPE_MR;
	                    return -1;
	          case 'X':
	          case 'x': if (t[2] == '\0') return GETDNS_RRTYPE_MX;
	                    return -1;
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
	                    case 'd': if (t[3] == '\0') return GETDNS_RRTYPE_NID;
	                              return -1;
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
	          case 't': if (t[3] == '\0') return GETDNS_RRTYPE_OPT;
	                    return -1;
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
	          case 'x': if (t[2] == '\0') return GETDNS_RRTYPE_PX;
	                    return -1;
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
	          case 'p': if (t[2] == '\0') return GETDNS_RRTYPE_RP;
	                    return -1;
	          case 'R':
	          case 'r': /* before "RR", final "SIG" (GETDNS_RRTYPE_RRSIG) */
	                    if ((t[2]|0x20) == 's' && (t[3]|0x20) == 'i' && (t[4]|0x20) == 'g' && t[5] == '\0')
	                              return GETDNS_RRTYPE_RRSIG;
	                    return -1;
	          case 'T':
	          case 't': if (t[2] == '\0') return GETDNS_RRTYPE_RT;
	                    return -1;
	          default : return -1;
	          };
	case 'S':
	case 's': switch (t[1]) {
	          case 'I':
	          case 'i': switch (t[2]) {
	                    case 'G':
	                    case 'g': if (t[3] == '\0') return GETDNS_RRTYPE_SIG;
	                              return -1;
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
	          case 'Y':
		  case 'y': /* before "TY", then "PE" followed by a number */
	                    if ((t[2]|0x20) == 'p' && (t[3]|0x20) == 'e' && t[4] != '\0') {
	                            r = (int) strtol(t + 4, &endptr, 10);
	                            if (*endptr == '\0') return r;
	                    }
	                    return -1;
	          default : return -1;
	          };
	case 'U':
	case 'u': switch (t[1]) {
	          case 'I':
	          case 'i': switch (t[2]) {
	                    case 'D':
	                    case 'd': if (t[3] == '\0') return GETDNS_RRTYPE_UID;
	                              return -1;
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

