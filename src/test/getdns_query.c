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
#include "debug.h"
#include "getdns_str2dict.h"
#include "getdns_context_config.h"
#include "getdns_context_set_listen_addresses.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#ifndef USE_WINSOCK
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#else
#include <winsock2.h>
#include <iphlpapi.h>
typedef unsigned short in_port_t;
#include <windows.h>
#include <wincrypt.h>
#endif

#define EXAMPLE_PIN "pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\""

static int quiet = 0;
static int batch_mode = 0;
static char *query_file = NULL;
static int json = 0;
static char *the_root = ".";
static char *name;
static getdns_context *context;
static getdns_dict *extensions;
static getdns_dict *query_extensions_spc = NULL;
static getdns_list *pubkey_pinset = NULL;
static getdns_list *listen_list = NULL;
static getdns_dict *listen_dict = NULL;
static size_t pincount = 0;
static size_t listen_count = 0;
static uint16_t request_type = GETDNS_RRTYPE_NS;
static int timeout, edns0_size, padding_blocksize;
static int async = 0, interactive = 0;
static enum { GENERAL, ADDRESS, HOSTNAME, SERVICE } calltype = GENERAL;

int get_rrtype(const char *t);

static getdns_return_t
fill_transport_list(getdns_context *context, char *transport_list_str, 
                    getdns_transport_list_t *transports, size_t *transport_count)
{
	size_t max_transports = *transport_count;
	*transport_count = 0;
	for ( size_t i = 0
	    ; i < max_transports && i < strlen(transport_list_str)
	    ; i++, (*transport_count)++) {
		switch(*(transport_list_str + i)) {
			case 'U': 
				transports[i] = GETDNS_TRANSPORT_UDP;
				break;
			case 'T': 
				transports[i] = GETDNS_TRANSPORT_TCP;
				break;
			case 'L': 
				transports[i] = GETDNS_TRANSPORT_TLS;
				break;
			default:
				fprintf(stderr, "Unrecognised transport '%c' in string %s\n", 
				       *(transport_list_str + i), transport_list_str);
				return GETDNS_RETURN_GENERIC_ERROR;
		}
	}
	return GETDNS_RETURN_GOOD;
}

void
print_usage(FILE *out, const char *progname)
{
	fprintf(out, "usage: %s [<option> ...] \\\n"
	    "\t[@<upstream> ...] [+<extension> ...] [\'{ <settings> }\'] [<name>] [<type>]\n", progname);
	fprintf(out, "\ndefault mode: "
#ifdef HAVE_LIBUNBOUND
	    "recursive"
#else
	    "stub"
#endif
	    ", synchronous resolution of NS record\n\t\tusing UDP with TCP fallback\n");
	fprintf(out, "\nupstreams: @<ip>[%%<scope_id>][@<port>][#<tls port>][~<tls name>][^<tsig spec>]");
	fprintf(out, "\n            <ip>@<port> may be given as <IPv4>:<port>");
	fprintf(out, "\n                  or \'[\'<IPv6>[%%<scope_id>]\']\':<port> too\n");
	fprintf(out, "\ntsig spec: [<algorithm>:]<name>:<secret in Base64>\n");
	fprintf(out, "\nextensions:\n");
	fprintf(out, "\t+add_warning_for_bad_dns\n");
	fprintf(out, "\t+dnssec_return_status\n");
	fprintf(out, "\t+dnssec_return_only_secure\n");
	fprintf(out, "\t+dnssec_return_all_statuses\n");
	fprintf(out, "\t+dnssec_return_validation_chain\n");
	fprintf(out, "\t+dnssec_return_full_validation_chain\n");
#ifdef DNSSEC_ROADBLOCK_AVOIDANCE
	fprintf(out, "\t+dnssec_roadblock_avoidance\n");
#endif
#ifdef EDNS_COOKIES
	fprintf(out, "\t+edns_cookies\n");
#endif
	fprintf(out, "\t+return_both_v4_and_v6\n");
	fprintf(out, "\t+return_call_reporting\n");
	fprintf(out, "\t+sit=<cookie>\t\tSend along cookie OPT with value <cookie>\n");
	fprintf(out, "\t+specify_class=<class>\n");
	fprintf(out, "\t+0\t\t\tClear all extensions\n");
	fprintf(out, "\nsettings in json dict format (like outputted by -i option).\n");
	fprintf(out, "\noptions:\n");
	fprintf(out, "\t-a\tPerform asynchronous resolution "
	    "(default = synchronous)\n");
	fprintf(out, "\t-A\taddress lookup (<type> is ignored)\n");
	fprintf(out, "\t-B\tBatch mode. Schedule all messages before processing responses.\n");
	fprintf(out, "\t-b <bufsize>\tSet edns0 max_udp_payload size\n");
	fprintf(out, "\t-c\tSend Client Subnet privacy request\n");
	fprintf(out, "\t-C\t<filename>\n");
	fprintf(out, "\t\tRead settings from config file <filename>\n");
	fprintf(out, "\t\tThe getdns context will be configured with these settings\n");
	fprintf(out, "\t\tThe file must be in json dict format.\n");
	fprintf(out, "\t-D\tSet edns0 do bit\n");
	fprintf(out, "\t-d\tclear edns0 do bit\n");
	fprintf(out, "\t-e <idle_timeout>\tSet idle timeout in miliseconds\n");
	fprintf(out, "\t-F <filename>\tread the queries from the specified file\n");
	fprintf(out, "\t-f <filename>\tRead DNSSEC trust anchors from <filename>\n");
	fprintf(out, "\t-G\tgeneral lookup\n");
	fprintf(out, "\t-H\thostname lookup. (<name> must be an IP address; <type> is ignored)\n");
	fprintf(out, "\t-h\tPrint this help\n");
	fprintf(out, "\t-i\tPrint api information\n");
	fprintf(out, "\t-I\tInteractive mode (> 1 queries on same context)\n");
	fprintf(out, "\t-j\tOutput json response dict\n");
	fprintf(out, "\t-J\tPretty print json response dict\n");
	fprintf(out, "\t-k\tPrint root trust anchors\n");
	fprintf(out, "\t-K <pin>\tPin a public key for TLS connections (can repeat)\n");
	fprintf(out, "\t\t(should look like '" EXAMPLE_PIN "')\n");
	fprintf(out, "\t-n\tSet TLS authentication mode to NONE (default)\n");
	fprintf(out, "\t-m\tSet TLS authentication mode to REQUIRED\n");
	fprintf(out, "\t-p\tPretty print response dict\n");
	fprintf(out, "\t-P <blocksize>\tPad TLS queries to a multiple of blocksize\n");
	fprintf(out, "\t-q\tQuiet mode - don't print response\n");
	fprintf(out, "\t-r\tSet recursing resolution type\n");
	fprintf(out, "\t-R <filename>\tRead root hints from <filename>\n");
	fprintf(out, "\t-s\tSet stub resolution type (default = recursing)\n");
	fprintf(out, "\t-S\tservice lookup (<type> is ignored)\n");
	fprintf(out, "\t-t <timeout>\tSet timeout in miliseconds\n");
	fprintf(out, "\t-x\tDo not follow redirects\n");
	fprintf(out, "\t-X\tFollow redirects (default)\n");

	fprintf(out, "\t-0\tAppend suffix to single label first (default)\n");
	fprintf(out, "\t-W\tAppend suffix always\n");
	fprintf(out, "\t-1\tAppend suffix only to single label after failure\n");
	fprintf(out, "\t-M\tAppend suffix only to multi label name after failure\n");
	fprintf(out, "\t-N\tNever append a suffix\n");
	fprintf(out, "\t-Z <suffixes>\tSet suffixes with the given comma separed list\n");

	fprintf(out, "\t-T\tSet transport to TCP only\n");
	fprintf(out, "\t-O\tSet transport to TCP only keep connections open\n");
	fprintf(out, "\t-L\tSet transport to TLS only keep connections open\n");
	fprintf(out, "\t-E\tSet transport to TLS with TCP fallback only keep connections open\n");
	fprintf(out, "\t-u\tSet transport to UDP with TCP fallback (default)\n");
	fprintf(out, "\t-U\tSet transport to UDP only\n");
	fprintf(out, "\t-l <transports>\tSet transport list. List can contain 1 of each of the characters\n");
	fprintf(out, "\t\t\t U T L S for UDP, TCP or TLS e.g 'UT' or 'LTU' \n");
	fprintf(out, "\t-z <listen address>\n");
	fprintf(out, "\t\tListen for DNS requests on the given IP address\n");
	fprintf(out, "\t\t<listen address> is in the same format as upstreams.\n");
	fprintf(out, "\t\tThis option can be given more than once.\n");
}

static getdns_return_t validate_chain(getdns_dict *response)
{
	getdns_return_t r;
	getdns_list *validation_chain;
	getdns_list *replies_tree;
	getdns_dict *reply;
	getdns_list *to_validate;
	getdns_list *trust_anchor;
	size_t i;
	int s;
	
	if (!(to_validate = getdns_list_create()))
		return GETDNS_RETURN_MEMORY_ERROR;

	if (getdns_context_get_dnssec_trust_anchors(context, &trust_anchor))
		trust_anchor = getdns_root_trust_anchor(NULL);

	if ((r = getdns_dict_get_list(
	    response, "validation_chain", &validation_chain)))
		goto error;

	if ((r = getdns_dict_get_list(
	    response, "replies_tree", &replies_tree)))
		goto error;

	fprintf(stdout, "replies_tree dnssec_status: ");
	switch ((s = getdns_validate_dnssec(
	    replies_tree, validation_chain, trust_anchor))) {

	case GETDNS_DNSSEC_SECURE:
		fprintf(stdout, "GETDNS_DNSSEC_SECURE\n");
		break;
	case GETDNS_DNSSEC_BOGUS:
		fprintf(stdout, "GETDNS_DNSSEC_BOGUS\n");
		break;
	case GETDNS_DNSSEC_INDETERMINATE:
		fprintf(stdout, "GETDNS_DNSSEC_INDETERMINATE\n");
		break;
	case GETDNS_DNSSEC_INSECURE:
		fprintf(stdout, "GETDNS_DNSSEC_INSECURE\n");
		break;
	case GETDNS_DNSSEC_NOT_PERFORMED:
		fprintf(stdout, "GETDNS_DNSSEC_NOT_PERFORMED\n");
		break;
	default:
		fprintf(stdout, "%d\n", (int)s);
	}

	i = 0;
	while (!(r = getdns_list_get_dict(replies_tree, i++, &reply))) {

		if ((r = getdns_list_set_dict(to_validate, 0, reply)))
			goto error;

		printf("reply "PRIsz", dnssec_status: ", i);
		switch ((s = getdns_validate_dnssec(
		    to_validate, validation_chain, trust_anchor))) {

		case GETDNS_DNSSEC_SECURE:
			fprintf(stdout, "GETDNS_DNSSEC_SECURE\n");
			break;
		case GETDNS_DNSSEC_BOGUS:
			fprintf(stdout, "GETDNS_DNSSEC_BOGUS\n");
			break;
		case GETDNS_DNSSEC_INDETERMINATE:
			fprintf(stdout, "GETDNS_DNSSEC_INDETERMINATE\n");
			break;
		case GETDNS_DNSSEC_INSECURE:
			fprintf(stdout, "GETDNS_DNSSEC_INSECURE\n");
			break;
		case GETDNS_DNSSEC_NOT_PERFORMED:
			fprintf(stdout, "GETDNS_DNSSEC_NOT_PERFORMED\n");
			break;
		default:
			fprintf(stdout, "%d\n", (int)s);
		}
	}
	if (r == GETDNS_RETURN_NO_SUCH_LIST_ITEM)
		r = GETDNS_RETURN_GOOD;
error:
	getdns_list_destroy(trust_anchor);
	getdns_list_destroy(to_validate);

	return r;
}

void callback(getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *response, void *userarg, getdns_transaction_t trans_id)
{
	char *response_str;

	/* This is a callback with data */;
	if (response && !quiet && (response_str = json ?
	    getdns_print_json_dict(response, json == 1)
	  : getdns_pretty_print_dict(response))) {

		fprintf(stdout, "ASYNC response:\n%s\n", response_str);
		validate_chain(response);
		free(response_str);
	}

	if (callback_type == GETDNS_CALLBACK_COMPLETE) {
		printf("Response code was: GOOD. Status was: Callback with ID %"PRIu64"  was successfull.\n",
			trans_id);

	} else if (callback_type == GETDNS_CALLBACK_CANCEL)
		fprintf(stderr,
			"An error occurred: The callback with ID %"PRIu64" was cancelled. Exiting.\n",
			trans_id);
	else {
		fprintf(stderr,
			"An error occurred: The callback got a callback_type of %d. Exiting.\n",
			(int)callback_type);
		fprintf(stderr,
			"Error :      '%s'\n",
			getdns_get_errorstr_by_id(callback_type));
	}
	getdns_dict_destroy(response);
	response = NULL;
}

#define CONTINUE ((getdns_return_t)-2)
#define CONTINUE_ERROR ((getdns_return_t)-3)

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
	if ((r = getdns_dict_set_int(option, "option_code", 10)))
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

static void parse_config(const char *config_str)
{
	getdns_dict *config_dict;
	getdns_list *list;
	getdns_return_t r;

	if ((r = getdns_str2dict(config_str, &config_dict)))
		fprintf(stderr, "Could not parse config file: %s\n",
		    getdns_get_errorstr_by_id(r));

	else {
		if (!(r = getdns_dict_get_list(
		    config_dict, "listen_addresses", &list))) {
			if (listen_list && !listen_dict) {
				getdns_list_destroy(listen_list);
				listen_list = NULL;
			}
			/* Strange construction to copy the list.
			 * Needs to be done, because config dict
			 * will get destroyed.
			 */
			if (!listen_dict &&
			    !(listen_dict = getdns_dict_create())) {
				fprintf(stderr, "Could not create "
						"listen_dict");
				r = GETDNS_RETURN_MEMORY_ERROR;

			} else if ((r = getdns_dict_set_list(
			    listen_dict, "listen_list", list)))
				fprintf(stderr, "Could not set listen_list");

			else if ((r = getdns_dict_get_list(
			    listen_dict, "listen_list", &listen_list)))
				fprintf(stderr, "Could not get listen_list");

			else if ((r = getdns_list_get_length(
			    listen_list, &listen_count)))
				fprintf(stderr, "Could not get listen_count");

			(void) getdns_dict_remove_name(
			    config_dict, "listen_addresses");
		}
		if ((r = _getdns_context_config_(
		    context, extensions, config_dict))) {
			fprintf(stderr, "Could not configure context with "
			    "config dict: %s\n", getdns_get_errorstr_by_id(r));
		}
		getdns_dict_destroy(config_dict);
	}
}

getdns_return_t parse_args(int argc, char **argv)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	size_t i, j;
	char *arg, *c, *endptr;
	int t, print_api_info = 0, print_trust_anchors = 0;
	getdns_list *upstream_list = NULL;
	getdns_list *tas = NULL, *hints = NULL;
	getdns_dict *pubkey_pin = NULL;
	getdns_list *suffixes;
	char *suffix;
	getdns_bindata bindata;
	size_t upstream_count = 0;
	FILE *fh;
	uint32_t klass;
	char *config_file = NULL;
	long config_file_sz;

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
					    " %d", (int)r);
					break;
				}
			} else if (strncmp(arg+1, "specify_class=", 14) == 0) {
				if (strncasecmp(arg+15, "IN", 3) == 0)
					r = getdns_dict_set_int(extensions,
					    "specify_class", GETDNS_RRCLASS_IN);
				else if (strncasecmp(arg+15, "CH", 3) == 0)
					r = getdns_dict_set_int(extensions,
					    "specify_class", GETDNS_RRCLASS_CH);
				else if (strncasecmp(arg+15, "HS", 3) == 0)
					r = getdns_dict_set_int(extensions,
					    "specify_class", GETDNS_RRCLASS_HS);
				else if (strncasecmp(arg+15, "NONE", 5) == 0)
					r = getdns_dict_set_int(extensions,
					    "specify_class", GETDNS_RRCLASS_NONE);
				else if (strncasecmp(arg+15, "ANY", 4) == 0)
					r = getdns_dict_set_int(extensions,
					    "specify_class", GETDNS_RRCLASS_ANY);
				else if (strncasecmp(arg+15, "CLASS", 5) == 0) {
					klass = strtol(arg + 20, &endptr, 10);
					if (*endptr || klass > 255)
						fprintf(stderr,
						    "Unknown class: %s\n",
						    arg+15);
					else
						r = getdns_dict_set_int(extensions,
						    "specify_class", klass);

				} else
					fprintf(stderr,
					    "Unknown class: %s\n", arg+15);
			} else if (arg[1] == '0') {
			    /* Unset all existing extensions*/
				getdns_dict_destroy(extensions);
				extensions = getdns_dict_create();
				break;
			} else if ((r = getdns_dict_set_int(extensions, arg+1,
			    GETDNS_EXTENSION_TRUE))) {
				fprintf(stderr, "Could not set extension "
				    "\"%s\": %d\n", argv[i], (int)r);
				break;
			}
			continue;

		} else if (arg[0] == '@') {
			getdns_dict *upstream = _getdns_ipaddr_dict(arg + 1);
			if (upstream) {
				if (!upstream_list &&
				    !(upstream_list =
				    getdns_list_create_with_context(context))){
					fprintf(stderr, "Could not create upstream list\n");
					return GETDNS_RETURN_MEMORY_ERROR;
				}
				(void) getdns_list_set_dict(upstream_list,
				    upstream_count++, upstream);
				getdns_dict_destroy(upstream);
			}
			continue;
		} else if (arg[0] == '{') {
			parse_config(arg);
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
			case 'c':
				if (getdns_context_set_edns_client_subnet_private(context, 1))
					return GETDNS_RETURN_GENERIC_ERROR;
				break;
			case 'C':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "file name expected "
					    "after -C\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (!(fh = fopen(argv[i], "r"))) {
					fprintf(stderr, "Could not open \"%s\""
					    ": %s\n",argv[i], strerror(errno));
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (fseek(fh, 0,SEEK_END) == -1) {
					perror("fseek");
					fclose(fh);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				config_file_sz = ftell(fh);
				if (config_file_sz <= 0) {
					/* Empty config is no config */
					fclose(fh);
					break;
				}
				if (!(config_file=malloc(config_file_sz + 1))){
					fclose(fh);
					fprintf(stderr, "Could not allocate me"
					    "mory for \"%s\"\n", argv[i]);
					return GETDNS_RETURN_MEMORY_ERROR;
				}
				rewind(fh);
				if (fread(config_file, 1, config_file_sz, fh)
				    != config_file_sz) {
					fprintf(stderr, "An error occurred whil"
					    "e reading \"%s\": %s\n",argv[i],
					    strerror(errno));
					fclose(fh);
					return GETDNS_RETURN_MEMORY_ERROR;
				}
				config_file[config_file_sz] = 0;
				fclose(fh);
				parse_config(config_file);
				free(config_file);
				config_file = NULL;
				break;
			case 'D':
				(void) getdns_context_set_edns_do_bit(context, 1);
				break;
			case 'd':
				(void) getdns_context_set_edns_do_bit(context, 0);
				break;
			case 'f':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "file name expected "
					    "after -f\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (!(fh = fopen(argv[i], "r"))) {
					fprintf(stderr, "Could not open \"%s\""
					    ": %s\n",argv[i], strerror(errno));
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (getdns_fp2rr_list(fh, &tas, NULL, 3600)) {
					fprintf(stderr,"Could not parse "
					    "\"%s\"\n", argv[i]);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				fclose(fh);
				if (getdns_context_set_dnssec_trust_anchors(
				    context, tas)) {
					fprintf(stderr,"Could not set "
					    "trust anchors from \"%s\"\n",
					    argv[i]);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_list_destroy(tas);
				tas = NULL;
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
			case 'K':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "pin string of the form "
						EXAMPLE_PIN
						"expected after -K\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				pubkey_pin = getdns_pubkey_pin_create_from_string(context,
										 argv[i]);
				if (pubkey_pin == NULL) {
					fprintf(stderr, "could not convert '%s' into a "
						"public key pin.\n"
						"Good pins look like: " EXAMPLE_PIN "\n"
						"Please see RFC 7469 for details about "
						"the format\n", argv[i]);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (pubkey_pinset == NULL)
					pubkey_pinset = getdns_list_create_with_context(context);
				if (r = getdns_list_set_dict(pubkey_pinset, pincount++,
							     pubkey_pin), r) {
					fprintf(stderr, "Failed to add pin to pinset (error %d: %s)\n",
						(int)r, getdns_get_errorstr_by_id(r));
					getdns_dict_destroy(pubkey_pin);
					pubkey_pin = NULL;
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_dict_destroy(pubkey_pin);
				pubkey_pin = NULL;
				break;
			case 'k':
				print_trust_anchors = 1;
				break;
			case 'n':
				getdns_context_set_tls_authentication(context,
				                 GETDNS_AUTHENTICATION_NONE);
				break;
			case 'm':
				getdns_context_set_tls_authentication(context,
				                 GETDNS_AUTHENTICATION_REQUIRED);
				break;
			case 'P':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "tls_query_padding_blocksize "
					    "expected after -P\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				padding_blocksize = strtol(argv[i], &endptr, 10);
				if (*endptr || padding_blocksize < 0) {
					fprintf(stderr, "non-negative "
					    "numeric padding blocksize expected "
					    "after -P\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (getdns_context_set_tls_query_padding_blocksize(
					    context, padding_blocksize))
					return GETDNS_RETURN_GENERIC_ERROR;
				goto next;
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
			case 'R':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "file name expected "
					    "after -f\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (!(fh = fopen(argv[i], "r"))) {
					fprintf(stderr, "Could not open \"%s\""
					    ": %s\n",argv[i], strerror(errno));
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (getdns_fp2rr_list(fh, &hints, NULL, 3600)) {
					fprintf(stderr,"Could not parse "
					    "\"%s\"\n", argv[i]);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				fclose(fh);
				if (getdns_context_set_dns_root_servers(
				    context, hints)) {
					fprintf(stderr,"Could not set "
					    "root servers from \"%s\"\n",
					    argv[i]);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_list_destroy(hints);
				hints = NULL;
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
					fprintf(stderr, "timeout expected "
					    "after -t\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				timeout = strtol(argv[i], &endptr, 10);
				if (*endptr || timeout < 0) {
					fprintf(stderr, "positive "
					    "numeric timeout expected "
					    "after -t\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_context_set_timeout(
					context, timeout);
				goto next;
			case 'x': 
				getdns_context_set_follow_redirects(
				    context, GETDNS_REDIRECTS_DO_NOT_FOLLOW);
				break;
			case 'X': 
				getdns_context_set_follow_redirects(
				    context, GETDNS_REDIRECTS_FOLLOW);
				break;
			case 'e':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "idle timeout expected "
					    "after -t\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				timeout = strtol(argv[i], &endptr, 10);
				if (*endptr || timeout < 0) {
					fprintf(stderr, "positive "
					    "numeric idle timeout expected "
					    "after -t\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_context_set_idle_timeout(
					context, timeout);
				goto next;
			case 'W':
				(void) getdns_context_set_append_name(context,
				    GETDNS_APPEND_NAME_ALWAYS);
				break;
			case '1':
				(void) getdns_context_set_append_name(context,
			GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE);
				break;
			case '0':
				(void) getdns_context_set_append_name(context,
				    GETDNS_APPEND_NAME_TO_SINGLE_LABEL_FIRST);
				break;
			case 'M':
				(void) getdns_context_set_append_name(context,
		GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE);
				break;
			case 'N':
				(void) getdns_context_set_append_name(context,
				    GETDNS_APPEND_NAME_NEVER);
				break;
			case 'Z':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "suffixes expected"
					    "after -Z\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (!(suffixes = getdns_list_create()))
					return GETDNS_RETURN_MEMORY_ERROR;
				suffix = strtok(argv[i], ",");
				j = 0;
				while (suffix) {
					bindata.size = strlen(suffix);
					bindata.data = (void *)suffix;
					(void) getdns_list_set_bindata(
					    suffixes, j++, &bindata);
					suffix = strtok(NULL, ",");
				}
				(void) getdns_context_set_suffix(context,
				    suffixes);
				getdns_list_destroy(suffixes);
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
			case 'u':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP);
				break;
			case 'U':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_UDP_ONLY);
				break;
			case 'l':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "transport list expected "
					    "after -l\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_transport_list_t transports[10];
				size_t transport_count = sizeof(transports);
				if ((r = fill_transport_list(context, argv[i], transports, &transport_count)) ||
				    (r = getdns_context_set_dns_transport_list(context, 
				                                               transport_count, transports))){
						fprintf(stderr, "Could not set transports\n");
						return r;
				}
				break;
			case 'B':
				batch_mode = 1;
				break;

			case 'z':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "listed address "
					                "expected after -z\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_dict *downstream =
				    _getdns_ipaddr_dict(argv[i]);
				if (!downstream) {
					fprintf(stderr, "could not parse "
					        "listen address: %s", argv[i]);
				}
				if (!listen_list &&
				    !(listen_list =
				    getdns_list_create_with_context(context))){
					fprintf(stderr, "Could not create "
							"downstram list\n");
					return GETDNS_RETURN_MEMORY_ERROR;
				}
				getdns_list_set_dict(listen_list,
				    listen_count++, downstream);
				getdns_dict_destroy(downstream);
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
	if (pubkey_pinset && upstream_count) {
		getdns_dict *upstream;
		/* apply the accumulated pubkey pinset to all upstreams: */
		for (i = 0; i < upstream_count; i++) {
			if (r = getdns_list_get_dict(upstream_list, i, &upstream), r) {
				fprintf(stderr, "Failed to get upstream "PRIsz" when adding pinset\n", i);
				return r;
			}
			if (r = getdns_dict_set_list(upstream, "tls_pubkey_pinset", pubkey_pinset), r) {
				fprintf(stderr, "Failed to set pubkey pinset on upstream "PRIsz"\n", i);
				return r;
			}
		}
	}
	if (upstream_count &&
	    (r = getdns_context_set_upstream_recursive_servers(
	    context, upstream_list))) {
		fprintf(stderr, "Error setting upstream recursive servers\n");
	}
	if (upstream_list)
		getdns_list_destroy(upstream_list);

	if (print_api_info) {
		getdns_dict *api_information = 
		    getdns_context_get_api_information(context);
		char *api_information_str =
		    getdns_pretty_print_dict(api_information);
		fprintf(stdout, "%s\n", api_information_str);
		free(api_information_str);
		getdns_dict_destroy(api_information);
		return CONTINUE;
	}
	if (print_trust_anchors) {
		if (!getdns_context_get_dnssec_trust_anchors(context, &tas)) {
		/* if ((tas = getdns_root_trust_anchor(NULL))) { */
			char *tas_str = getdns_pretty_print_list(tas);
			fprintf(stdout, "%s\n", tas_str);
			free(tas_str);
			getdns_list_destroy(tas);
			return CONTINUE;
		} else
			return CONTINUE_ERROR;
	}
	return r;
}

getdns_return_t do_the_call(void)
{
	getdns_return_t r;
	getdns_dict *address = NULL;
	getdns_dict *response = NULL;
	char *response_str;
	uint32_t status;

	if (calltype == HOSTNAME &&
	    !(address = _getdns_ipaddr_dict(name))) {
		fprintf(stderr, "Could not convert \"%s\" "
				"to an IP address", name);
		return GETDNS_RETURN_GOOD;
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
		if (r == GETDNS_RETURN_GOOD && !batch_mode) 
			getdns_context_run(context);
		if (r != GETDNS_RETURN_GOOD)
			fprintf(stderr, "An error occurred: %d '%s'\n", (int)r,
				 getdns_get_errorstr_by_id(r));
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
		if (r != GETDNS_RETURN_GOOD) {
			fprintf(stderr, "An error occurred: %d '%s'\n", (int)r,
				 getdns_get_errorstr_by_id(r));
			getdns_dict_destroy(address);
			return r;
		}
		if (response && !quiet) {
			if ((response_str = json ?
			    getdns_print_json_dict(response, json == 1)
			  : getdns_pretty_print_dict(response))) {

				fprintf( stdout, "SYNC response:\n%s\n"
				       , response_str);
				validate_chain(response);
				free(response_str);
			} else {
				r = GETDNS_RETURN_MEMORY_ERROR;
				fprintf( stderr
				       , "Could not print response\n");
			}
		}
		getdns_dict_get_int(response, "status", &status);
		fprintf(stdout, "Response code was: GOOD. Status was: %s\n", 
			 getdns_get_errorstr_by_id(status));
		if (response)
			getdns_dict_destroy(response);
	}
	getdns_dict_destroy(address);
	return r;
}

getdns_eventloop *loop = NULL;
FILE *fp;

void read_line_cb(void *userarg)
{
	getdns_eventloop_event *read_line_ev = userarg;
	getdns_return_t r;

	char line[1024], *token, *linev[256];
	int linec;

	if (!fgets(line, 1024, fp) || !*line) {
		if (query_file)
			fprintf(stdout,"End of file.");
		loop->vmt->clear(loop, read_line_ev);
		return;
	}
	if (query_file)
		fprintf(stdout,"Found query: %s", line);

	linev[0] = __FILE__;
	linec = 1;
	if (!(token = strtok(line, " \t\f\n\r"))) {
		if (! query_file) {
			printf("> ");
			fflush(stdout);
		}
		return;
	}
	if (*token == '#') {
		fprintf(stdout,"Result:      Skipping comment\n");
		if (! query_file) {
			printf("> ");
			fflush(stdout);
		}
		return;
	}
	do linev[linec++] = token;
	while (linec < 256 && (token = strtok(NULL, " \t\f\n\r")));

	if (((r = parse_args(linec, linev)) || (r = do_the_call())) &&
	    (r != CONTINUE && r != CONTINUE_ERROR))
		loop->vmt->clear(loop, read_line_ev);

	else if (! query_file) {
		printf("> ");
		fflush(stdout);
	}
}

typedef struct dns_msg {
	getdns_transaction_t  request_id;
	getdns_dict          *query;
	uint32_t              rt;
	uint32_t              do_bit;
	uint32_t             cd_bit;
} dns_msg;

#if defined(TRACE_DEBUG) && TRACE_DEBUG
#define SERVFAIL(error,r,msg,resp_p) do { \
	if (r)	DEBUG_TRACE("%s: %s\n", error, getdns_get_errorstr_by_id(r)); \
	else	DEBUG_TRACE("%s\n", error); \
	servfail(msg, resp_p); \
	} while (0)
#else
#define SERVFAIL(error,r,msg,resp_p) servfail(msg, resp_p)
#endif

void servfail(dns_msg *msg, getdns_dict **resp_p)
{
	getdns_dict *dict;

	if (*resp_p)
		getdns_dict_destroy(*resp_p);
	if (!(*resp_p = getdns_dict_create()))
		return;
	if (!getdns_dict_get_dict(msg->query, "header", &dict))
		getdns_dict_set_dict(*resp_p, "header", dict);
	if (!getdns_dict_get_dict(msg->query, "question", &dict))
		getdns_dict_set_dict(*resp_p, "question", dict);
	(void) getdns_dict_set_int(
	    *resp_p, "/header/rcode", GETDNS_RCODE_SERVFAIL);
	(void) getdns_dict_set_int(*resp_p, "/header/qr", 1);
	(void) getdns_dict_set_int(*resp_p, "/header/ad", 0);
	(void) getdns_dict_set_int(*resp_p, "/header/ra",
	    msg->rt == GETDNS_RESOLUTION_RECURSING ? 1 : 0);
}

void request_cb(getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *response, void *userarg, getdns_transaction_t transaction_id)
{
	dns_msg *msg = (dns_msg *)userarg;
	uint32_t qid;
	getdns_return_t r = GETDNS_RETURN_GOOD;
	uint32_t n;

	DEBUG_TRACE("reply for: %p %"PRIu64" %d\n", msg, transaction_id, (int)callback_type);
	assert(msg);

#if 0
	fprintf(stderr, "reply: %s\n", getdns_pretty_print_dict(response));
#endif

	if (callback_type != GETDNS_CALLBACK_COMPLETE)
		SERVFAIL("Callback type not complete",
		    callback_type, msg, &response);

	else if (!response)
		SERVFAIL("Missing response", 0, msg, &response);

	else if ((r = getdns_dict_get_int(msg->query, "/header/id", &qid)) ||
	    (r=getdns_dict_set_int(response,"/replies_tree/0/header/id",qid)))
		SERVFAIL("Could not copy QID", r, msg, &response);

	else if (getdns_dict_get_int(
	    response, "/replies_tree/0/header/rcode", &n))
		SERVFAIL("No reply in replies tree", 0, msg, &response);

	else if (msg->cd_bit != 1 && !getdns_dict_get_int(
	    response, "/replies_tree/0/dnssec_status", &n)
	    && n == GETDNS_DNSSEC_BOGUS)
		SERVFAIL("DNSSEC status was bogus", 0, msg, &response);

	else if ((r = getdns_dict_get_int(
	    response, "/replies_tree/0/header/rcode", &n)))
		SERVFAIL("Could not get rcode from reply", r, msg, &response);

	else if (n == GETDNS_RCODE_SERVFAIL)
		servfail(msg, &response);

	else if (msg->rt == GETDNS_RESOLUTION_STUB)
		; /* following checks are for RESOLUTION_RECURSING only */
	
	else if ((r =  getdns_dict_set_int(
	    response, "/replies_tree/0/header/cd", msg->cd_bit)))
		SERVFAIL("Could not copy CD bit", r, msg, &response);

	else if ((r = getdns_dict_get_int(
	    response, "/replies_tree/0/header/ra", &n)))
		SERVFAIL("Could not get RA bit from reply", r, msg, &response);

	else if (n == 0)
		SERVFAIL("Recursion not available", 0, msg, &response);

	if (!response)
		/* No response, no reply */
		_getdns_cancel_reply(context, msg->request_id);

	else if ((r = getdns_reply(context, msg->request_id, response))) {
		fprintf(stderr, "Could not reply: %s\n",
		    getdns_get_errorstr_by_id(r));
		_getdns_cancel_reply(context, msg->request_id);
	}
	if (msg) {
		getdns_dict_destroy(msg->query);
		free(msg);
	}
	if (response)
		getdns_dict_destroy(response);
}	

void incoming_request_handler(getdns_context *context,
    getdns_dict *request, getdns_transaction_t request_id)
{
	getdns_bindata *qname;
	char *qname_str = NULL;
	uint32_t qtype;
	uint32_t qclass;
	getdns_return_t r;
	getdns_dict *header;
	uint32_t n;
	getdns_list *list;
	getdns_transaction_t transaction_id;
	getdns_dict *qext = NULL;

	if (!query_extensions_spc &&
	    !(query_extensions_spc = getdns_dict_create()))
		fprintf(stderr, "Could not create query extensions space\n");

	else if ((r = getdns_dict_set_dict(
	    query_extensions_spc, "qext", extensions)))
		fprintf(stderr, "Could not copy extensions in query extensions"
		                " space: %s\n", getdns_get_errorstr_by_id(r));

	else if ((r = getdns_dict_get_dict(query_extensions_spc,"qext",&qext)))
		fprintf(stderr, "Could not get query extensions from space: %s"
		              , getdns_get_errorstr_by_id(r));

	/* pass through the header and the OPT record */
	n = 0;
	msg->do_bit = msg->cd_bit = 0;
	msg->rt = GETDNS_RESOLUTION_STUB;
	(void) getdns_dict_get_int(msg->query, "/additional/0/do", &msg->do_bit);
	(void) getdns_dict_get_int(msg->query, "/header/cd", &msg->cd_bit);
	if ((r = getdns_context_get_resolution_type(context, &msg->rt)))
		fprintf(stderr, "Could get resolution type from context: %s\n",
		    getdns_get_errorstr_by_id(r));

	if (msg->rt == GETDNS_RESOLUTION_STUB) {
		(void)getdns_dict_set_int(
		    qext , "/add_opt_parameters/do_bit", msg->do_bit);
		if (!getdns_dict_get_dict(msg->query, "header", &header))
			(void)getdns_dict_set_dict(qext, "header", header);

	} else if (getdns_dict_get_int(extensions,"dnssec_return_status",&n) ||
	    n == GETDNS_EXTENSION_FALSE)
		(void)getdns_dict_set_int(qext, "dnssec_return_status",
		    msg->do_bit ? GETDNS_EXTENSION_TRUE : GETDNS_EXTENSION_FALSE);

	if (!getdns_dict_get_int(qext, "dnssec_return_status", &n) &&
	    n == GETDNS_EXTENSION_TRUE)
		(void) getdns_dict_set_int(qext, "dnssec_return_all_statuses",
		    msg->cd_bit ? GETDNS_EXTENSION_TRUE : GETDNS_EXTENSION_FALSE);

	if (!getdns_dict_get_int(msg->query,"/additional/0/extended_rcode",&n))
		(void)getdns_dict_set_int(
		    qext, "/add_opt_parameters/extended_rcode", n);

	if (!getdns_dict_get_int(msg->query, "/additional/0/version", &n))
		(void)getdns_dict_set_int(
		    qext, "/add_opt_parameters/version", n);

	if (!getdns_dict_get_int(
	    msg->query, "/additional/0/udp_payload_size", &n))
		(void)getdns_dict_set_int(qext,
		    "/add_opt_parameters/maximum_udp_payload_size", n);

	if (!getdns_dict_get_list(
	    msg->query, "/additional/0/rdata/options", &list))
		(void)getdns_dict_set_list(qext,
		    "/add_opt_parameters/options", list);

#if 0
	do {
		char *str = getdns_pretty_print_dict(msg->query);
		fprintf(stderr, "query: %s\n", str);
		free(str);
		str = getdns_pretty_print_dict(qext);
		fprintf(stderr, "query with extensions: %s\n", str);
		free(str);
	} while (0);
#endif
	if ((r = getdns_dict_get_bindata(msg->query,"/question/qname",&qname)))
		fprintf(stderr, "Could not get qname from query: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r = getdns_convert_dns_name_to_fqdn(qname, &qname_str)))
		fprintf(stderr, "Could not convert qname: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r=getdns_dict_get_int(msg->query,"/question/qtype",&qtype)))
		fprintf(stderr, "Could get qtype from query: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r=getdns_dict_get_int(msg->query,"/question/qclass",&qclass)))
		fprintf(stderr, "Could get qclass from query: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r = getdns_dict_set_int(qext, "specify_class", qclass)))
		fprintf(stderr, "Could set class from query: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r = getdns_general(context, qname_str, qtype,
	    qext, msg, &transaction_id, request_cb)))
		fprintf(stderr, "Could not schedule query: %s\n",
		    getdns_get_errorstr_by_id(r));
	else {
		DEBUG_TRACE("scheduled: %p %"PRIu64" for %s %d\n",
		    msg, transaction_id, qname_str, (int)qtype);
		free(qname_str);
		return;
	}
	free(qname_str);
	servfail(msg, &response);
	if (!response)
		/* No response, no reply */
		_getdns_cancel_reply(context, msg->request_id);

	else if ((r = getdns_reply(context, msg->request_id, response))) {
		fprintf(stderr, "Could not reply: %s\n",
		    getdns_get_errorstr_by_id(r));
		_getdns_cancel_reply(context, msg->request_id);
	}
	getdns_dict_destroy(msg->query);
	free(msg);
	if (response)
		getdns_dict_destroy(response);
}

int
main(int argc, char **argv)
{
	getdns_return_t r;

	name = the_root;
	if ((r = getdns_context_create(&context, 1))) {
		fprintf(stderr, "Create context failed: %d\n", (int)r);
		return r;
	}
	if ((r = getdns_context_set_use_threads(context, 1)))
		goto done_destroy_context;
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
	} else
		fp = stdin;

	if (listen_count || interactive) {
		if ((r = getdns_context_get_eventloop(context, &loop)))
			goto done_destroy_context;
		assert(loop);
	}
	if (listen_count)
		if ((r = getdns_context_set_listen_addresses(context,
		    incoming_request_handler, listen_list)))
			goto done_destroy_context;

	/* Make the call */
	if (interactive) {
		getdns_eventloop_event read_line_ev = {
		    &read_line_ev, read_line_cb, NULL, NULL, NULL };

		assert(loop);
		(void) loop->vmt->schedule(
		    loop, fileno(fp), -1, &read_line_ev);

		if (!query_file) {
			printf("> ");
			fflush(stdout);
		}
		loop->vmt->run(loop);
	}
	else if (listen_count) {
		assert(loop);
		loop->vmt->run(loop);
	} else
		r = do_the_call();

	if ((r == GETDNS_RETURN_GOOD && batch_mode))
		getdns_context_run(context);

	/* Clean up */
	getdns_dict_destroy(extensions);
done_destroy_context:
	getdns_context_destroy(context);

	if (listen_list)
		getdns_list_destroy(listen_list);

	if (fp)
		fclose(fp);

	if (r == CONTINUE)
		return 0;
	else if (r == CONTINUE_ERROR)
		return 1;
	fprintf(stdout, "\nAll done.\n");
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
	          case 'S':
	          case 's': /* before "CS", final "YNC" (GETDNS_RRTYPE_CSYNC) */
	                    if ((t[2]|0x20) == 'y' && (t[3]|0x20) == 'n' && (t[4]|0x20) == 'c' && t[5] == '\0')
	                              return GETDNS_RRTYPE_CSYNC;
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

