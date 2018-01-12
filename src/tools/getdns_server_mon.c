/*
 * Copyright (c) 2018, NLNet Labs, Sinodun
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

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>

#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

#define APP_NAME "getdns_server_mon"

#define EXAMPLE_PIN "pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\""

/* Plugin exit values */
typedef enum {
        EXIT_OK = 0,
        EXIT_WARNING,
        EXIT_CRITICAL,
        EXIT_UNKNOWN
} exit_value_t;

/* Plugin verbosity values */
typedef enum {
        VERBOSITY_MINIMAL = 0,
        VERBOSITY_ADDITIONAL,
        VERBOSITY_CONFIG,
        VERBOSITY_DEBUG
} verbosity_t;

static struct test_info_s
{
        getdns_context *context;

        /* Output control */
        bool monitoring;
        FILE *errout;
        verbosity_t verbosity;

        /* Test config info */
        bool fail_on_dns_errors;
} test_info;

static const char *rcode_text(int rcode)
{
        const char *text[] = {
                "OK",
                "FORMERR",
                "SERVFAIL",
                "NXDOMAIN",
                "NOTIMP",
                "REFUSED"
        };

        if ((size_t) rcode >= sizeof(text) / sizeof(text[0]))
                return "(?)";
        else
                return text[rcode];
}

/* Thanks to:
 * https://zakird.com/2013/10/13/certificate-parsing-with-openssl
 */
static bool extract_cert_expiry(const unsigned char *data, size_t len, time_t *t)
{
        X509 *cert = d2i_X509(NULL, &data, len);
        if (!cert)
                return false;

        ASN1_TIME *not_after = X509_get_notAfter(cert);

        /*
         * Use ASN1_TIME_diff to get a time delta between now and expiry.
         * This is much easier than trying to parse the time.
         */
        int day, sec;
        *t = time(NULL);
        ASN1_TIME_diff(&day, &sec, NULL, not_after);
        *t += day * 86400 + sec;

        X509_free(cert);
        return true;
}

static void exit_tidy()
{
        if (test_info.context)
                getdns_context_destroy(test_info.context);
}

static void usage()
{
        fputs(
"Usage: " APP_NAME " [-MEr] @upstream testname [<name>] [<type>]\n"
"  -M|--monitoring               Make output suitable for monitoring tools\n"
"  -E|--fail-on-dns-errors       Fail on DNS error (NXDOMAIN, SERVFAIL)\n"
"  -T|--tls     		 Use TLS transport\n"
"  -S|--strict-usage-profile     Use strict profile (require authentication)\n"
"  -K|--spki-pin <spki-pin>      SPKI pin for TLS connections (can repeat)\n"
"  -v|--verbose                  Increase output verbosity\n"
"  -V|--version                  Report GetDNS version\n"
"\n"
"spki-pin: Should look like '" EXAMPLE_PIN "'\n"
"\n"
"upstream: @<ip>[%<scope_id][@<port>][#<tls_port>][~tls name>][^<tsig spec>]\n"
"          <ip>@<port> may be given as <IPv4>:<port> or\n"
"                      '['<IPv6>[%<scope_id>]']':<port>\n"
"\n"
"tsig spec: [<algorithm>:]<name>:<secret in Base64>\n"
"\n"
"Tests:\n"
"  auth [<name> [<type>]]        Check authentication of TLS server\n"
"                                If both a SPKI pin and authentication name are\n"
"                                provided, both must authenticate for this test\n"
"                                to pass.\n"
"  qname-min                     Check whether server supports QNAME minimisation\n"
"  cert-valid [<name> [type]] [warn-days,crit-days]\n"
"                                Check server certificate validity, report\n"
"                                warning or critical if days to expiry at\n"
"                                or below thresholds (default 14,7).\n"
"\n"
"Enabling monitoring mode ensures output messages and exit statuses conform\n"
"to the requirements of monitoring plugins (www.monitoring-plugins.org).\n",
                test_info.errout);
        exit(EXIT_UNKNOWN);
}

static void version()
{
        fputs(APP_NAME ": getdns " GETDNS_VERSION " , API " GETDNS_API_VERSION ".\n",
              test_info.errout);
        exit(EXIT_UNKNOWN);
}

static exit_value_t search(const struct test_info_s *test_info,
                           const char *name,
                           uint16_t type,
                           getdns_dict **response)
{
        getdns_return_t ret;
        getdns_dict *extensions = getdns_dict_create();

        if ((ret = getdns_dict_set_int(extensions, "return_call_reporting", GETDNS_EXTENSION_TRUE)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info->errout,
                        "Cannot set return call reporting: %s (%d)",
                        getdns_get_errorstr_by_id(ret),
                        ret);
                getdns_dict_destroy(extensions);
                return EXIT_UNKNOWN;
        }
        if ((ret = getdns_dict_set_int(extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info->errout,
                        "Cannot set return both IPv4 and IPv6: %s (%d)",
                        getdns_get_errorstr_by_id(ret),
                        ret);
                getdns_dict_destroy(extensions);
                return EXIT_UNKNOWN;
        }

        if (test_info->verbosity >= VERBOSITY_DEBUG) {
                fprintf(test_info->errout,
                        "Context: %s\n",
                        getdns_pretty_print_dict(getdns_context_get_api_information(test_info->context)));
        }

        ret = getdns_general_sync(test_info->context,
                                  name,
                                  type,
                                  extensions,
                                  response);
        getdns_dict_destroy(extensions);
        if (ret != GETDNS_RETURN_GOOD) {
                fprintf(test_info->errout,
                        "Error resolving '%s': %s (%d)",
                        name,
                        getdns_get_errorstr_by_id(ret),
                        ret);
                return EXIT_CRITICAL;
        }

        if (test_info->verbosity >= VERBOSITY_DEBUG) {
                fprintf(test_info->errout,
                        "Response: %s\n",
                        getdns_pretty_print_dict(*response));
        }

        return EXIT_OK;
}

static exit_value_t check_result(const struct test_info_s *test_info,
                                 const getdns_dict *response)
{
        getdns_return_t ret;
        uint32_t error_id;

        if ((ret = getdns_dict_get_int(response, "status", &error_id)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info->errout,
                        "Cannot get result status: %s (%d)",
                        getdns_get_errorstr_by_id(ret),
                        ret);
                return EXIT_UNKNOWN;
        }

        if (test_info->verbosity >= VERBOSITY_ADDITIONAL){
                fprintf(test_info->errout,
                        "result: %s (%d), ",
                        getdns_get_errorstr_by_id(error_id),
                        error_id);
        }

        if (error_id == GETDNS_RESPSTATUS_GOOD)
                return EXIT_OK;

        uint32_t rcode;

        ret = getdns_dict_get_int(response, "/replies_tree/0/header/rcode", &rcode);
        if (ret == GETDNS_RETURN_NO_SUCH_DICT_NAME ||
            ret == GETDNS_RETURN_NO_SUCH_LIST_ITEM) {
                fputs("Search had no results, timeout?", test_info->errout);
                return EXIT_CRITICAL;
        } else if (ret != GETDNS_RETURN_GOOD) {
                fprintf(test_info->errout,
                        "Cannot get DNS return code: %s (%d)",
                        getdns_get_errorstr_by_id(ret),
                        ret);
                return EXIT_UNKNOWN;
        }

        if (test_info->fail_on_dns_errors && rcode > 0) {
                fprintf(test_info->errout,
                        "DNS error %s (%d)",
                        rcode_text(rcode),
                        rcode);
                return EXIT_CRITICAL;
        }

        return EXIT_OK;
}

static exit_value_t get_report_info(const struct test_info_s *test_info,
                                    const getdns_dict *response,
                                    uint32_t *rtt,
                                    getdns_bindata **auth_status,
                                    time_t *cert_expire_time)
{
        getdns_return_t ret;
        getdns_list *l;
        uint32_t rtt_val;
        getdns_bindata *auth_status_val = NULL;
        time_t cert_expire_time_val = 0;

        if ((ret = getdns_dict_get_list(response, "call_reporting", &l)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info->errout,
                        "Cannot get call report: %s (%d)",
                        getdns_get_errorstr_by_id(ret),
                        ret);
                return EXIT_UNKNOWN;
        }

        getdns_dict *d;
        if ((ret = getdns_list_get_dict(l, 0, &d)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info->errout,
                        "Cannot get call report first item: %s (%d)",
                        getdns_get_errorstr_by_id(ret),
                        ret);
                return EXIT_UNKNOWN;
        }
        if ((ret = getdns_dict_get_int(d, "run_time/ms", &rtt_val)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info->errout,
                        "Cannot get RTT: %s (%d)",
                        getdns_get_errorstr_by_id(ret),
                        ret);
                return EXIT_UNKNOWN;
        }
        if (rtt)
                *rtt = rtt_val;
        if (test_info->verbosity >= VERBOSITY_ADDITIONAL)
                fprintf(test_info->errout, "RTT %dms, ", rtt_val);

        if (getdns_dict_get_bindata(d, "tls_auth_status", &auth_status_val) == GETDNS_RETURN_GOOD) {
                /* Just in case - not sure this is necessary */
                auth_status_val->data[auth_status_val->size] = '\0';
                if (test_info->verbosity >= VERBOSITY_ADDITIONAL)
                        fprintf(test_info->errout, "auth. %s, ", (char *) auth_status_val->data);
        }
        if (auth_status)
                *auth_status = auth_status_val;

        getdns_bindata *cert;
        if (getdns_dict_get_bindata(d, "tls_peer_cert", &cert) == GETDNS_RETURN_GOOD) {
                if (!extract_cert_expiry(cert->data, cert->size, &cert_expire_time_val)) {
                        fputs("Cannot parse PKIX certificate", test_info->errout);
                        return EXIT_UNKNOWN;
                }
                if (test_info->verbosity >= VERBOSITY_ADDITIONAL) {
                        struct tm *tm = gmtime(&cert_expire_time_val);
                        char buf[25];
                        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
                        fprintf(test_info->errout, "cert expiry %s, ", buf);
                }
        }
        if (cert_expire_time)
                *cert_expire_time = cert_expire_time_val;

        return EXIT_OK;
}

/**
 * Test routines.
 */

static exit_value_t test_qname_minimisation(const struct test_info_s *test_info,
                                            char ** av)
{
        if (*av) {
                fputs("qname-minimisation takes no arguments",
                      test_info->errout);
                return EXIT_UNKNOWN;
        }

        getdns_dict *response;
        exit_value_t xit = search(test_info, "qnamemintest.internet.nl", GETDNS_RRTYPE_TXT, &response);
        if (xit != EXIT_OK)
                return xit;

        xit = check_result(test_info, response);
        if (xit != EXIT_OK)
                return xit;

        /* Don't need any of this, but do want check and verbosity reporting. */
        xit = get_report_info(test_info, response, NULL, NULL, NULL);
        if (xit != EXIT_OK)
                return xit;

	getdns_list *answers;
	getdns_return_t ret;

	if ((ret = getdns_dict_get_list(response, "/replies_tree/0/answer", &answers)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info->errout,
                        "Cannot get answers: %s (%d)",
                        getdns_get_errorstr_by_id(ret),
                        ret);
                return EXIT_UNKNOWN;
	}

	size_t no_answers;
	if ((ret = getdns_list_get_length(answers, &no_answers)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info->errout,
                        "Cannot get number of answers: %s (%d)",
                        getdns_get_errorstr_by_id(ret),
                        ret);
                return EXIT_UNKNOWN;
	}
	if (no_answers <= 0) {
		fputs("Got zero answers", test_info->errout);
		return EXIT_WARNING;
	}

	for (size_t i = 0; i < no_answers; ++i) {
		getdns_dict *answer;

		if ((ret = getdns_list_get_dict(answers, i, &answer)) != GETDNS_RETURN_GOOD) {
			fprintf(test_info->errout,
				"Cannot get answer number %zu: %s (%d)",
				i,
				getdns_get_errorstr_by_id(ret),
				ret);
			return EXIT_UNKNOWN;
		}

		uint32_t rtype;

		if ((ret = getdns_dict_get_int(answer, "type", &rtype)) != GETDNS_RETURN_GOOD) {
			fprintf(test_info->errout,
				"Cannot get answer type: %s (%d)",
				getdns_get_errorstr_by_id(ret),
				ret);
			return EXIT_UNKNOWN;
		}
		if (rtype != GETDNS_RRTYPE_TXT)
			continue;

		getdns_bindata *rtxt;
		if ((ret = getdns_dict_get_bindata(answer, "/rdata/txt_strings/0", &rtxt)) != GETDNS_RETURN_GOOD) {
			fputs("No answer text", test_info->errout);
			return EXIT_WARNING;
		}

		if (rtxt->size > 0 ) {
			switch(rtxt->data[0]) {
			case 'H':
				fputs("QNAME minimisation ON", test_info->errout);
				return EXIT_OK;

			case 'N':
				fputs("QNAME minimisation OFF", test_info->errout);
				return EXIT_WARNING;

			default:
				/* Unrecognised message. */
				break;
			}
		}
	}

	fputs("No valid QNAME minimisation data", test_info->errout);
        return EXIT_UNKNOWN;
}

static struct test_funcs_s
{
        const char *name;
        exit_value_t (*func)(const struct test_info_s *test_info, char **av);
} TESTS[] =
{
        { "qname-min", test_qname_minimisation },
        { NULL, NULL }
};

int main(int ATTR_UNUSED(ac), char *av[])
{
        getdns_return_t ret;
        getdns_list *pinset = NULL;
        size_t pinset_size = 0;
        bool strict_usage_profile = false;
	bool use_tls = false;

        test_info.errout = stderr;
        atexit(exit_tidy);
        if ((ret = getdns_context_create(&test_info.context, 1)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info.errout,
                        "Create context failed: %s (%d)\n",
                        getdns_get_errorstr_by_id(ret),
                        ret);
                exit(EXIT_UNKNOWN);
        }

        for (++av; *av && *av[0] == '-'; ++av) {
                if (strcmp(*av, "-M") == 0 ||
                    strcmp(*av, "--monitoring") == 0) {
                        test_info.monitoring = true;
                        test_info.errout = stdout;
                } else if (strcmp(*av, "-E") == 0 ||
                           strcmp(*av, "--fail-on-dns-errors") == 0) {
                        test_info.fail_on_dns_errors = true;
                } else if (strcmp(*av, "-T") == 0 ||
                           strcmp(*av, "--tls") == 0 ) {
                        use_tls = true;
                } else if (strcmp(*av, "-S") == 0 ||
                           strcmp(*av, "--strict-usage-profile") == 0 ) {
                        strict_usage_profile = true;
			use_tls = true;
                } else if (strcmp(*av, "-K") == 0 ||
                           strcmp(*av, "--spki-pin") == 0 ) {
                        ++av;
                        if (!*av) {
                                fputs("pin string of the form " EXAMPLE_PIN "expected after -K|--pin\n", test_info.errout);
                                exit(EXIT_UNKNOWN);
                        }

                        getdns_dict *pin;

                        pin = getdns_pubkey_pin_create_from_string(test_info.context, *av);
                        if (!pin) {
                                fprintf(test_info.errout,
                                        "Could not convert '%s' into a public key pin.\n"
                                        "Good pins look like: " EXAMPLE_PIN "\n"
                                        "Please see RFC 7469 for details about the format.\n", *av);
                                exit(EXIT_UNKNOWN);
                        }
                        if (!pinset)
                                pinset = getdns_list_create_with_context(test_info.context);
                        ret = getdns_list_set_dict(pinset,
                                                   pinset_size++,
                                                   pin);
                        getdns_dict_destroy(pin);
                        if (ret != GETDNS_RETURN_GOOD) {
                                fprintf(test_info.errout,
                                        "Could not add pin '%s' to pin set.\n",
                                        *av);
                                getdns_list_destroy(pinset);
                                exit(EXIT_UNKNOWN);

                        }
			use_tls = true;
                } else if (strcmp(*av, "-v") == 0 ||
                           strcmp(*av, "--verbose") == 0) {
                        ++test_info.verbosity;
                } else if (strcmp(*av, "-V") == 0 ||
                           strcmp(*av, "--version") == 0) {
                        version();
                } else {
                        usage();
                }
        }

        if (*av == NULL || *av[0] != '@')
                usage();

        const char *upstream = *av++;
        getdns_dict *resolver;
        getdns_bindata *address;

        if ((ret = getdns_str2dict(&upstream[1], &resolver)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info.errout,
                        "Could not convert \"%s\" to an IP dict: %s (%d)\n",
                        &upstream[1],
                        getdns_get_errorstr_by_id(ret),
                        ret);
                exit(EXIT_UNKNOWN);
        }
        if ((ret = getdns_dict_get_bindata(resolver, "address_data", &address)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info.errout,
                        "\"%s\" did not translate to an IP dict: %s (%d)\n",
                        &upstream[1],
                        getdns_get_errorstr_by_id(ret),
                        ret);
                getdns_dict_destroy(resolver);
                exit(EXIT_UNKNOWN);
        }

        /* Set parameters on the resolver. */
        if (pinset) {
                ret = getdns_dict_set_list(resolver,
                                           "tls_pubkey_pinset",
                                           pinset);
                getdns_list_destroy(pinset);
                if (ret != GETDNS_RETURN_GOOD) {
                        fprintf(test_info.errout,
                                "Cannot set keys for \"%s\": %s (%d)\n",
                                &upstream[1],
                                getdns_get_errorstr_by_id(ret),
                                ret);
                        exit(EXIT_UNKNOWN);
                }
        }

        /* Set getdns context to use the indicated resolver. */
        getdns_list *l = getdns_list_create();
        ret = getdns_list_set_dict(l, 0, resolver);
        getdns_dict_destroy(resolver);
        if (ret != GETDNS_RETURN_GOOD) {
                fprintf(test_info.errout,
                        "Unable to add upstream '%s' to list: %s (%d)\n",
                        upstream,
                        getdns_get_errorstr_by_id(ret),
                        ret);
                getdns_list_destroy(l);
                exit(EXIT_UNKNOWN);
        }
        ret = getdns_context_set_upstream_recursive_servers(test_info.context, l);
        getdns_list_destroy(l);
        if (ret != GETDNS_RETURN_GOOD) {
                fprintf(test_info.errout,
                        "Unable to set upstream resolver to '%s': %s (%d)\n",
                        upstream,
                        getdns_get_errorstr_by_id(ret),
                        ret);
                exit(EXIT_UNKNOWN);
        }

        /* Set context to stub mode. */
        if ((ret = getdns_context_set_resolution_type(test_info.context, GETDNS_RESOLUTION_STUB)) != GETDNS_RETURN_GOOD) {
                fprintf(test_info.errout,
                        "Unable to set stub mode: %s (%d)\n",
                        getdns_get_errorstr_by_id(ret),
                        ret);
                exit(EXIT_UNKNOWN);
        }

        /* Set other context parameters. */
	if (use_tls) {
		getdns_transport_list_t t[] = { GETDNS_TRANSPORT_TLS };
		if ((ret = getdns_context_set_dns_transport_list(test_info.context, 1, t)) != GETDNS_RETURN_GOOD) {
			fprintf(test_info.errout,
				"Unable to set TLS transport: %s (%d)\n",
				getdns_get_errorstr_by_id(ret),
				ret);
			exit(EXIT_UNKNOWN);
		}
	}

        if (strict_usage_profile) {
                ret = getdns_context_set_tls_authentication(test_info.context, GETDNS_AUTHENTICATION_REQUIRED);
                if (ret != GETDNS_RETURN_GOOD) {
                        fprintf(test_info.errout,
                                "Unable to set strict profile: %s (%d)\n",
                                getdns_get_errorstr_by_id(ret),
                                ret);
                        exit(EXIT_UNKNOWN);
                }
        }

        /* Choose and run test */
        const char *testname = *av;

        if (!testname)
                usage();
        ++av;

        for (const struct test_funcs_s *f = TESTS;
             f->name != NULL;
             ++f) {
                if (strcmp(testname, f->name) == 0) {
                        exit_value_t xit = f->func(&test_info, av);
                        fputc('\n', test_info.errout);
                        exit(xit);
                }
        }
        fprintf(test_info.errout, "Unknown test %s\n", testname);
        exit(EXIT_UNKNOWN);
}
