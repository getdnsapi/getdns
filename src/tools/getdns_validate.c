/*
 * getdns_validate.c - Validate DNSSEC responses offline
 *
 * Copyright (c) 2019, NLnet Labs. All rights reserved.
 * 
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _XOPEN_SOURCE
#include <getdns/getdns_extra.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

/* root_first is needed to route around a bug in the current version of the
 * getdns API that requires non RRSIG records in the root to be first.
 * It scans a getdns_list of resource records, and returns a new list rotated
 * to make the root non RRSIG record first.
 * Without root records, no new list is created and the input list is returned.
 * All failures are returned early.
 */
getdns_return_t root_first(getdns_list *in, getdns_list **out)
{
	getdns_return_t r;
	size_t in_len, i, j, j_len, k;
	getdns_dict *rr;
	getdns_bindata *name;
	uint32_t rr_type = 0;

	/* Scan list `in` for root non RRSIG resource record */
	if ((r = getdns_list_get_length(in, &in_len)))
		return r;

	for (i = 0; i < in_len; i++) {
		if ((r = getdns_list_get_dict(in, i, &rr))
		||  (r = getdns_dict_get_bindata(rr, "name", &name))
		||  (r = getdns_dict_get_int(rr, "type", &rr_type)))
			return r;

		if (name->size == 1 && name->data[0] == 0
		&&  rr_type != GETDNS_RRTYPE_RRSIG)
			break;
	}
	if (i == in_len) {
		/* No root non RRSIG resource record found.
		 * return the original list
		 */
		*out = in;
		return GETDNS_RETURN_GOOD;
	}
	/* root non RRSIG record found at position `i`.
	 * Create a new list copying the resource records from `i` till the
	 * end, and then from 0 till `i`.
	 */
	if (!(*out = getdns_list_create()))
		return GETDNS_RETURN_MEMORY_ERROR;

	/* Copy from `i` till the end into the new list */
	for (j_len = j = i, k = 0; j < in_len; j++) {
		if ((r = getdns_list_get_dict(in, j, &rr))
		||  (r = getdns_list_set_dict(*out, k++, rr)))
			break;
	}
	/* Copy from 0 till `i` end into the new list */
	if (!r) for (j = 0; j < j_len; j++) {
		if ((r = getdns_list_get_dict(in, j, &rr))
		||  (r = getdns_list_set_dict(*out, k++, rr)))
			break;
	}
	if (r)
		getdns_list_destroy(*out);
	return r;
}

getdns_return_t print_dnssec_status(int status)
{
	switch (status) {
	case GETDNS_DNSSEC_SECURE:
	case GETDNS_DNSSEC_INSECURE:
	case GETDNS_DNSSEC_INDETERMINATE:
	case GETDNS_DNSSEC_BOGUS:
		printf("%i %s\n", status, getdns_get_errorstr_by_id(status));
		return GETDNS_RETURN_GOOD;
	default:
		fprintf(stderr, "Error validating");
		return status;
	};
}

void print_usage(FILE *out)
{
	fprintf(out, "usage: getdns_validate [<option> ...] "
	    "<to_validate> [<qname>] [<qtype>]\n\n");
	fprintf(out,"\tDNSSEC validate RRsets in <to_validate>. "
	    "When <qname> and <qtype>\n");
	fprintf(out, "\tare specified, the non existence proof is validated "
	    "for that query\n");
	fprintf(out, "\tname and type with the NSEC or NSEC3 records in "
	    "<to_validate>\n\n");
	fprintf(out, "options:\n");
	fprintf(out, "\t-h\tprint this text\n");
	fprintf(out, "\t-d <time>\n\t\tSet validation time.\n"
	    "\t\t<date> should be in ISO 8601 format.\n"
	    "\t\tyyyy-mm-dd or yyyy-mm-ddThh:mm:ssZ\n\n");
	fprintf(out, "\t-k <trust acnhors file>\n"
	    "\t\tFile containing trust anchor RRsets.\n"
	    "\t\tThese may be of type DNSKEY or DS\n\n");
	fprintf(out, "\t-s <support records file>\n"
	    "\t\tFile containing the necessary RRsets to build the chain\n"
	    "\t\tof trust from one of the trust anchors up to the RRsets\n"
	    "\t\tin <to_validate>\n");
}

const char *fqdn(const char *qname)
{
	static char fqdn_buf[1025] = "";

	if (strlen(qname) == 0
	||  qname[strlen(qname)-1] == '.'
	||  strlen(qname) >= sizeof(fqdn_buf))
		return qname;
	else	return strcat(strcat(fqdn_buf, qname), ".");
}

int main(int argc, char **argv)
{
	const char       *support_records_fn = NULL;
	const char       *trust_anchors_fn   = NULL;
	getdns_list      *to_validate        = NULL;
	getdns_list      *to_validate_fixed  = NULL;
	getdns_list      *support_records    = NULL;
	getdns_list      *trust_anchors      = NULL;
	FILE             *fh_to_validate     = NULL;
	FILE             *fh_support_records = NULL;
	FILE             *fh_trust_anchors   = NULL;
	getdns_return_t   r = GETDNS_RETURN_GOOD;

	char              qtype_str[1024]    = "GETDNS_RRTYPE_";
	getdns_bindata   *qname              = NULL;
	uint32_t          qtype              = GETDNS_RRTYPE_A;
	getdns_dict      *nx_reply           = NULL;
	getdns_list      *nx_list            = NULL;

	int               opt;
	struct tm         tm;
	(void)memset(&tm, 0, sizeof(tm));
	time_t            validation_time    = time(NULL);
	char             *endptr;

	while ((opt = getopt(argc, argv, "d:hk:s:")) != -1) {
		switch(opt) {
		case 'd':
			if (!(endptr = strptime(optarg, "%F", &tm))
			|| (   *endptr != 0
			   && !(endptr = strptime(optarg, "%FT%T%z", &tm)))) {
				print_usage(stderr);
				exit(EXIT_FAILURE);
			}
			validation_time = mktime(&tm);
			break;
		case 'h':
			print_usage(stdout);
			exit(EXIT_SUCCESS);
		case 'k':
			trust_anchors_fn = optarg;
			break;
		case 's':
			support_records_fn = optarg;
			break;
		default:
			print_usage(stderr);
			exit(EXIT_FAILURE);
		}
	}
	if (optind >= argc)
		print_usage(stderr);

	else if (!(fh_to_validate = fopen(argv[optind], "r"))) {
		fprintf(stderr, "Error opening \"%s\"", argv[optind]);
		r = GETDNS_RETURN_IO_ERROR;

	} else if ((r = getdns_fp2rr_list(fh_to_validate
	                                 ,  &to_validate, NULL, 3600)))
		fprintf(stderr, "Error reading \"%s\"", argv[1]);

	else if ((r = root_first(to_validate, &to_validate_fixed)))
		fprintf(stderr, "Error reordering \"%s\"", argv[1]);

	else if (support_records_fn
	    && !(fh_support_records = fopen(support_records_fn, "r"))) {
		fprintf(stderr, "Error opening \"%s\"", support_records_fn);
		r = GETDNS_RETURN_IO_ERROR;

	} else if (fh_support_records
	    && (r = getdns_fp2rr_list(fh_support_records
	                             ,  &support_records, NULL, 3600)))
		fprintf(stderr, "Error reading \"%s\"", support_records_fn);

	else if (trust_anchors_fn
	    && !(fh_trust_anchors = fopen(trust_anchors_fn, "r"))) {
		fprintf(stderr, "Error opening \"%s\"", trust_anchors_fn);
		r = GETDNS_RETURN_IO_ERROR;

	} else if (fh_trust_anchors
	    && (r = getdns_fp2rr_list(fh_trust_anchors
	                             ,  &trust_anchors, NULL, 3600)))
		fprintf(stderr, "Error reading \"%s\"", trust_anchors_fn);

	else if (!trust_anchors &&
	    !(trust_anchors = getdns_root_trust_anchor(NULL))) {
		fprintf(stderr, "Missing trust anchors");
		r = GETDNS_RETURN_GENERIC_ERROR;

	} else if (optind + 1 < argc
	    && (r = getdns_str2bindata(fqdn(argv[optind + 1]), &qname)))
		fprintf(stderr, "Could not parse qname");

	else if (optind + 2 < argc
	    && (r = getdns_str2int( strcat(qtype_str, argv[optind + 2])
	                          , &qtype)))
		fprintf(stderr, "Could not parse qtype");

	else if (!qname && (r = getdns_validate_dnssec2(
	    to_validate_fixed, support_records, trust_anchors,
	    validation_time, 1)))
		r = print_dnssec_status(r);

	else if (!(nx_reply = getdns_dict_create())) {
		fprintf(stderr, "Could not create nx_reply dict");
		r = GETDNS_RETURN_MEMORY_ERROR;

	} else if ((r = getdns_dict_set_bindata(
	    nx_reply, "/question/qname", qname)))
		fprintf(stderr, "Could not set qname");

	else if ((r = getdns_dict_set_int(
	    nx_reply, "/question/qtype", qtype)))
		fprintf(stderr, "Could not set qtype");

	else if ((r = getdns_dict_set_int(
	    nx_reply, "/question/qclass", GETDNS_RRCLASS_IN)))
		fprintf(stderr, "Could not set qclass");

	else if ((r = getdns_dict_set_list(
	    nx_reply, "/answer", to_validate_fixed)))
		fprintf(stderr, "Could not set answer section");

	else if (!(nx_list = getdns_list_create())) {
		fprintf(stderr, "Could not create nx_list list");
		r = GETDNS_RETURN_MEMORY_ERROR;

	} else if ((r = getdns_list_set_dict(nx_list, 0, nx_reply)))
		fprintf(stderr, "Could not append nx_reply to nx_list");

	else if ((r = getdns_validate_dnssec2(
	    nx_list, support_records, trust_anchors,
	    validation_time, 1)))
		r = print_dnssec_status(r);

	if (to_validate)	getdns_list_destroy(to_validate);
	if (to_validate_fixed && to_validate_fixed != to_validate)
		getdns_list_destroy(to_validate_fixed);
	if (support_records)	getdns_list_destroy(support_records);
	if (trust_anchors)	getdns_list_destroy(trust_anchors);
	if (fh_to_validate)	(void) fclose(fh_to_validate);
	if (fh_support_records)	(void) fclose(fh_support_records);
	if (fh_trust_anchors)	(void) fclose(fh_trust_anchors);
	if (qname)		{ free(qname->data); free(qname); }
	if (nx_reply)		getdns_dict_destroy(nx_reply);
	if (nx_list)		getdns_list_destroy(nx_list);

	if (r) {
		fprintf(stderr, ": %s\n", r == GETDNS_RETURN_IO_ERROR ?
		    strerror(errno) : getdns_get_errorstr_by_id(r));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
