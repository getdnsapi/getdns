/**
 *
 * /brief getdns support functions for DNS Resource Records
 */
/*
 * Copyright (c) 2013, NLnet Labs, Verisign, Inc.
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

#ifndef RR_DICT_H_
#define RR_DICT_H_

#include <ldns/ldns.h>
#include "getdns/getdns.h"

typedef uint8_t *(*priv_getdns_rdf_end_t)(
    uint8_t *pkt, uint8_t *pkt_end, uint8_t *rdf);
/* Limit checks are already done with priv_getdns_rdf_end_t */
typedef getdns_return_t (*priv_getdns_rdf_dict_set_value_t)(
    getdns_dict *dict, uint8_t *rdf);
typedef getdns_return_t (*priv_getdns_rdf_list_append_value_t)(
    getdns_list *list, uint8_t *rdf);

typedef struct priv_getdns_rdf_special {
	priv_getdns_rdf_end_t               rdf_end;
	priv_getdns_rdf_dict_set_value_t    dict_set_value;
	priv_getdns_rdf_list_append_value_t list_append_value;
} priv_getdns_rdf_special;

/* draft-levine-dnsextlang'ish type rr and rdata definitions */

#define GETDNS_RDF_INTEGER   0x010000
#define GETDNS_RDF_BINDATA   0x020000
#define GETDNS_RDF_DNAME     0x060000
#define GETDNS_RDF_REPEAT    0x100000

#define GETDNS_RDF_FIXEDSZ   0x0000FF
#define GETDNS_RDF_LEN_VAL   0x00FF00

typedef enum priv_getdns_rdf_wf_type {
	GETDNS_RDF_N       = 0x060000,
	GETDNS_RDF_N_A     = GETDNS_RDF_N,
	GETDNS_RDF_N_A_C   = GETDNS_RDF_N,
	GETDNS_RDF_N_C     = GETDNS_RDF_N,
	GETDNS_RDF_N_M     = 0x160000,

	GETDNS_RDF_I1      = 0x010001,
	GETDNS_RDF_I2      = 0x010002,
	GETDNS_RDF_I4      = 0x010004,
	GETDNS_RDF_I6      = 0x020006,
	GETDNS_RDF_A       = 0x020004,
	GETDNS_RDF_AAAA    = 0x020010,

	GETDNS_RDF_S       = 0x020100,
	GETDNS_RDF_S_M     = 0x120100,

	GETDNS_RDF_B       = 0x020000,
	GETDNS_RDF_B_C     = 0x020100,
	GETDNS_RDF_B32_C   = 0x020100,
	GETDNS_RDF_X       = 0x020000,
	GETDNS_RDF_X_C     = 0x020100,
	GETDNS_RDF_X_2     = 0x020200,
	GETDNS_RDF_X6      = 0x020006,
	GETDNS_RDF_X8      = 0x020008,

	GETDNS_RDF_R       = 0x100000, /* Repeat */

	GETDNS_RDF_SPECIAL = 0x800000,
} priv_getdns_rdf_type;

typedef struct priv_getdns_rdata_def {
	const char              *name;
	priv_getdns_rdf_type     type;
	priv_getdns_rdf_special *special;
} priv_getdns_rdata_def;

typedef struct priv_getdns_rr_def {
	const char                  *name;
	const priv_getdns_rdata_def *rdata;
	int                          n_rdata_fields;
} priv_getdns_rr_def;

const priv_getdns_rr_def *priv_getdns_rr_def_lookup(uint16_t rr_type);

getdns_return_t priv_getdns_create_dict_from_rr(
    struct getdns_context *context, ldns_rr *rr, struct getdns_dict** rr_dict);

getdns_return_t priv_getdns_create_rr_from_dict(
    struct getdns_dict *rr_dict, ldns_rr **rr);

const char *priv_getdns_rr_type_name(int rr_type);

#endif

/* rrs.h */
