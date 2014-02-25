/**
 *
 * /brief getdns support functions for DNS Resource Records
 *
 * This file contains the tables with the information needed by getdns about
 * individual RRs, such as their name and rdata fields and types.
 * This information is provided via the response dict.
 *
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

#include "rr-dict.h"
#include "types-internal.h"
#include "context.h"
#include "dict.h"

#define ALEN(a) (sizeof(a)/sizeof(a[0]))

struct rdata_def {
	const char *name;
	int type;
};

struct rr_def {
	const char *name;
	const struct rdata_def *rdata;
	int n_rdata_fields;
};

static struct rdata_def          a_rdata[] = {
	{ "ipv4_address"                , t_bindata }};
static struct rdata_def         ns_rdata[] = {
	{ "nsdname"                     , t_bindata }};
static struct rdata_def         md_rdata[] = {
	{ "madname"                     , t_bindata }};
static struct rdata_def         mf_rdata[] = {
	{ "madname"                     , t_bindata }};
static struct rdata_def      cname_rdata[] = {
	{ "cname"                       , t_bindata }};
static struct rdata_def        soa_rdata[] = {
	{ "mname"                       , t_bindata },
	{ "rname"                       , t_bindata },
	{ "serial"                      , t_int     },
	{ "refresh"                     , t_int     },
	{ "refresh"                     , t_int     },
	{ "retry"                       , t_int     },
	{ "expire"                      , t_int     }};
static struct rdata_def         mb_rdata[] = {
	{ "madname"                     , t_bindata }};
static struct rdata_def         mg_rdata[] = {
	{ "mgmname"                     , t_bindata }};
static struct rdata_def         mr_rdata[] = {
	{ "newname"                     , t_bindata }};
static struct rdata_def       null_rdata[] = {
	{ "anything"                    , t_bindata }};
static struct rdata_def        wks_rdata[] = {
	{ "address"                     , t_bindata },
	{ "protocol"                    , t_int     },
	{ "bitmap"                      , t_bindata }};
static struct rdata_def        ptr_rdata[] = {
	{ "ptrdname"                    , t_bindata }};
static struct rdata_def      hinfo_rdata[] = {
	{ "cpu"                         , t_bindata }};
static struct rdata_def      minfo_rdata[] = {
	{ "rmailbx"                     , t_bindata }};
static struct rdata_def         mx_rdata[] = {
	{ "preference"                  , t_bindata }};
static struct rdata_def        txt_rdata[] = {
	{ "txt_strings"                 , t_list    }};
static struct rdata_def         rp_rdata[] = {
	{ "mbox_dname"                  , t_bindata }};
static struct rdata_def      afsdb_rdata[] = {
	{ "subtype"                     , t_bindata }};
static struct rdata_def        x25_rdata[] = {
	{ "psdn_address"                , t_bindata }};
static struct rdata_def       isdn_rdata[] = {
	{ "isdn_address"                , t_bindata }};
static struct rdata_def         rt_rdata[] = {
	{ "preference"                  , t_bindata }};
static struct rdata_def       nsap_rdata[] = {
	{ "nsap"                        , t_bindata }};
static struct rdata_def        sig_rdata[] = {
	{ "sig_obsolete"                , t_bindata }};
static struct rdata_def        key_rdata[] = {
	{ "key_obsolete"                , t_bindata }};
static struct rdata_def         px_rdata[] = {
	{ "preference"                  , t_int     },
	{ "map822"                      , t_bindata },
	{ "mapx400"                     , t_bindata }};
static struct rdata_def       gpos_rdata[] = {
	{ "longitude"                   , t_bindata },
	{ "latitude"                    , t_bindata },
	{ "altitude"                    , t_bindata }};
static struct rdata_def       aaaa_rdata[] = {
	{ "ipv6_address"                , t_bindata }};
static struct rdata_def        loc_rdata[] = {
	{ "loc_obsolete"                , t_bindata }};
static struct rdata_def        nxt_rdata[] = {
	{ "nxt_obsolete"                , t_bindata }};
static struct rdata_def        eid_rdata[] = {
	{ "eid_unknown"                 , t_bindata }};
static struct rdata_def     nimloc_rdata[] = {
	{ "nimloc_unknown"              , t_bindata }};
static struct rdata_def        srv_rdata[] = {
	{ "priority"                    , t_int     },
	{ "weight"                      , t_int     },
	{ "port"                        , t_int     },
	{ "target"                      , t_bindata }};
static struct rdata_def       atma_rdata[] = {
	{ "format"                      , t_bindata }};
static struct rdata_def      naptr_rdata[] = {
	{ "order"                       , t_int     },
	{ "preference"                  , t_int     },
	{ "flags"                       , t_bindata },
	{ "service"                     , t_bindata },
	{ "regexp"                      , t_bindata },
	{ "replacement"                 , t_bindata }};
static struct rdata_def         kx_rdata[] = {
	{ "preference"                  , t_bindata }};
static struct rdata_def       cert_rdata[] = {
	{ "type"                        , t_int     },
	{ "key_tag"                     , t_int     },
	{ "algorithm"                   , t_int     },
	{ "certificate_or_crl"          , t_bindata }};
static struct rdata_def         a6_rdata[] = {
	{ "a6_obsolete"                 , t_bindata }};
static struct rdata_def      dname_rdata[] = {
	{ "target"                      , t_bindata }};
static struct rdata_def       sink_rdata[] = {
	{ "sink_unknown"                , t_bindata }};
static struct rdata_def        opt_rdata[] = {
	{ "options"                     , t_dict    },
	{ "option_code"                 , t_int     },
	{ "option_data"                 , t_bindata },
	{ "udp_payload_size"            , t_int     },
	{ "extended_rcode"              , t_int     },
	{ "version"                     , t_int     },
	{ "do"                          , t_int     },
	{ "z"                           , t_int     }};
static struct rdata_def        apl_rdata[] = {
	{ "apitems"                     , t_dict    },
	{ "address_family"              , t_int     },
	{ "prefix"                      , t_int     },
	{ "n"                           , t_int     },
	{ "afdpart"                     , t_bindata }};
static struct rdata_def         ds_rdata[] = {
	{ "key_tag"                     , t_int     },
	{ "algorithm"                   , t_int     },
	{ "digest_type"                 , t_int     },
	{ "digest"                      , t_bindata }};
static struct rdata_def      sshfp_rdata[] = {
	{ "algorithm"                   , t_int     },
	{ "fp_type"                     , t_int     },
	{ "fingerprint"                 , t_bindata }};
static struct rdata_def   ipseckey_rdata[] = {
	{ "algorithm"                   , t_int     },
	{ "gateway_type"                , t_int     },
	{ "precedence"                  , t_int     },
	{ "gateway"                     , t_bindata },
	{ "public_key"                  , t_bindata }};
static struct rdata_def      rrsig_rdata[] = {
	{ "type_covered"                , t_int     },
	{ "algorithm"                   , t_int     },
	{ "labels"                      , t_int     },
	{ "original_ttl"                , t_int     },
	{ "signature_expiration"        , t_int     },
	{ "signature_inception"         , t_int     },
	{ "key_tag"                     , t_int     },
	{ "signers_name"                , t_bindata },
	{ "signature"                   , t_bindata }};
static struct rdata_def       nsec_rdata[] = {
	{ "next_domain_name"            , t_bindata }};
static struct rdata_def     dnskey_rdata[] = {
	{ "flags"                       , t_int     },
	{ "protocol"                    , t_int     },
	{ "algorithm"                   , t_int     },
	{ "public_key"                  , t_bindata }};
static struct rdata_def      dhcid_rdata[] = {
	{ "dhcid_opaque"                , t_bindata }};
static struct rdata_def      nsec3_rdata[] = {
	{ "hash_algorithm"              , t_int     },
	{ "flags"                       , t_int     },
	{ "iterations"                  , t_int     },
	{ "salt"                        , t_bindata },
	{ "next_hashed_owner_name"      , t_bindata },
	{ "type_bit_maps"               , t_bindata }};
static struct rdata_def nsec3param_rdata[] = {
	{ "hash_algorithm"              , t_int     },
	{ "flags"                       , t_int     },
	{ "iterations"                  , t_int     },
	{ "salt"                        , t_bindata }};
static struct rdata_def       tlsa_rdata[] = {
	{ "certificate_usage"           , t_int     },
	{ "selector"                    , t_int     },
	{ "matching_type"               , t_int     },
	{ "certificate_association_data", t_bindata }};
static struct rdata_def        hip_rdata[] = {
	{ "pk_algorithm"                , t_int     },
	{ "hit"                         , t_bindata },
	{ "public_key"                  , t_bindata },
	{ "rendezvous_servers"          , t_list    }};
static struct rdata_def      ninfo_rdata[] = {
	{ "ninfo_unknown"               , t_bindata }};
static struct rdata_def       rkey_rdata[] = {
	{ "rkey_unknown"                , t_bindata }};
static struct rdata_def     talink_rdata[] = {
	{ "talink_unknown"              , t_bindata }};
static struct rdata_def        cds_rdata[] = {
	{ "cds_unknown"                 , t_bindata }};
static struct rdata_def        spf_rdata[] = {
	{ "text"                        , t_bindata }};
static struct rdata_def      uinfo_rdata[] = {
	{ "uinfo_unknown"               , t_bindata }};
static struct rdata_def        uid_rdata[] = {
	{ "uid_unknown"                 , t_bindata }};
static struct rdata_def        gid_rdata[] = {
	{ "gid_unknown"                 , t_bindata }};
static struct rdata_def     unspec_rdata[] = {
	{ "unspec_unknown"              , t_bindata }};
static struct rdata_def        nid_rdata[] = {
	{ "preference"                  , t_int     },
	{ "node_id"                     , t_bindata }};
static struct rdata_def        l32_rdata[] = {
	{ "preference"                  , t_int     },
	{ "locator32"                   , t_bindata }};
static struct rdata_def        l64_rdata[] = {
	{ "preference"                  , t_int     },
	{ "locator64"                   , t_bindata }};
static struct rdata_def         lp_rdata[] = {
	{ "preference"                  , t_int     },
	{ "fqdn"                        , t_bindata }};
static struct rdata_def      eui48_rdata[] = {
	{ "eui48_address"               , t_bindata }};
static struct rdata_def      eui64_rdata[] = {
	{ "eui64_address"               , t_bindata }};
static struct rdata_def       tkey_rdata[] = {
	{ "algorithm"                   , t_bindata },
	{ "inception"                   , t_int     },
	{ "expiration"                  , t_int     },
	{ "mode"                        , t_int     },
	{ "error"                       , t_int     },
	{ "key_data"                    , t_bindata },
	{ "other_data"                  , t_bindata }};
static struct rdata_def       tsig_rdata[] = {
	{ "algorithm"                   , t_bindata },
	{ "time_signed"                 , t_bindata },
	{ "fudge"                       , t_int     },
	{ "mac"                         , t_bindata },
	{ "original_id"                 , t_int     },
	{ "error"                       , t_int     },
	{ "other_data"                  , t_bindata }};
static struct rdata_def      mailb_rdata[] = {
	{ "mailb_unknown"               , t_bindata }};
static struct rdata_def      maila_rdata[] = {
	{ "maila_unknown"               , t_bindata }};
static struct rdata_def        uri_rdata[] = {
	{ "priority"                    , t_int     },
	{ "weight"                      , t_int     },
	{ "target"                      , t_bindata }};
static struct rdata_def        caa_rdata[] = {
	{ "flags"                       , t_int     },
	{ "tag"                         , t_bindata },
	{ "value"                       , t_bindata }};
static struct rdata_def         ta_rdata[] = {
	{ "ta_unknown"                  , t_bindata }};
static struct rdata_def        dlv_rdata[] = {
	{ "key_tag"                     , t_int     },
	{ "algorithm"                   , t_int     },
	{ "digest_type"                 , t_int     },
	{ "digest"                      , t_bindata }};

static struct rr_def rr_defs[] = {
	{         NULL,             NULL, 0                      },
	{          "A",          a_rdata, ALEN(         a_rdata) }, /* 1 - */
	{         "NS",         ns_rdata, ALEN(        ns_rdata) },
	{         "MD",         md_rdata, ALEN(        md_rdata) },
	{         "MF",         mf_rdata, ALEN(        mf_rdata) },
	{      "CNAME",      cname_rdata, ALEN(     cname_rdata) },
	{        "SOA",        soa_rdata, ALEN(       soa_rdata) },
	{         "MB",         mb_rdata, ALEN(        mb_rdata) },
	{         "MG",         mg_rdata, ALEN(        mg_rdata) },
	{         "MR",         mr_rdata, ALEN(        mr_rdata) },
	{       "NULL",       null_rdata, ALEN(      null_rdata) },
	{        "WKS",        wks_rdata, ALEN(       wks_rdata) },
	{        "PTR",        ptr_rdata, ALEN(       ptr_rdata) },
	{      "HINFO",      hinfo_rdata, ALEN(     hinfo_rdata) },
	{      "MINFO",      minfo_rdata, ALEN(     minfo_rdata) },
	{         "MX",         mx_rdata, ALEN(        mx_rdata) },
	{        "TXT",        txt_rdata, ALEN(       txt_rdata) },
	{         "RP",         rp_rdata, ALEN(        rp_rdata) },
	{      "AFSDB",      afsdb_rdata, ALEN(     afsdb_rdata) },
	{        "X25",        x25_rdata, ALEN(       x25_rdata) },
	{       "ISDN",       isdn_rdata, ALEN(      isdn_rdata) },
	{         "RT",         rt_rdata, ALEN(        rt_rdata) },
	{       "NSAP",       nsap_rdata, ALEN(      nsap_rdata) }, /* - 22 */
	{         NULL,             NULL, 0                      },
	{        "SIG",        sig_rdata, ALEN(       sig_rdata) }, /* 24 - */
	{        "KEY",        key_rdata, ALEN(       key_rdata) },
	{         "PX",         px_rdata, ALEN(        px_rdata) },
	{       "GPOS",       gpos_rdata, ALEN(      gpos_rdata) },
	{       "AAAA",       aaaa_rdata, ALEN(      aaaa_rdata) },
	{        "LOC",        loc_rdata, ALEN(       loc_rdata) },
	{        "NXT",        nxt_rdata, ALEN(       nxt_rdata) },
	{        "EID",        eid_rdata, ALEN(       eid_rdata) },
	{     "NIMLOC",     nimloc_rdata, ALEN(    nimloc_rdata) },
	{        "SRV",        srv_rdata, ALEN(       srv_rdata) },
	{       "ATMA",       atma_rdata, ALEN(      atma_rdata) },
	{      "NAPTR",      naptr_rdata, ALEN(     naptr_rdata) },
	{         "KX",         kx_rdata, ALEN(        kx_rdata) },
	{       "CERT",       cert_rdata, ALEN(      cert_rdata) },
	{         "A6",         a6_rdata, ALEN(        a6_rdata) },
	{      "DNAME",      dname_rdata, ALEN(     dname_rdata) },
	{       "SINK",       sink_rdata, ALEN(      sink_rdata) },
	{        "OPT",        opt_rdata, ALEN(       opt_rdata) },
	{        "APL",        apl_rdata, ALEN(       apl_rdata) },
	{         "DS",         ds_rdata, ALEN(        ds_rdata) },
	{      "SSHFP",      sshfp_rdata, ALEN(     sshfp_rdata) },
	{   "IPSECKEY",   ipseckey_rdata, ALEN(  ipseckey_rdata) },
	{      "RRSIG",      rrsig_rdata, ALEN(     rrsig_rdata) },
	{       "NSEC",       nsec_rdata, ALEN(      nsec_rdata) },
	{     "DNSKEY",     dnskey_rdata, ALEN(    dnskey_rdata) },
	{      "DHCID",      dhcid_rdata, ALEN(     dhcid_rdata) },
	{      "NSEC3",      nsec3_rdata, ALEN(     nsec3_rdata) },
	{ "NSEC3PARAM", nsec3param_rdata, ALEN(nsec3param_rdata) },
	{       "TLSA",       tlsa_rdata, ALEN(      tlsa_rdata) }, /* - 52 */
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{        "HIP",        hip_rdata, ALEN(       hip_rdata) }, /* 55 - */
	{      "NINFO",      ninfo_rdata, ALEN(     ninfo_rdata) },
	{       "RKEY",       rkey_rdata, ALEN(      rkey_rdata) },
	{     "TALINK",     talink_rdata, ALEN(    talink_rdata) },
	{        "CDS",        cds_rdata, ALEN(       cds_rdata) }, /* - 59 */
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{        "SPF",        spf_rdata, ALEN(       spf_rdata) }, /* 99 - */
	{      "UINFO",      uinfo_rdata, ALEN(     uinfo_rdata) },
	{        "UID",        uid_rdata, ALEN(       uid_rdata) },
	{        "GID",        gid_rdata, ALEN(       gid_rdata) },
	{     "UNSPEC",     unspec_rdata, ALEN(    unspec_rdata) },
	{        "NID",        nid_rdata, ALEN(       nid_rdata) },
	{        "L32",        l32_rdata, ALEN(       l32_rdata) },
	{        "L64",        l64_rdata, ALEN(       l64_rdata) },
	{         "LP",         lp_rdata, ALEN(        lp_rdata) },
	{      "EUI48",      eui48_rdata, ALEN(     eui48_rdata) },
	{      "EUI64",      eui64_rdata, ALEN(     eui64_rdata) }, /* - 109 */
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{       "TKEY",       tkey_rdata, ALEN(      tkey_rdata) }, /* 249 - */
	{       "TSIG",       tsig_rdata, ALEN(      tsig_rdata) }, /* - 250 */
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{      "MAILB",      mailb_rdata, ALEN(     mailb_rdata) }, /* 253 - */
	{      "MAILA",      maila_rdata, ALEN(     maila_rdata) }, /* - 254 */
	{         NULL,             NULL, 0                      },
	{        "URI",        uri_rdata, ALEN(       uri_rdata) }, /* 256 - */
	{        "CAA",        caa_rdata, ALEN(       caa_rdata) }, /* - 257 */
	{         "TA",         ta_rdata, ALEN(        ta_rdata) }, /* 32768 */
	{        "DLV",        dlv_rdata, ALEN(       dlv_rdata) }  /* 32769 */
};

static const struct rr_def *
rr_def_lookup(uint16_t rr_type)
{
	if (rr_type <= 257)
		return &rr_defs[rr_type];
	else if (rr_type == 32768)
		return &rr_defs[258];
	else if (rr_type == 32769)
		return &rr_defs[259];
	return rr_defs;
}

const char *
priv_getdns_rr_type_name(int rr_type)
{
	return rr_def_lookup(rr_type)->name;
}

/* list of txt records */
static getdns_return_t
priv_getdns_equip_dict_with_txt_rdfs(struct getdns_dict* rdata, ldns_rr* rr,
                                     const struct rr_def* def,
                                     struct getdns_context* context) {
    size_t i;
    struct getdns_bindata bindata;
    uint8_t buffer[LDNS_MAX_RDFLEN];
    getdns_return_t r = GETDNS_RETURN_GOOD;
    struct getdns_list* records = getdns_list_create_with_context(context);
    if (!records) {
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    for (i = 0; i < ldns_rr_rd_count(rr) && r == GETDNS_RETURN_GOOD; ++i) {
        ldns_rdf* rdf = ldns_rr_rdf(rr, i);
        int rdf_size = (int) ldns_rdf_size(rdf);
        uint8_t* rdf_data = ldns_rdf_data(rdf);
        if (rdf_size < 1) {
            r = GETDNS_RETURN_GENERIC_ERROR;
            continue;
        }
        int txt_size = (int) rdf_data[0];
        if (rdf_size < txt_size) {
            r = GETDNS_RETURN_GENERIC_ERROR;
            continue;
        }
        bindata.size = txt_size + 1;
        memcpy(buffer, rdf_data + 1, txt_size);
        buffer[txt_size] = 0;
        bindata.data = buffer;

        r = getdns_list_set_bindata(records, i, &bindata);
    }
    if (r == GETDNS_RETURN_GOOD) {
        r = getdns_dict_set_list(rdata, def->rdata[0].name, records);
    }
    getdns_list_destroy(records);
    return r;
}

/* heavily borrowed/copied from ldns 1.6.17 */
static
getdns_return_t getdns_rdf_hip_get_alg_hit_pk(ldns_rdf *rdf, uint8_t* alg,
                                              struct getdns_bindata* hit,
                                              struct getdns_bindata* pk)
{
    uint8_t *data;
    size_t rdf_size;

    if ((rdf_size = ldns_rdf_size(rdf)) < 6) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    data = ldns_rdf_data(rdf);
    hit->size = data[0];
    *alg      = data[1];
    pk->size  = ldns_read_uint16(data + 2);
    hit->data      = data + 4;
    pk->data       = data + 4 + hit->size;
    if (hit->size == 0 || pk->size == 0 ||
        rdf_size < (size_t) hit->size + pk->size + 4) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
priv_getdns_equip_dict_with_hip_rdfs(struct getdns_dict* rdata, ldns_rr* rr,
                                     const struct rr_def* def,
                                     struct getdns_context* context) {
    uint8_t alg;
    getdns_return_t r;
    struct getdns_bindata hit_data;
    struct getdns_bindata key_data;
    /* first rdf contains the key data */
    ldns_rdf* rdf = ldns_rr_rdf(rr, 0);
    /* ask LDNS to parse it for us */
    r = getdns_rdf_hip_get_alg_hit_pk(rdf, &alg, &hit_data, &key_data);
    if (r != GETDNS_RETURN_GOOD) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }

    r = getdns_dict_set_int(rdata, def->rdata[0].name, alg);
    r |= getdns_dict_set_bindata(rdata, def->rdata[1].name, &hit_data);
    r |= getdns_dict_set_bindata(rdata, def->rdata[2].name, &key_data);
    if (r != GETDNS_RETURN_GOOD) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }

    if (ldns_rr_rd_count(rr) > 1) {
        /* servers */
        size_t i;
        struct getdns_bindata server_data;
        struct getdns_list* servers = getdns_list_create_with_context(context);
        if (!servers) {
            return GETDNS_RETURN_MEMORY_ERROR;
        }
        for (i = 1; i < ldns_rr_rd_count(rr) && r == GETDNS_RETURN_GOOD; ++i) {
            ldns_rdf* server_rdf = ldns_rr_rdf(rr, i);
            server_data.size = ldns_rdf_size(server_rdf);
            server_data.data = ldns_rdf_data(server_rdf);
            r = getdns_list_set_bindata(servers, i - 1, &server_data);
        }
        if (r == GETDNS_RETURN_GOOD) {
            r = getdns_dict_set_list(rdata, def->rdata[3].name, servers);
        }
        /* always clean up */
        getdns_list_destroy(servers);
        if (r != GETDNS_RETURN_GOOD) {
        	return GETDNS_RETURN_GENERIC_ERROR;
        }
    }

    return r;
}

static getdns_return_t
priv_append_apl_record(struct getdns_list* records, ldns_rdf* rdf,
                       const struct rr_def* def, struct getdns_context* context) {
    getdns_return_t r = GETDNS_RETURN_GOOD;
    uint8_t* data;
    size_t size;
    uint16_t family;
    uint8_t prefix;
    uint8_t negation;
    size_t addr_len;
    size_t pos = 0;
    size_t index = 0;
    struct getdns_bindata addr_data;

    if (ldns_rdf_get_type(rdf) != LDNS_RDF_TYPE_APL) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    getdns_list_get_length(records, &index);

    data = ldns_rdf_data(rdf);
    size = ldns_rdf_size(rdf);
    if (size < 4) {
        /* not enough for the fam, prefix, n, and data len */
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    while (pos < size && r == GETDNS_RETURN_GOOD) {
        struct getdns_dict* apl_dict;
        family = ldns_read_uint16(data + pos);
        prefix = data[pos + 2];
        negation = (data[pos + 3] & 0x80) > 1 ? 1 : 0;
        addr_len = data[pos + 3] & 0x7F;
        if (size < 4 + addr_len) {
            /* not enough.. */
            return GETDNS_RETURN_GENERIC_ERROR;
        }
        addr_data.size = addr_len;
        addr_data.data = data + 4 + pos;

        /* add to a dictionary */
        apl_dict = getdns_dict_create_with_context(context);
        if (!apl_dict) {
            /* memory fail */
            return GETDNS_RETURN_MEMORY_ERROR;
        }
        r |= getdns_dict_set_int(apl_dict, def->rdata[1].name, family);
        r |= getdns_dict_set_int(apl_dict, def->rdata[2].name, prefix);
        r |= getdns_dict_set_int(apl_dict, def->rdata[3].name, negation);
        r |= getdns_dict_set_bindata(apl_dict, def->rdata[4].name, &addr_data);

        if (r == GETDNS_RETURN_GOOD) {
            r = getdns_list_set_dict(records, index, apl_dict);
        }
        pos += addr_data.size + 4;
        ++index;
        /* always clean up */
        getdns_dict_destroy(apl_dict);
    }

    return r;
}

static getdns_return_t
priv_getdns_equip_dict_with_apl_rdfs(struct getdns_dict* rdata, ldns_rr* rr,
                                     const struct rr_def* def,
                                     struct getdns_context* context) {
    size_t i;
    getdns_return_t r = GETDNS_RETURN_GOOD;
    struct getdns_list* records = getdns_list_create_with_context(context);
    if (!records) {
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    for (i = 0; i < ldns_rr_rd_count(rr) && r == GETDNS_RETURN_GOOD; ++i) {
        r = priv_append_apl_record(records, ldns_rr_rdf(rr, i),
                                   def, context);
    }
    if (r == GETDNS_RETURN_GOOD) {
        getdns_dict_set_list(rdata, def->rdata[0].name, records);
    }
    getdns_list_destroy(records);

    return GETDNS_RETURN_GOOD;
}

static getdns_return_t
priv_getdns_equip_dict_with_spf_rdfs(struct getdns_dict* rdata, ldns_rr* rr,
                                     const struct rr_def* def,
                                     struct getdns_context* context) {
    size_t i;
    struct getdns_bindata bindata;
    getdns_return_t r = GETDNS_RETURN_GOOD;
    int num_copied = 0;
    bindata.size = 0;
    /* one giant bindata */
    /* validate and calculate size */
    for (i = 0; i < ldns_rr_rd_count(rr) && r == GETDNS_RETURN_GOOD; ++i) {
        ldns_rdf* rdf = ldns_rr_rdf(rr, i);
        int rdf_size = (int) ldns_rdf_size(rdf);
        uint8_t* rdf_data = ldns_rdf_data(rdf);
        if (rdf_size < 1) {
            r = GETDNS_RETURN_GENERIC_ERROR;
            continue;
        }
        /* txt size without null byte */
        int txt_size = (int) rdf_data[0];
        if (rdf_size < txt_size) {
            r = GETDNS_RETURN_GENERIC_ERROR;
            continue;
        }
        bindata.size += txt_size;
    }
    /* add one for the null byte */
    bindata.size++;

    if (r != GETDNS_RETURN_GOOD) {
        /* validations failed */
        return r;
    }
	bindata.data = context
	    ? GETDNS_XMALLOC(context->my_mf, uint8_t, bindata.size)
	    : malloc(bindata.size);
    if (!bindata.data) {
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    /* copy in */
    for (i = 0; i < ldns_rr_rd_count(rr) && r == GETDNS_RETURN_GOOD; ++i) {
        ldns_rdf* rdf = ldns_rr_rdf(rr, i);
        /* safe to trust these now */
        uint8_t* rdf_data = ldns_rdf_data(rdf);
        int txt_size = (int) rdf_data[0];
        memcpy(bindata.data + num_copied, rdf_data + 1, txt_size);
        num_copied += txt_size;
    }
    bindata.data[num_copied] = 0;
    r = getdns_dict_set_bindata(rdata, def->rdata[0].name, &bindata);
	if (context)
		GETDNS_FREE(context->my_mf, bindata.data);
	else
		free(bindata.data);
    return r;
}


static getdns_return_t
priv_getdns_equip_dict_with_rdfs(struct getdns_dict *rdata, ldns_rr *rr,
                                 struct getdns_context* context)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	const struct rr_def *def;
	struct getdns_bindata bindata;
	size_t i;
	int intval;

	assert(rdata);
	assert(rr);

	def = rr_def_lookup(ldns_rr_get_type(rr));
    /* specialty handlers */
    /* TODO: convert generic one into function w/ similar signature and store in the
     * def? */
    if (def->rdata == txt_rdata) {
        return priv_getdns_equip_dict_with_txt_rdfs(rdata, rr, def, context);
    } else if (def->rdata == hip_rdata) {
        return priv_getdns_equip_dict_with_hip_rdfs(rdata, rr, def, context);
    } else if (def->rdata == apl_rdata) {
        return priv_getdns_equip_dict_with_apl_rdfs(rdata, rr, def, context);
    } else if (def->rdata == spf_rdata) {
        return priv_getdns_equip_dict_with_spf_rdfs(rdata, rr, def, context);
    }
    /* generic */
	for (i = 0; i < ldns_rr_rd_count(rr) && r == GETDNS_RETURN_GOOD; i++) {
		if (i >= def->n_rdata_fields)
			break;

		switch (def->rdata[i].type) {
		case t_bindata: bindata.size = ldns_rdf_size(ldns_rr_rdf(rr, i));
		                bindata.data = ldns_rdf_data(ldns_rr_rdf(rr, i));
		                r = getdns_dict_set_bindata(
				    rdata, (char *)def->rdata[i].name, &bindata);
				break;
		case t_int    : switch (ldns_rdf_size(ldns_rr_rdf(rr, i))) {
				case  1: intval = (uint8_t)*ldns_rdf_data(
				             ldns_rr_rdf(rr, i));
					 break;
				case  2: intval = ldns_read_uint16(
				             ldns_rdf_data(ldns_rr_rdf(rr, i)));
				         break;
				case  4: intval = ldns_read_uint32(
				             ldns_rdf_data(ldns_rr_rdf(rr, i)));
					 break;
				default: intval = -1;
				         /* TODO Compare with LDNS rdf types */
					 break;
		                }
		                r = getdns_dict_set_int(
				    rdata, (char *)def->rdata[i].name, intval);
				break;
		default       : break;
		}
	}
	return r;
}

static getdns_return_t
priv_getdns_create_dict_from_rdfs(
    struct getdns_context *context, ldns_rr *rr, struct getdns_dict** rdata)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	struct getdns_bindata rdata_raw;
	uint8_t *data_ptr;
	size_t i;

	assert(rr);
	assert(rdata);

	*rdata = getdns_dict_create_with_context(context);
	if (! *rdata)
		return GETDNS_RETURN_MEMORY_ERROR;
	do { /* break on error (to cleanup *rdata) */

		/* Count and reserve "raw" rdata space */
		rdata_raw.size = 0;
		for (i = 0; i < ldns_rr_rd_count(rr); i++)
			rdata_raw.size += ldns_rdf_size(ldns_rr_rdf(rr, i));
		rdata_raw.data = context
		    ? GETDNS_XMALLOC(context->mf, uint8_t, rdata_raw.size)
		    : malloc(rdata_raw.size);
		if (! rdata_raw.data) {
			r = GETDNS_RETURN_MEMORY_ERROR;
			break;
		}
		/* Copy rdata fields to rdata space */
		data_ptr = rdata_raw.data;
		for (i = 0; i < ldns_rr_rd_count(rr); i++) {
			(void) memcpy(data_ptr,
			    ldns_rdf_data(ldns_rr_rdf(rr, i)),
			    ldns_rdf_size(ldns_rr_rdf(rr, i)));
			data_ptr += ldns_rdf_size(ldns_rr_rdf(rr, i));
		}

		/* Set "rdata_raw" attribute" */
		r = getdns_dict_set_bindata(*rdata, "rdata_raw", &rdata_raw);
		if (context)
			GETDNS_FREE(context->mf, rdata_raw.data);
		else
			free(rdata_raw.data);
		if (r != GETDNS_RETURN_GOOD)
			break;

		/* Now set the RR type specific attributes */
		r = priv_getdns_equip_dict_with_rdfs(*rdata, rr, context);
		if (r == GETDNS_RETURN_GOOD)
			return r;
	} while(0);
	getdns_dict_destroy(*rdata);
	return r;
}

getdns_return_t
priv_getdns_create_dict_from_rr(
    struct getdns_context *context, ldns_rr *rr, struct getdns_dict** rr_dict)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	struct getdns_bindata name;
	struct getdns_dict *rdata;

	assert(rr);
	assert(rr_dict);

	*rr_dict = getdns_dict_create_with_context(context);
	if (! *rr_dict)
		return GETDNS_RETURN_MEMORY_ERROR;
	do { /* break on error (to cleanup *rr_dict) */
		r = getdns_dict_set_int(*rr_dict,
		    "type", ldns_rr_get_type(rr));
		if (r != GETDNS_RETURN_GOOD)
			break;
		r = getdns_dict_set_int(*rr_dict,
		    "class", ldns_rr_get_class(rr));
		if (r != GETDNS_RETURN_GOOD)
			break;
		r = getdns_dict_set_int(*rr_dict, "ttl", ldns_rr_ttl(rr));
		if (r != GETDNS_RETURN_GOOD)
			break;

		/* "name" attribute.
		 * ldns_rr_owner(rr) is already uncompressed!
		 */
		name.size = ldns_rdf_size(ldns_rr_owner(rr));
		name.data = ldns_rdf_data(ldns_rr_owner(rr));
		r = getdns_dict_set_bindata(*rr_dict, "name", &name);
		if (r != GETDNS_RETURN_GOOD)
			break;

		/* The "rdata" dict... copies of copies of copies :( */
		r = priv_getdns_create_dict_from_rdfs(context, rr, &rdata);
		if (r != GETDNS_RETURN_GOOD)
			break;
		r = getdns_dict_set_dict(*rr_dict, "rdata", rdata);
		getdns_dict_destroy(rdata);
		if (r == GETDNS_RETURN_GOOD)
			return r;
	} while (0);
	getdns_dict_destroy(*rr_dict);
	return r;
}

getdns_return_t
priv_getdns_create_reply_question_dict(
    struct getdns_context *context, ldns_pkt *pkt, struct getdns_dict** q_dict)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	ldns_rr *rr;
	struct getdns_bindata qname;

	assert(pkt);
	assert(q_dict);

       	rr = ldns_rr_list_rr(ldns_pkt_question(pkt), 0);
	if (! rr)
		return GETDNS_RETURN_GENERIC_ERROR;

	*q_dict = getdns_dict_create_with_context(context);
	if (! *q_dict)
		return GETDNS_RETURN_MEMORY_ERROR;
	do { /* break on error (to cleanup *q_dict) */
		r = getdns_dict_set_int(*q_dict,
		    "qtype", ldns_rr_get_type(rr));
		if (r != GETDNS_RETURN_GOOD)
			break;
		r = getdns_dict_set_int(*q_dict,
		    "qclass", ldns_rr_get_class(rr));
		if (r != GETDNS_RETURN_GOOD)
			break;

		/* "qname" attribute.
		 * ldns_rr_owner(rr) is already uncompressed!
		 */
		qname.size = ldns_rdf_size(ldns_rr_owner(rr));
		qname.data = ldns_rdf_data(ldns_rr_owner(rr));
		r = getdns_dict_set_bindata(*q_dict, "qname", &qname);
		if (r == GETDNS_RETURN_GOOD)
			return r;
	} while (0);
	getdns_dict_destroy(*q_dict);
	return r;
}

static getdns_return_t priv_getdns_construct_wire_rdata_from_rdata(
    struct getdns_dict *rdata, uint32_t rr_type,
    uint8_t **wire, size_t *wire_size)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	const ldns_rr_descriptor *rr_descript;
	const struct rr_def *def;
	size_t i, size;
	struct getdns_bindata *bindata;
	uint32_t value;
	uint8_t *ptr;

	assert(rdata);
	assert(wire);
	assert(wire_size);

	def = rr_def_lookup(rr_type);
	rr_descript = ldns_rr_descript(rr_type);

	/* First calculate needed size */
	size = 0;
	for (i = 0; i < def->n_rdata_fields && r == GETDNS_RETURN_GOOD; i++) {
		switch (def->rdata[i].type) {
		case t_bindata: r = getdns_dict_get_bindata(rdata,
				    def->rdata[i].name, &bindata);
				if (r)
					break;
				size += bindata->size;
				break;
		case t_int    : switch (ldns_rr_descriptor_field_type(
				        rr_descript, i)) {

				case LDNS_RDF_TYPE_CLASS:
				case LDNS_RDF_TYPE_ALG  :
				case LDNS_RDF_TYPE_INT8 : size += 1;
							  break;
				case LDNS_RDF_TYPE_TYPE :
				case LDNS_RDF_TYPE_CERT_ALG:
				case LDNS_RDF_TYPE_INT16: size += 2;
							  break;
				case LDNS_RDF_TYPE_TIME :
				case LDNS_RDF_TYPE_PERIOD:
				case LDNS_RDF_TYPE_INT32: size += 4;
							  break;
				default: r = GETDNS_RETURN_GENERIC_ERROR;
				         break;
				}
				break;
		default       : r = GETDNS_RETURN_GENERIC_ERROR;
				break;
		}
	}
	*wire_size = size + 2;
	*wire = ptr = GETDNS_XMALLOC(rdata->mf, uint8_t, size + 2);
	if (! ptr)
		return GETDNS_RETURN_MEMORY_ERROR;

	ptr[0] = (uint8_t) (size >> 8) & 0xff;
	ptr[1] = (uint8_t)  size       & 0xff;
	ptr += 2;
	for (i = 0; i < def->n_rdata_fields && r == GETDNS_RETURN_GOOD; i++) {
		switch (def->rdata[i].type) {
		case t_bindata: r = getdns_dict_get_bindata(rdata,
				    def->rdata[i].name, &bindata);
				if (r)
					break;
				(void) memcpy(ptr, bindata->data,
				                   bindata->size);
				ptr += bindata->size;
				break;
		case t_int    : r = getdns_dict_get_int(rdata,
				    def->rdata[i].name, &value);
				if (r)
					break;

				switch (ldns_rr_descriptor_field_type(
				        rr_descript, i)) {

				case LDNS_RDF_TYPE_CLASS:
				case LDNS_RDF_TYPE_ALG  :
				case LDNS_RDF_TYPE_INT8 : ptr[0] = (uint8_t)
							      value & 0xff;
				                          ptr += 1;
							  break;
				case LDNS_RDF_TYPE_TYPE :
				case LDNS_RDF_TYPE_CERT_ALG:
				case LDNS_RDF_TYPE_INT16: ptr[0] = (uint8_t)
							      (value>>8)&0xff;
							  ptr[1] = (uint8_t)
							      value & 0xff;
							  ptr += 2;
							  break;
				case LDNS_RDF_TYPE_TIME :
				case LDNS_RDF_TYPE_PERIOD:
				case LDNS_RDF_TYPE_INT32: ptr[0] = (uint8_t)
							      (value>>24)&0xff;
							  ptr[1] = (uint8_t)
							      (value>>16)&0xff;
							  ptr[2] = (uint8_t)
							      (value>>8)&0xff;
							  ptr[3] = (uint8_t)
							      value & 0xff;
							  ptr += 4;
							  break;
				default: r = GETDNS_RETURN_GENERIC_ERROR;
				         break;
				}
				break;
		default       : r = GETDNS_RETURN_GENERIC_ERROR;
				break;
		}
	}
	if (r)
		GETDNS_FREE(rdata->mf, ptr);
	return r;
}

static getdns_return_t
priv_getdns_dict_get_raw_rdata(struct getdns_dict *rdata,
    uint8_t **wire, size_t *wire_size)
{
	getdns_return_t r;
	struct getdns_bindata *bindata;

	if ((r = getdns_dict_get_bindata(rdata, "rdata_raw", &bindata)))
		return r;

	*wire_size = bindata->size + 2;
	*wire = GETDNS_XMALLOC(rdata->mf, uint8_t, *wire_size);
	if (! *wire)
		return GETDNS_RETURN_MEMORY_ERROR;

	(*wire)[0] = (uint8_t) (bindata->size >> 8) & 0xff;
	(*wire)[1] = (uint8_t)  bindata->size       & 0xff;

	(void) memcpy(*wire + 2, bindata->data, bindata->size);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
priv_getdns_create_rr_from_dict(struct getdns_dict *rr_dict, ldns_rr **rr)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	struct getdns_bindata *name;
	struct getdns_dict *rdata;
	uint32_t rr_type;
	ldns_rdf *owner;
	ldns_status s;
	size_t pos;
	uint8_t *wire;
	size_t wire_size;

	assert(rr_dict);
	assert(rr);

	*rr = ldns_rr_new();
	if (! *rr)
		return GETDNS_RETURN_MEMORY_ERROR;
	do {
		r = getdns_dict_get_bindata(rr_dict, "name", &name);
		if (r != GETDNS_RETURN_GOOD)
			break;
		owner = ldns_rdf_new_frm_data(
		    LDNS_RDF_TYPE_DNAME, name->size, name->data);
		if (! owner) {
			r = GETDNS_RETURN_MEMORY_ERROR;
			break;
		}
		ldns_rr_set_owner(*rr, owner);

		r = getdns_dict_get_int(rr_dict, "type", &rr_type);
		if (r != GETDNS_RETURN_GOOD)
			break;
		ldns_rr_set_type(*rr, rr_type);

		r = getdns_dict_get_dict(rr_dict, "rdata", &rdata);
		if (r != GETDNS_RETURN_GOOD)
			break;

		r = priv_getdns_dict_get_raw_rdata(rdata, &wire, &wire_size);
		if (r == GETDNS_RETURN_NO_SUCH_DICT_NAME) {
			r = priv_getdns_construct_wire_rdata_from_rdata(
			    rdata, rr_type, &wire, &wire_size);
		}
		if (r != GETDNS_RETURN_GOOD)
			break;
		pos = 0;
		s = ldns_wire2rdf(*rr, wire, wire_size, &pos);
		GETDNS_FREE(rr_dict->mf, wire);
		if (s == LDNS_STATUS_OK)
			return r;
		r = GETDNS_RETURN_GENERIC_ERROR;
	} while (0);
	ldns_rr_free(*rr);
	return r;
}

static  getdns_return_t
priv_getdns_get_opt_dict(struct getdns_context* context,
    struct getdns_dict** record_dict, uint8_t* record_start,
    size_t* bytes_remaining, size_t* bytes_parsed) {

    getdns_return_t r = GETDNS_RETURN_GOOD;
    struct getdns_dict* opt = NULL;
    uint16_t code;
    struct getdns_bindata opt_data;
    if (*bytes_remaining < 4) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    code = ldns_read_uint16(record_start);
    opt_data.size = ldns_read_uint16(record_start + 2);
    if (*bytes_remaining < (4 + opt_data.size)) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    opt = getdns_dict_create_with_context(context);
    if (!opt) {
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    /* set code */
    r = getdns_dict_set_int(opt, opt_rdata[1].name, code);
    if (r != GETDNS_RETURN_GOOD) {
        getdns_dict_destroy(opt);
        return r;
    }
    /* set data */
    opt_data.data = record_start + 4;
    getdns_dict_set_bindata(opt, opt_rdata[2].name, &opt_data);
    if (r != GETDNS_RETURN_GOOD) {
        getdns_dict_destroy(opt);
        return r;
    }
    /* set result data */
    *bytes_remaining = *bytes_remaining - (4 + opt_data.size);
    *bytes_parsed = *bytes_parsed + (4 + opt_data.size);
    *record_dict = opt;
    return r;
}

static getdns_return_t
priv_getdns_create_opt_rr(
    struct getdns_context *context, ldns_rdf* rdf,
    struct getdns_dict** rr_dict) {

    struct getdns_dict* result = NULL;
    getdns_return_t r = GETDNS_RETURN_GOOD;
    size_t bytes_remaining = ldns_rdf_size(rdf);
    size_t bytes_parsed = 0;
    uint8_t* record_start = ldns_rdf_data(rdf);
    struct getdns_list* records = getdns_list_create_with_context(context);
    size_t idx = 0;
    if (!records) {
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    while (r == GETDNS_RETURN_GOOD && bytes_remaining > 0) {
        struct getdns_dict* opt = NULL;
        r = priv_getdns_get_opt_dict(context, &opt,
                record_start + bytes_parsed, &bytes_remaining,
                &bytes_parsed);
        if (r == GETDNS_RETURN_GOOD) {
            getdns_list_set_dict(records, idx, opt);
            getdns_dict_destroy(opt);
            idx++;
        }
    }
    if (r != GETDNS_RETURN_GOOD) {
        getdns_list_destroy(records);
        return r;
    }
    result = getdns_dict_create_with_context(context);
    if (!result) {
        getdns_list_destroy(records);
        return GETDNS_RETURN_MEMORY_ERROR;
    }
    /* cheat */
    r = 0;
    r |= getdns_dict_set_list(result,
            opt_rdata[0].name, records);
    getdns_list_destroy(records);

    /* does class makes sense? */
    if (r != GETDNS_RETURN_GOOD) {
        getdns_dict_destroy(result);
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    *rr_dict = result;
    return r;
}

getdns_return_t priv_getdns_append_opt_rr(
    struct getdns_context *context, struct getdns_list* rdatas, ldns_pkt* pkt) {
    struct getdns_dict* opt_rr;
    struct getdns_dict* rr_dict;
    getdns_return_t r = 0;
    struct getdns_bindata rdata;
    ldns_rdf* edns_data = ldns_pkt_edns_data(pkt);
    uint8_t rdata_buf[65536];
    size_t list_len;
    if (!edns_data) {
        /* nothing to do */
        return GETDNS_RETURN_GOOD;
    }
    r = getdns_list_get_length(rdatas, &list_len);
    if (r != GETDNS_RETURN_GOOD) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    r = priv_getdns_create_opt_rr(context, edns_data,
        &opt_rr);
    if (r != GETDNS_RETURN_GOOD) {
        return r;
    }
    /* size is: 0 label, 2 byte type, 2 byte class (size),
                4 byte ttl, 2 byte opt len + data itself */
    rdata.size = 11 + ldns_rdf_size(edns_data);
    rdata.data = rdata_buf;
    rdata_buf[0] = 0;
    ldns_write_uint16(rdata_buf + 1, LDNS_RR_TYPE_OPT);
    ldns_write_uint16(rdata_buf + 3, ldns_pkt_edns_udp_size(pkt));
    rdata_buf[5] = ldns_pkt_edns_extended_rcode(pkt);
    rdata_buf[6] = ldns_pkt_edns_version(pkt);
    ldns_write_uint16(rdata_buf + 7, ldns_pkt_edns_z(pkt));
    ldns_write_uint16(rdata_buf + 9, ldns_rdf_size(edns_data));
    memcpy(rdata_buf + 11, ldns_rdf_data(edns_data), ldns_rdf_size(edns_data));

    /* add data */
    r |= getdns_dict_set_bindata(opt_rr, "rdata_raw", &rdata);
    if (r != GETDNS_RETURN_GOOD) {
        getdns_dict_destroy(opt_rr);
        return GETDNS_RETURN_GENERIC_ERROR;
    }

    rr_dict = getdns_dict_create_with_context(context);
    if (!rr_dict) {
        getdns_dict_destroy(opt_rr);
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    r = getdns_dict_set_dict(rr_dict, "rdata", opt_rr);
    getdns_dict_destroy(opt_rr);
    if (r != GETDNS_RETURN_GOOD) {
        getdns_dict_destroy(rr_dict);
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    /* add rest of the fields */
    r = getdns_dict_set_int(rr_dict, "type", GETDNS_RRTYPE_OPT);
    r |= getdns_dict_set_int(rr_dict, "udp_payload_size", ldns_pkt_edns_udp_size(pkt));
    r |= getdns_dict_set_int(rr_dict, "extended_rcode", ldns_pkt_edns_extended_rcode(pkt));
	r |= getdns_dict_set_int(rr_dict, "version", ldns_pkt_edns_version(pkt));
    r |= getdns_dict_set_int(rr_dict, "do", ldns_pkt_edns_do(pkt));
    r |= getdns_dict_set_int(rr_dict, "z", ldns_pkt_edns_z(pkt));
    if (r != GETDNS_RETURN_GOOD) {
        getdns_dict_destroy(rr_dict);
        return GETDNS_RETURN_GENERIC_ERROR;
    }

    /* append */
    r = getdns_list_set_dict(rdatas, list_len, opt_rr);
    getdns_dict_destroy(opt_rr);
    if (r != GETDNS_RETURN_GOOD) {
        return GETDNS_RETURN_GENERIC_ERROR;
    }
    return r;
}


