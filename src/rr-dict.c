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
#include "util-internal.h"
#include "types-internal.h"
#include "context.h"
#include "dict.h"

#define ALEN(a) (sizeof(a)/sizeof(a[0]))
#define UNKNOWN_RDATA NULL

/*
static uint8_t *
template_rdf_end(uint8_t *pkt, uint8_t *pkt_end, uint8_t *rdf)
{
	return NULL;
}
static getdns_return_t
template_dict_set_value(getdns_dict *dict, uint8_t *rdf)
{
	return GETDNS_RETURN_GENERIC_ERROR;
}
static getdns_return_t
template_list_set_value(getdns_list *list, uint8_t *rdf)
{
	return GETDNS_RETURN_GENERIC_ERROR;
}
static priv_getdns_rdf_special template = {
    template_rdf_end, template_dict_set_value, template_list_set_value
};
*/

static uint8_t *
apl_n_rdf_end(uint8_t *pkt, uint8_t *pkt_end, uint8_t *rdf)
{
	return rdf < pkt_end ? rdf + 1 : NULL;
}
static getdns_return_t
apl_n_dict_set_value(getdns_dict *dict, uint8_t *rdf)
{
	return getdns_dict_set_int(dict, "n", (*rdf  >> 7));
}
static getdns_return_t
apl_n_list_set_value(getdns_list *list, uint8_t *rdf)
{
	return getdns_list_append_int(list, (*rdf  >> 7));
}
static priv_getdns_rdf_special apl_n = {
    apl_n_rdf_end, apl_n_dict_set_value, apl_n_list_set_value
};

static uint8_t *
apl_afdpart_rdf_end(uint8_t *pkt, uint8_t *pkt_end, uint8_t *rdf)
{
	uint8_t *end = rdf + (rdf[-1] & 0x7F);
	return end <= pkt_end ? end : NULL;
}
static getdns_return_t
apl_afdpart_dict_set_value(getdns_dict *dict, uint8_t *rdf)
{
	getdns_bindata bindata = { (rdf[-1] & 0x7F), rdf };
	return getdns_dict_set_bindata(dict, "afdpart", &bindata);
}
static getdns_return_t
apl_afdpart_list_set_value(getdns_list *list, uint8_t *rdf)
{
	getdns_bindata bindata = { (rdf[-1] & 0x7F), rdf };
	return getdns_list_append_bindata(list, &bindata);
}
static priv_getdns_rdf_special apl_afdpart = {
    apl_afdpart_rdf_end, apl_afdpart_dict_set_value, apl_afdpart_list_set_value
};

static priv_getdns_rdata_def          a_rdata[] = {
	{ "ipv4_address"                , GETDNS_RDF_A    }};
static priv_getdns_rdata_def         ns_rdata[] = {
	{ "nsdname"                     , GETDNS_RDF_N_C  }};
static priv_getdns_rdata_def         md_rdata[] = {
	{ "madname"                     , GETDNS_RDF_N_C  }};
static priv_getdns_rdata_def      cname_rdata[] = {
	{ "cname"                       , GETDNS_RDF_N_C  }};
static priv_getdns_rdata_def        soa_rdata[] = {
	{ "mname"                       , GETDNS_RDF_N_C  },
	{ "rname"                       , GETDNS_RDF_N_C  },
	{ "serial"                      , GETDNS_RDF_I4   },
	{ "refresh"                     , GETDNS_RDF_I4   },
	{ "refresh"                     , GETDNS_RDF_I4   },
	{ "retry"                       , GETDNS_RDF_I4   },
	{ "expire"                      , GETDNS_RDF_I4   }};
static priv_getdns_rdata_def         mg_rdata[] = {
	{ "mgmname"                     , GETDNS_RDF_N_C  }};
static priv_getdns_rdata_def         mr_rdata[] = {
	{ "newname"                     , GETDNS_RDF_N_C  }};
static priv_getdns_rdata_def       null_rdata[] = {
	{ "anything"                    , GETDNS_RDF_X    }};
static priv_getdns_rdata_def        wks_rdata[] = {
	{ "address"                     , GETDNS_RDF_A    },
	{ "protocol"                    , GETDNS_RDF_I1   },
	{ "bitmap"                      , GETDNS_RDF_X    }};
static priv_getdns_rdata_def        ptr_rdata[] = {
	{ "ptrdname"                    , GETDNS_RDF_N_C  }};
static priv_getdns_rdata_def      hinfo_rdata[] = {
	{ "cpu"                         , GETDNS_RDF_S    },
	{ "os"                          , GETDNS_RDF_S    }};
static priv_getdns_rdata_def      minfo_rdata[] = {
	{ "rmailbx"                     , GETDNS_RDF_N_C  },
	{ "emailbx"                     , GETDNS_RDF_N_C  }};
static priv_getdns_rdata_def         mx_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "exchange"                    , GETDNS_RDF_N_C  }};
static priv_getdns_rdata_def        txt_rdata[] = {
	{ "txt_strings"                 , GETDNS_RDF_S_M  }};
static priv_getdns_rdata_def         rp_rdata[] = {
	{ "mbox_dname"                  , GETDNS_RDF_N    },
	{ "txt_dname"                   , GETDNS_RDF_N    }};
static priv_getdns_rdata_def      afsdb_rdata[] = {
	{ "subtype"                     , GETDNS_RDF_I2   },
	{ "hostname"                    , GETDNS_RDF_N    }};
static priv_getdns_rdata_def        x25_rdata[] = {
	{ "psdn_address"                , GETDNS_RDF_S    }};
static priv_getdns_rdata_def       isdn_rdata[] = {
	{ "isdn_address"                , GETDNS_RDF_S    },
	{ "sa"                          , GETDNS_RDF_S    }};
static priv_getdns_rdata_def         rt_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "intermediate_host"           , GETDNS_RDF_N    }};
static priv_getdns_rdata_def       nsap_rdata[] = {
	{ "nsap"                        , GETDNS_RDF_X    }};
static priv_getdns_rdata_def        sig_rdata[] = {
	{ "sig_obsolete"                , GETDNS_RDF_X    }};
static priv_getdns_rdata_def        key_rdata[] = {
	{ "key_obsolete"                , GETDNS_RDF_X    }};
static priv_getdns_rdata_def         px_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "map822"                      , GETDNS_RDF_N    },
	{ "mapx400"                     , GETDNS_RDF_N    }};
static priv_getdns_rdata_def       gpos_rdata[] = {
	{ "longitude"                   , GETDNS_RDF_S    },
	{ "latitude"                    , GETDNS_RDF_S    },
	{ "altitude"                    , GETDNS_RDF_S    }};
static priv_getdns_rdata_def       aaaa_rdata[] = {
	{ "ipv6_address"                , GETDNS_RDF_AAAA }};
static priv_getdns_rdata_def        loc_rdata[] = {
	{ "loc_obsolete"                , GETDNS_RDF_X    }};
static priv_getdns_rdata_def        nxt_rdata[] = {
	{ "nxt_obsolete"                , GETDNS_RDF_X    }};
static priv_getdns_rdata_def        srv_rdata[] = {
	{ "priority"                    , GETDNS_RDF_I2   },
	{ "weight"                      , GETDNS_RDF_I2   },
	{ "port"                        , GETDNS_RDF_I2   },
	{ "target"                      , GETDNS_RDF_N    }};
static priv_getdns_rdata_def       atma_rdata[] = {
	{ "format"                      , GETDNS_RDF_X    }};
static priv_getdns_rdata_def      naptr_rdata[] = {
	{ "order"                       , GETDNS_RDF_I2   },
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "flags"                       , GETDNS_RDF_S    },
	{ "service"                     , GETDNS_RDF_S    },
	{ "regexp"                      , GETDNS_RDF_S    },
	{ "replacement"                 , GETDNS_RDF_N    }};
static priv_getdns_rdata_def         kx_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "exchanger"                   , GETDNS_RDF_N    }};
static priv_getdns_rdata_def       cert_rdata[] = {
	{ "type"                        , GETDNS_RDF_I2   },
	{ "key_tag"                     , GETDNS_RDF_I2   },
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "certificate_or_crl"          , GETDNS_RDF_B    }};
static priv_getdns_rdata_def         a6_rdata[] = {
	{ "a6_obsolete"                 , GETDNS_RDF_X    }};
static priv_getdns_rdata_def      dname_rdata[] = {
	{ "target"                      , GETDNS_RDF_N    }};
static priv_getdns_rdata_def        opt_rdata[] = {
	{ "options"                     , GETDNS_RDF_R    },
	{ "option_code"                 , GETDNS_RDF_I2   },
	{ "option_data"                 , GETDNS_RDF_X_2  }};
static priv_getdns_rdata_def        apl_rdata[] = {
	{ "apitems"                     , GETDNS_RDF_R    },
	{ "address_family"              , GETDNS_RDF_I2   },
	{ "prefix"                      , GETDNS_RDF_I1   },
	{ "n"                           , GETDNS_RDF_SPECIAL, &apl_n },
	{ "afdpart"                     , GETDNS_RDF_SPECIAL, &apl_afdpart }};
static priv_getdns_rdata_def         ds_rdata[] = {
	{ "key_tag"                     , GETDNS_RDF_I2   },
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "digest_type"                 , GETDNS_RDF_I1   },
	{ "digest"                      , GETDNS_RDF_X    }};
static priv_getdns_rdata_def      sshfp_rdata[] = {
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "fp_type"                     , GETDNS_RDF_I1   },
	{ "fingerprint"                 , GETDNS_RDF_X    }};
static priv_getdns_rdata_def   ipseckey_rdata[] = {
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "gateway_type"                , GETDNS_RDF_I1   },
	{ "precedence"                  , GETDNS_RDF_I1   },
	{ "gateway"                     , GETDNS_RDF_SPECIAL, NULL },
	{ "public_key"                  , GETDNS_RDF_B    }};
static priv_getdns_rdata_def      rrsig_rdata[] = {
	{ "type_covered"                , GETDNS_RDF_I2   },
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "labels"                      , GETDNS_RDF_I1   },
	{ "original_ttl"                , GETDNS_RDF_I4   },
	{ "signature_expiration"        , GETDNS_RDF_I4   },
	{ "signature_inception"         , GETDNS_RDF_I4   },
	{ "key_tag"                     , GETDNS_RDF_I2   },
	{ "signers_name"                , GETDNS_RDF_N    },
	{ "signature"                   , GETDNS_RDF_B    }};
static priv_getdns_rdata_def       nsec_rdata[] = {
	{ "next_domain_name"            , GETDNS_RDF_N    },
	{ "type_bit_maps"               , GETDNS_RDF_X    }};
static priv_getdns_rdata_def     dnskey_rdata[] = {
	{ "flags"                       , GETDNS_RDF_I2   },
	{ "protocol"                    , GETDNS_RDF_I1   },
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "public_key"                  , GETDNS_RDF_B    }};
static priv_getdns_rdata_def      dhcid_rdata[] = {
	{ "dhcid_opaque"                , GETDNS_RDF_B    }};
static priv_getdns_rdata_def      nsec3_rdata[] = {
	{ "hash_algorithm"              , GETDNS_RDF_I1   },
	{ "flags"                       , GETDNS_RDF_I1   },
	{ "iterations"                  , GETDNS_RDF_I2   },
	{ "salt"                        , GETDNS_RDF_X_C  },
	{ "next_hashed_owner_name"      , GETDNS_RDF_B32_C},
	{ "type_bit_maps"               , GETDNS_RDF_X    }};
static priv_getdns_rdata_def nsec3param_rdata[] = {
	{ "hash_algorithm"              , GETDNS_RDF_I1   },
	{ "flags"                       , GETDNS_RDF_I1   },
	{ "iterations"                  , GETDNS_RDF_I2   },
	{ "salt"                        , GETDNS_RDF_X_C  }};
static priv_getdns_rdata_def       tlsa_rdata[] = {
	{ "certificate_usage"           , GETDNS_RDF_I1   },
	{ "selector"                    , GETDNS_RDF_I1   },
	{ "matching_type"               , GETDNS_RDF_I1   },
	{ "certificate_association_data", GETDNS_RDF_X    }};
static priv_getdns_rdata_def        hip_rdata[] = {
	{ "pk_algorithm"                , GETDNS_RDF_SPECIAL, NULL },
	{ "hit"                         , GETDNS_RDF_SPECIAL, NULL },
	{ "public_key"                  , GETDNS_RDF_SPECIAL, NULL },
	{ "rendezvous_servers"          , GETDNS_RDF_N_M  }};
static priv_getdns_rdata_def        spf_rdata[] = {
	{ "text"                        , GETDNS_RDF_S_M  }};
static priv_getdns_rdata_def        nid_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "node_id"                     , GETDNS_RDF_X8   }};
static priv_getdns_rdata_def        l32_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "locator32"                   , GETDNS_RDF_A    }};
static priv_getdns_rdata_def        l64_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "locator64"                   , GETDNS_RDF_X8   }};
static priv_getdns_rdata_def         lp_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "fqdn"                        , GETDNS_RDF_N    }};
static priv_getdns_rdata_def      eui48_rdata[] = {
	{ "eui48_address"               , GETDNS_RDF_X6   }};
static priv_getdns_rdata_def      eui64_rdata[] = {
	{ "eui64_address"               , GETDNS_RDF_X8   }};
static priv_getdns_rdata_def       tkey_rdata[] = {
	{ "algorithm"                   , GETDNS_RDF_N    },
	{ "inception"                   , GETDNS_RDF_I4   },
	{ "expiration"                  , GETDNS_RDF_I4   },
	{ "mode"                        , GETDNS_RDF_I2   },
	{ "error"                       , GETDNS_RDF_I2   },
	{ "key_data"                    , GETDNS_RDF_X_2  },
	{ "other_data"                  , GETDNS_RDF_X_2  }};
static priv_getdns_rdata_def       tsig_rdata[] = {
	{ "algorithm"                   , GETDNS_RDF_N    },
	{ "time_signed"                 , GETDNS_RDF_I6   },
	{ "fudge"                       , GETDNS_RDF_I2   },
	{ "mac"                         , GETDNS_RDF_X_2  },
	{ "original_id"                 , GETDNS_RDF_I2   },
	{ "error"                       , GETDNS_RDF_I2   },
	{ "other_data"                  , GETDNS_RDF_X_2  }};
static priv_getdns_rdata_def        uri_rdata[] = {
	{ "priority"                    , GETDNS_RDF_I2   },
	{ "weight"                      , GETDNS_RDF_I2   },
	{ "target"                      , GETDNS_RDF_S_M  }};
static priv_getdns_rdata_def        caa_rdata[] = {
	{ "flags"                       , GETDNS_RDF_I1   },
	{ "tag"                         , GETDNS_RDF_S    },
	{ "value"                       , GETDNS_RDF_S_M  }};
static priv_getdns_rdata_def        dlv_rdata[] = {
	{ "key_tag"                     , GETDNS_RDF_I2   },
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "digest_type"                 , GETDNS_RDF_I1   },
	{ "digest"                      , GETDNS_RDF_X    }};

static priv_getdns_rr_def priv_getdns_rr_defs[] = {
	{         NULL,             NULL, 0                      },
	{          "A",          a_rdata, ALEN(         a_rdata) }, /* 1 - */
	{         "NS",         ns_rdata, ALEN(        ns_rdata) },
	{         "MD",         md_rdata, ALEN(        md_rdata) },
	{         "MF",         md_rdata, ALEN(        md_rdata) },
	{      "CNAME",      cname_rdata, ALEN(     cname_rdata) },
	{        "SOA",        soa_rdata, ALEN(       soa_rdata) },
	{         "MB",         md_rdata, ALEN(        md_rdata) },
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
	{        "EID",    UNKNOWN_RDATA, 0                      },
	{     "NIMLOC",    UNKNOWN_RDATA, 0                      },
	{        "SRV",        srv_rdata, ALEN(       srv_rdata) },
	{       "ATMA",       atma_rdata, ALEN(      atma_rdata) },
	{      "NAPTR",      naptr_rdata, ALEN(     naptr_rdata) },
	{         "KX",         kx_rdata, ALEN(        kx_rdata) },
	{       "CERT",       cert_rdata, ALEN(      cert_rdata) },
	{         "A6",         a6_rdata, ALEN(        a6_rdata) },
	{      "DNAME",      dname_rdata, ALEN(     dname_rdata) },
	{       "SINK",    UNKNOWN_RDATA, 0                      },
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
	{      "NINFO",    UNKNOWN_RDATA, 0                      },
	{       "RKEY",    UNKNOWN_RDATA, 0                      },
	{     "TALINK",    UNKNOWN_RDATA, 0                      },
	{        "CDS",         ds_rdata, ALEN(        ds_rdata) },
	{    "CDNSKEY",     dnskey_rdata, ALEN(    dnskey_rdata) },
	{ "OPENPGPKEY",    UNKNOWN_RDATA, 0                      }, /* - 61 */
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
	{      "UINFO",    UNKNOWN_RDATA, 0                      },
	{        "UID",    UNKNOWN_RDATA, 0                      },
	{        "GID",    UNKNOWN_RDATA, 0                      },
	{     "UNSPEC",    UNKNOWN_RDATA, 0                      },
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
	{      "MAILB",    UNKNOWN_RDATA, 0                      }, /* 253 - */
	{      "MAILA",    UNKNOWN_RDATA, 0                      }, /* - 254 */
	{         NULL,             NULL, 0                      },
	{        "URI",        uri_rdata, ALEN(       uri_rdata) }, /* 256 - */
	{        "CAA",        caa_rdata, ALEN(       caa_rdata) }, /* - 257 */
	{         "TA",    UNKNOWN_RDATA, 0                      }, /* 32768 */
	{        "DLV",        dlv_rdata, ALEN(       dlv_rdata) }  /* 32769 */
};

const priv_getdns_rr_def *
priv_getdns_rr_def_lookup(uint16_t rr_type)
{
	if (rr_type <= 257)
		return &priv_getdns_rr_defs[rr_type];
	else if (rr_type == 32768)
		return &priv_getdns_rr_defs[258];
	else if (rr_type == 32769)
		return &priv_getdns_rr_defs[259];
	return priv_getdns_rr_defs;
}

const char *
priv_getdns_rr_type_name(int rr_type)
{
	return priv_getdns_rr_def_lookup(rr_type)->name;
}

/* list of txt records */
static getdns_return_t
priv_getdns_equip_dict_with_txt_rdfs(struct getdns_dict* rdata, ldns_rr* rr,
                                     const priv_getdns_rr_def* def,
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
                                     const priv_getdns_rr_def* def,
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
priv_append_apl_record(getdns_list* records, ldns_rdf* rdf,
    const priv_getdns_rr_def* def, getdns_context* context)
{
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
                                     const priv_getdns_rr_def* def,
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
                                     const priv_getdns_rr_def* def,
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
	const priv_getdns_rr_def *def;
	struct getdns_bindata bindata;
	size_t i;

	struct getdns_bindata *rdata_raw;
	const char *sptr;
	char *dptr, tmpbuf[100];

	uint8_t *rdf_data;
	size_t   rdf_size;

	assert(rdata);
	assert(rr);

	def = priv_getdns_rr_def_lookup(ldns_rr_get_type(rr));
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
    } else if (def->name &&
	    strlen(def->name) <= sizeof(tmpbuf) - 9 /* strlen("_unknown")+1 */ &&
	    (def->rdata == UNKNOWN_RDATA ||
	    ldns_rr_descriptor_field_type(
		ldns_rr_descript(ldns_rr_get_type(rr)), 0) == LDNS_RDF_TYPE_UNKNOWN)) {

		r = getdns_dict_get_bindata(rdata, "rdata_raw", &rdata_raw);
		if (r != GETDNS_RETURN_GOOD)
			return r;

		sptr = def->name;
		dptr = tmpbuf;
		do *dptr++ = tolower(*sptr);
			while (*sptr++); /* Including terminating '\0' */

		return getdns_dict_set_bindata(
		    rdata, strcat(tmpbuf, "_unknown"), rdata_raw);
    }
    /* generic */
	if (ldns_rr_rd_count(rr) != def->n_rdata_fields)
		return r;

	for (i = 0; !r && i < ldns_rr_rd_count(rr) 
	               && i < def->n_rdata_fields; i++) {

		if (! (def->rdata[i].type & GETDNS_RDF_INTEGER)) {
			bindata.size = ldns_rdf_size(ldns_rr_rdf(rr, i));
			bindata.data = ldns_rdf_data(ldns_rr_rdf(rr, i));
			r = getdns_dict_set_bindata(
			    rdata, (char*)def->rdata[i].name, &bindata);
			continue;
		}
		rdf_size = ldns_rdf_size(ldns_rr_rdf(rr, i));
		rdf_data = ldns_rdf_data(ldns_rr_rdf(rr, i));
		r = getdns_dict_set_int(rdata, (char *)def->rdata[i].name,
		      rdf_size == 1 ?                 *rdf_data
		    : rdf_size == 2 ? ldns_read_uint16(rdf_data)
		    : rdf_size == 4 ? ldns_read_uint32(rdf_data) : -1);
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

static getdns_return_t priv_getdns_construct_wire_rdata_from_rdata(
    struct getdns_dict *rdata, uint32_t rr_type,
    uint8_t **wire, size_t *wire_size)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	const ldns_rr_descriptor *rr_descript;
	const priv_getdns_rr_def *def;
	size_t i, size;
	struct getdns_bindata *bindata;
	uint32_t value;
	uint8_t *ptr;

	assert(rdata);
	assert(wire);
	assert(wire_size);

	def = priv_getdns_rr_def_lookup(rr_type);
	rr_descript = ldns_rr_descript(rr_type);

	/* First calculate needed size */
	size = 0;
	for (i = 0; !r && i < def->n_rdata_fields; i++) {
		if (def->rdata[i].type & GETDNS_RDF_BINDATA)
			if ((r = getdns_dict_get_bindata(rdata,
			    def->rdata[i].name, &bindata)))
				break;
			else {
				size += bindata->size;
				continue;
			}
		else if (!(def->rdata[i].type & GETDNS_RDF_INTEGER)) {
			r = GETDNS_RETURN_GENERIC_ERROR;
			break;
		}
		switch (ldns_rr_descriptor_field_type(rr_descript, i)) {

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
	}
	*wire_size = size + 2;
	*wire = ptr = GETDNS_XMALLOC(rdata->mf, uint8_t, size + 2);
	if (! ptr)
		return GETDNS_RETURN_MEMORY_ERROR;

	ptr[0] = (uint8_t) (size >> 8) & 0xff;
	ptr[1] = (uint8_t)  size       & 0xff;
	ptr += 2;
	for (i = 0; !r && i < def->n_rdata_fields; i++) {
		if (def->rdata[i].type & GETDNS_RDF_BINDATA)
			if ((r = getdns_dict_get_bindata(rdata,
			    def->rdata[i].name, &bindata)))
				break;
			else {
				(void) memcpy(ptr, bindata->data,
				                   bindata->size);
				ptr += bindata->size;
				continue;
			}
		else if (!(def->rdata[i].type & GETDNS_RDF_INTEGER)) {
			r = GETDNS_RETURN_GENERIC_ERROR;
			break;
		}
		if ((r = getdns_dict_get_int(
		    rdata, def->rdata[i].name, &value)))
			break;

		switch (ldns_rr_descriptor_field_type(rr_descript, i)) {

		case LDNS_RDF_TYPE_CLASS:
		case LDNS_RDF_TYPE_ALG  :
		case LDNS_RDF_TYPE_INT8 : ptr[0] = (uint8_t) value      & 0xff;
		                          ptr += 1;
					  break;
		case LDNS_RDF_TYPE_TYPE :
		case LDNS_RDF_TYPE_CERT_ALG:
		case LDNS_RDF_TYPE_INT16: ptr[0] = (uint8_t)(value>> 8) & 0xff;
					  ptr[1] = (uint8_t) value      & 0xff;
					  ptr += 2;
					  break;
		case LDNS_RDF_TYPE_TIME :
		case LDNS_RDF_TYPE_PERIOD:
		case LDNS_RDF_TYPE_INT32: ptr[0] = (uint8_t)(value>>24) & 0xff;
					  ptr[1] = (uint8_t)(value>>16) & 0xff;
					  ptr[2] = (uint8_t)(value>>8 ) & 0xff;
					  ptr[3] = (uint8_t) value      & 0xff;
					  ptr += 4;
					  break;
		default: r = GETDNS_RETURN_GENERIC_ERROR;
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

