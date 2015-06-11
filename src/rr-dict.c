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
#include "gldns/gbuffer.h"
#include "util-internal.h"
#include "types-internal.h"
#include "context.h"
#include "dict.h"

#define ALEN(a) (sizeof(a)/sizeof(a[0]))
#define UNKNOWN_RDATA NULL

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
apl_n_list_append_value(getdns_list *list, uint8_t *rdf)
{
	return getdns_list_append_int(list, (*rdf  >> 7));
}
static priv_getdns_rdf_special apl_n = {
    apl_n_rdf_end, apl_n_dict_set_value, apl_n_list_append_value
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
apl_afdpart_list_append_value(getdns_list *list, uint8_t *rdf)
{
	getdns_bindata bindata = { (rdf[-1] & 0x7F), rdf };
	return getdns_list_append_bindata(list, &bindata);
}
static priv_getdns_rdf_special apl_afdpart = {
    apl_afdpart_rdf_end,
    apl_afdpart_dict_set_value, apl_afdpart_list_append_value
};

static uint8_t *
ipseckey_gateway_rdf_end(uint8_t *pkt, uint8_t *pkt_end, uint8_t *rdf)
{
	uint8_t *end;

	if (rdf - 5 < pkt)
		return NULL;
	switch (rdf[-2]) {
	case 0:	end = rdf;
		break;
	case 1: end = rdf + 4;
		break;
	case 2: end = rdf + 16;
		break;
	case 3: for (end = rdf; end < pkt_end; end += *end + 1)
			if ((*end & 0xC0) == 0xC0)
				end  += 2;
			else if (*end & 0xC0)
				return NULL;
			else if (!*end) {
				end += 1;
				break;
			}
		break;
	default:
		return NULL;
	}
	return end <= pkt_end ? end : NULL;
}
static getdns_return_t
ipseckey_gateway_equip_bindata(uint8_t *rdf, getdns_bindata *bindata)
{
	bindata->data = rdf;
	switch (rdf[-2]) {
	case 0:	bindata->size = 0;
		break;
	case 1: bindata->size = 4;
		break;
	case 2: bindata->size = 16;
		break;
	case 3: while (*rdf)
			if ((*rdf & 0xC0) == 0xC0)
				rdf += 2;
			else if (*rdf & 0xC0)
				return GETDNS_RETURN_GENERIC_ERROR;
			else
				rdf += *rdf + 1;
		bindata->size = rdf + 1 - bindata->data;
		break;
	default:
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	return GETDNS_RETURN_GOOD;
	
}
static getdns_return_t
ipseckey_gateway_dict_set_value(getdns_dict *dict, uint8_t *rdf)
{
	getdns_bindata bindata;

	if (ipseckey_gateway_equip_bindata(rdf, &bindata))
		return GETDNS_RETURN_GENERIC_ERROR;

	else if (! bindata.size)
		return GETDNS_RETURN_GOOD;
	else
		return getdns_dict_set_bindata(dict, "gateway", &bindata);
}
static getdns_return_t
ipseckey_gateway_list_append_value(getdns_list *list, uint8_t *rdf)
{
	getdns_bindata bindata;

	if (ipseckey_gateway_equip_bindata(rdf, &bindata))
		return GETDNS_RETURN_GENERIC_ERROR;

	else if (! bindata.size)
		return GETDNS_RETURN_GOOD;
	else
		return getdns_list_append_bindata(list, &bindata);
}
static priv_getdns_rdf_special ipseckey_gateway = {
    ipseckey_gateway_rdf_end,
    ipseckey_gateway_dict_set_value, ipseckey_gateway_list_append_value
};

static uint8_t *
hip_pk_algorithm_rdf_end(uint8_t *pkt, uint8_t *pkt_end, uint8_t *rdf)
{
	return rdf + 4 > pkt_end ? NULL
	     : rdf + 4 + *rdf + gldns_read_uint16(rdf + 2) > pkt_end ? NULL
	     : rdf + 1;
}
static getdns_return_t
hip_pk_algorithm_dict_set_value(getdns_dict *dict, uint8_t *rdf)
{
	return getdns_dict_set_int(dict, "pk_algorithm", rdf[1]);
}
static getdns_return_t
hip_pk_algorithm_list_append_value(getdns_list *list, uint8_t *rdf)
{
	return getdns_list_append_int(list, rdf[1]);
}
static priv_getdns_rdf_special hip_pk_algorithm = {
    hip_pk_algorithm_rdf_end,
    hip_pk_algorithm_dict_set_value, hip_pk_algorithm_list_append_value
};

static uint8_t *
hip_hit_rdf_end(uint8_t *pkt, uint8_t *pkt_end, uint8_t *rdf)
{
	return rdf + 3 > pkt_end ? NULL
	     : rdf + 3 + rdf[-1] + gldns_read_uint16(rdf + 1) > pkt_end ? NULL
	     : rdf + 1;
}
static getdns_return_t
hip_hit_dict_set_value(getdns_dict *dict, uint8_t *rdf)
{
	getdns_bindata bindata = { rdf[-1], rdf + 3 };
	return getdns_dict_set_bindata(dict, "hit", &bindata);
}
static getdns_return_t
hip_hit_list_append_value(getdns_list *list, uint8_t *rdf)
{
	getdns_bindata bindata = { rdf[-1], rdf + 3 };
	return getdns_list_append_bindata(list, &bindata);
}
static priv_getdns_rdf_special hip_hit = {
    hip_hit_rdf_end, hip_hit_dict_set_value, hip_hit_list_append_value
};

static uint8_t *
hip_public_key_rdf_end(uint8_t *pkt, uint8_t *pkt_end, uint8_t *rdf)
{
	return rdf + 2 > pkt_end ? NULL
	     : rdf + 2 + rdf[-2] + gldns_read_uint16(rdf) > pkt_end ? NULL
	     : rdf + 2 + rdf[-2] + gldns_read_uint16(rdf);
}
static getdns_return_t
hip_public_key_dict_set_value(getdns_dict *dict, uint8_t *rdf)
{
	getdns_bindata bindata = { gldns_read_uint16(rdf), rdf + 2 + rdf[-2] };
	return getdns_dict_set_bindata(dict, "public_key", &bindata);
}
static getdns_return_t
hip_public_key_list_append_value(getdns_list *list, uint8_t *rdf)
{
	getdns_bindata bindata = { gldns_read_uint16(rdf), rdf + 2 + rdf[-2] };
	return getdns_list_append_bindata(list, &bindata);
}
static priv_getdns_rdf_special hip_public_key = {
    hip_public_key_rdf_end,
    hip_public_key_dict_set_value, hip_public_key_list_append_value
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
	{ "option_data"                 , GETDNS_RDF_X_S  }};
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
	{ "gateway"                     , GETDNS_RDF_SPECIAL, &ipseckey_gateway },
	{ "public_key"                  , GETDNS_RDF_B    }};
static priv_getdns_rdata_def      rrsig_rdata[] = {
	{ "type_covered"                , GETDNS_RDF_I2   },
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "labels"                      , GETDNS_RDF_I1   },
	{ "original_ttl"                , GETDNS_RDF_I4   },
	{ "signature_expiration"        , GETDNS_RDF_T    },
	{ "signature_inception"         , GETDNS_RDF_T    },
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
	{ "pk_algorithm"                , GETDNS_RDF_SPECIAL, &hip_pk_algorithm },
	{ "hit"                         , GETDNS_RDF_SPECIAL, &hip_hit },
	{ "public_key"                  , GETDNS_RDF_SPECIAL, &hip_public_key },
	{ "rendezvous_servers"          , GETDNS_RDF_N_M  }};
static priv_getdns_rdata_def        spf_rdata[] = {
	{ "text"                        , GETDNS_RDF_S_M  }};
static priv_getdns_rdata_def        nid_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "node_id"                     , GETDNS_RDF_AA   }};
static priv_getdns_rdata_def        l32_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "locator32"                   , GETDNS_RDF_A    }};
static priv_getdns_rdata_def        l64_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "locator64"                   , GETDNS_RDF_AA   }};
static priv_getdns_rdata_def         lp_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "fqdn"                        , GETDNS_RDF_N    }};
static priv_getdns_rdata_def      eui48_rdata[] = {
	{ "eui48_address"               , GETDNS_RDF_X6   }};
static priv_getdns_rdata_def      eui64_rdata[] = {
	{ "eui64_address"               , GETDNS_RDF_X8   }};
static priv_getdns_rdata_def       tkey_rdata[] = {
	{ "algorithm"                   , GETDNS_RDF_N    },
	{ "inception"                   , GETDNS_RDF_T    },
	{ "expiration"                  , GETDNS_RDF_T    },
	{ "mode"                        , GETDNS_RDF_I2   },
	{ "error"                       , GETDNS_RDF_I2   },
	{ "key_data"                    , GETDNS_RDF_X_S  },
	{ "other_data"                  , GETDNS_RDF_X_S  }};
static priv_getdns_rdata_def       tsig_rdata[] = {
	{ "algorithm"                   , GETDNS_RDF_N    },
	{ "time_signed"                 , GETDNS_RDF_T6   },
	{ "fudge"                       , GETDNS_RDF_I2   },
	{ "mac"                         , GETDNS_RDF_X_S  },
	{ "original_id"                 , GETDNS_RDF_I2   },
	{ "error"                       , GETDNS_RDF_I2   },
	{ "other_data"                  , GETDNS_RDF_X_S  }};
static priv_getdns_rdata_def        uri_rdata[] = {
	{ "priority"                    , GETDNS_RDF_I2   },
	{ "weight"                      , GETDNS_RDF_I2   },
	{ "target"                      , GETDNS_RDF_S_L  }};
static priv_getdns_rdata_def        caa_rdata[] = {
	{ "flags"                       , GETDNS_RDF_I1   },
	{ "tag"                         , GETDNS_RDF_S    },
	{ "value"                       , GETDNS_RDF_S_L  }};
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
	{ "OPENPGPKEY",    UNKNOWN_RDATA, 0                      }, /* 61 - */
	{      "CSYNC",    UNKNOWN_RDATA, 0                      }, /* - 62 */
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
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

