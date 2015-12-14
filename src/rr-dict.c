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

static const uint8_t *
apl_n_rdf_end(const uint8_t *pkt, const uint8_t *pkt_end, const uint8_t *rdf)
{
	return rdf < pkt_end ? rdf + 1 : NULL;
}
static getdns_return_t
apl_n_wire2dict(getdns_dict *dict, const uint8_t *rdf)
{
	return getdns_dict_set_int(dict, "n", (*rdf  >> 7));
}
static getdns_return_t
apl_n_wire2list(getdns_list *list, const uint8_t *rdf)
{
	return _getdns_list_append_int(list, (*rdf  >> 7));
}
static getdns_return_t
apl_n_2wire(uint32_t value, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	(void)rdata; /* unused parameter */

	if (*rdf_len < 1) {
		*rdf_len = 1;
		return GETDNS_RETURN_NEED_MORE_SPACE;
	}
	*rdf_len = 1;
	*rdf = value ? 0x80 : 0x00;
	return GETDNS_RETURN_GOOD;
}
static getdns_return_t
apl_n_dict2wire(const getdns_dict *dict,
    uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	uint32_t        value;

	if ((r = getdns_dict_get_int(dict, "n", &value)))
		return r;
	else
		return apl_n_2wire(value, rdata, rdf, rdf_len);
}
static getdns_return_t
apl_n_list2wire(const getdns_list *list, size_t i,
    uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	uint32_t        value;

	if ((r = getdns_list_get_int(list, i, &value)))
		return r;
	else
		return apl_n_2wire(value, rdata, rdf, rdf_len);
}
static _getdns_rdf_special apl_n = {
    apl_n_rdf_end,
    apl_n_wire2dict, apl_n_wire2list,
    apl_n_dict2wire, apl_n_list2wire
};

static const uint8_t *
apl_afdpart_rdf_end(
    const uint8_t *pkt, const uint8_t *pkt_end, const uint8_t *rdf)
{
	const uint8_t *end = rdf + (rdf[-1] & 0x7F);
	return end <= pkt_end ? end : NULL;
}
static getdns_return_t
apl_afdpart_wire2dict(getdns_dict *dict, const uint8_t *rdf)
{
	return _getdns_dict_set_const_bindata(
	    dict, "afdpart", (rdf[-1] & 0x7F), rdf);
}
static getdns_return_t
apl_afdpart_wire2list(getdns_list *list, const uint8_t *rdf)
{
	return _getdns_list_append_const_bindata(list, (rdf[-1] & 0x7F), rdf);
}
static getdns_return_t
apl_afdpart_2wire(
    const getdns_bindata *value, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	if (value->size > 0x7F)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (rdf - 1 < rdata)
		return GETDNS_RETURN_GENERIC_ERROR;

	if (*rdf_len < value->size) {
		*rdf_len = value->size;
		return GETDNS_RETURN_NEED_MORE_SPACE;
	}
	*rdf_len = value->size;

	/* Keeping first bit is safe because value->size <= 0x7F */
	rdf[-1] |= value->size;

	(void) memcpy(rdf, value->data, value->size);
	return GETDNS_RETURN_GOOD;
}
static getdns_return_t
apl_afdpart_dict2wire(
    const getdns_dict *dict, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	getdns_bindata *value;

	if ((r = getdns_dict_get_bindata(dict, "afdpart", &value)))
		return r;
	else
		return apl_afdpart_2wire(value, rdata, rdf, rdf_len);
}
static getdns_return_t
apl_afdpart_list2wire(const getdns_list *list,
    size_t i, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	getdns_bindata *value;

	if ((r = getdns_list_get_bindata(list, i, &value)))
		return r;
	else
		return apl_afdpart_2wire(value, rdata, rdf, rdf_len);
}
static _getdns_rdf_special apl_afdpart = {
    apl_afdpart_rdf_end,
    apl_afdpart_wire2dict, apl_afdpart_wire2list,
    apl_afdpart_dict2wire, apl_afdpart_list2wire
};

static const uint8_t *
ipseckey_gateway_rdf_end(
    const uint8_t *pkt, const uint8_t *pkt_end, const uint8_t *rdf)
{
	const uint8_t *end;

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
ipseckey_gateway_equip_const_bindata(
    const uint8_t *rdf, size_t *size, const uint8_t **data)
{
	*data = rdf;
	switch (rdf[-2]) {
	case 0:	*size = 0;
		break;
	case 1: *size = 4;
		break;
	case 2: *size = 16;
		break;
	case 3: while (*rdf)
			if ((*rdf & 0xC0) == 0xC0)
				rdf += 2;
			else if (*rdf & 0xC0)
				return GETDNS_RETURN_GENERIC_ERROR;
			else
				rdf += *rdf + 1;
		*size = rdf + 1 - *data;
		break;
	default:
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	return GETDNS_RETURN_GOOD;
}

static getdns_return_t
ipseckey_gateway_wire2dict(getdns_dict *dict, const uint8_t *rdf)
{
	size_t size;
	const uint8_t *data;

	if (ipseckey_gateway_equip_const_bindata(rdf, &size, &data))
		return GETDNS_RETURN_GENERIC_ERROR;

	else if (! size)
		return GETDNS_RETURN_GOOD;
	else
		return _getdns_dict_set_const_bindata(dict, "gateway", size, data);
}
static getdns_return_t
ipseckey_gateway_wire2list(getdns_list *list, const uint8_t *rdf)
{
	size_t size;
	const uint8_t *data;

	if (ipseckey_gateway_equip_const_bindata(rdf, &size, &data))
		return GETDNS_RETURN_GENERIC_ERROR;

	else if (!size)
		return GETDNS_RETURN_GOOD;
	else
		return _getdns_list_append_const_bindata(list, size, data);
}
static getdns_return_t
ipseckey_gateway_2wire(
    const getdns_bindata *value, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	if (rdf - 2 < rdata)
		return GETDNS_RETURN_GENERIC_ERROR;

	switch (rdf[-2]) {
	case 0:	if (value && value->size > 0)
			return GETDNS_RETURN_INVALID_PARAMETER;
		break;
	case 1: if (!value || value->size != 4)
			return GETDNS_RETURN_INVALID_PARAMETER;
		if (*rdf_len < 4) {
			*rdf_len = 4;
			return GETDNS_RETURN_NEED_MORE_SPACE;
		}
		*rdf_len = 4;
		(void)memcpy(rdf, value->data, 4);
		return GETDNS_RETURN_GOOD;
	case 2: if (!value || value->size != 16)
			return GETDNS_RETURN_INVALID_PARAMETER;
		if (*rdf_len < 16) {
			*rdf_len = 16;
			return GETDNS_RETURN_NEED_MORE_SPACE;
		}
		*rdf_len = 16;
		(void)memcpy(rdf, value->data, 16);
		return GETDNS_RETURN_GOOD;
	case 3: if (!value || value->size == 0)
			return GETDNS_RETURN_INVALID_PARAMETER;
		/* Assume bindata is a valid dname; garbage in, garbage out */
		if (*rdf_len < value->size) {
			*rdf_len = value->size;
			return GETDNS_RETURN_NEED_MORE_SPACE;
		}
		*rdf_len = value->size;
		(void)memcpy(rdf, value->data, value->size);
		return GETDNS_RETURN_GOOD;
	default:
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	return GETDNS_RETURN_GOOD;
}
static getdns_return_t
ipseckey_gateway_dict2wire(
    const getdns_dict *dict, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	getdns_bindata *value;

	if ((r = getdns_dict_get_bindata(dict, "gateway", &value)))
		return r;
	else
		return ipseckey_gateway_2wire(value, rdata, rdf, rdf_len);
}
static getdns_return_t
ipseckey_gateway_list2wire(const getdns_list *list,
    size_t i, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	getdns_bindata *value;

	if ((r = getdns_list_get_bindata(list, i, &value)))
		return r;
	else
		return ipseckey_gateway_2wire(value, rdata, rdf, rdf_len);
}
static _getdns_rdf_special ipseckey_gateway = {
    ipseckey_gateway_rdf_end,
    ipseckey_gateway_wire2dict, ipseckey_gateway_wire2list,
    ipseckey_gateway_dict2wire, ipseckey_gateway_list2wire
};

static const uint8_t *
hip_pk_algorithm_rdf_end(
    const uint8_t *pkt, const uint8_t *pkt_end, const uint8_t *rdf)
{
	return rdf + 4 > pkt_end ? NULL
	     : rdf + 4 + *rdf + gldns_read_uint16(rdf + 2) > pkt_end ? NULL
	     : rdf + 1;
}
static getdns_return_t
hip_pk_algorithm_wire2dict(getdns_dict *dict, const uint8_t *rdf)
{
	return getdns_dict_set_int(dict, "pk_algorithm", rdf[1]);
}
static getdns_return_t
hip_pk_algorithm_wire2list(getdns_list *list, const uint8_t *rdf)
{
	return _getdns_list_append_int(list, rdf[1]);
}
static getdns_return_t
hip_pk_algorithm_2wire(uint32_t value, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	if (rdata != rdf)
		return GETDNS_RETURN_GENERIC_ERROR;
	if (value > 0xFF)
		return GETDNS_RETURN_INVALID_PARAMETER;
	if (*rdf_len < 4) {
		*rdf_len = 4;
		return GETDNS_RETURN_NEED_MORE_SPACE;
	}
	*rdf_len = 4;
	rdata[1] = value;
	return GETDNS_RETURN_GOOD;
}
static getdns_return_t
hip_pk_algorithm_dict2wire(
    const getdns_dict *dict,uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	uint32_t        value;

	if ((r = getdns_dict_get_int(dict, "pk_algorithm", &value)))
		return r;
	else
		return hip_pk_algorithm_2wire(value, rdata, rdf, rdf_len);
}
static getdns_return_t
hip_pk_algorithm_list2wire(const getdns_list *list,
    size_t i, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	uint32_t        value;

	if ((r = getdns_list_get_int(list, i, &value)))
		return r;
	else
		return hip_pk_algorithm_2wire(value, rdata, rdf, rdf_len);
}
static _getdns_rdf_special hip_pk_algorithm = {
    hip_pk_algorithm_rdf_end,
    hip_pk_algorithm_wire2dict, hip_pk_algorithm_wire2list,
    hip_pk_algorithm_dict2wire, hip_pk_algorithm_list2wire
};

static const uint8_t *
hip_hit_rdf_end(const uint8_t *pkt, const uint8_t *pkt_end, const uint8_t *rdf)
{
	return rdf + 3 > pkt_end ? NULL
	     : rdf + 3 + rdf[-1] + gldns_read_uint16(rdf + 1) > pkt_end ? NULL
	     : rdf + 1;
}
static getdns_return_t
hip_hit_wire2dict(getdns_dict *dict, const uint8_t *rdf)
{
	return _getdns_dict_set_const_bindata(dict, "hit", rdf[-1], rdf + 3);
}
static getdns_return_t
hip_hit_wire2list(getdns_list *list, const uint8_t *rdf)
{
	return _getdns_list_append_const_bindata(list, rdf[-1], rdf + 3);
}
static getdns_return_t
hip_hit_2wire(
    const getdns_bindata *value, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	if (rdata != rdf - 4)
		return GETDNS_RETURN_GENERIC_ERROR;
	if (value && value->size > 0xFF)
		return GETDNS_RETURN_INVALID_PARAMETER;
	if (!value || value->size == 0) {
		rdata[0] = 0;
		*rdf_len = 0;
		return GETDNS_RETURN_GOOD;
	}
	if (value->size > *rdf_len) {
		*rdf_len = value->size;
		return GETDNS_RETURN_NEED_MORE_SPACE;
	}
	*rdf_len = value->size;
	rdata[0] = value->size;
	(void)memcpy(rdf, value->data, value->size);
	return GETDNS_RETURN_GOOD;
}
static getdns_return_t
hip_hit_dict2wire(
    const getdns_dict *dict, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	getdns_bindata *value;

	if ((r = getdns_dict_get_bindata(dict, "hit", &value)))
		return r;
	else
		return hip_hit_2wire(value, rdata, rdf, rdf_len);
}
static getdns_return_t
hip_hit_list2wire(const getdns_list *list,
    size_t i, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	getdns_bindata *value;

	if ((r = getdns_list_get_bindata(list, i, &value)))
		return r;
	else
		return hip_hit_2wire(value, rdata, rdf, rdf_len);
}
static _getdns_rdf_special hip_hit = {
    hip_hit_rdf_end,
    hip_hit_wire2dict, hip_hit_wire2list,
    hip_hit_dict2wire, hip_hit_list2wire
};

static const uint8_t *
hip_public_key_rdf_end(
    const uint8_t *pkt, const uint8_t *pkt_end, const uint8_t *rdf)
{
	return rdf + 2 > pkt_end ? NULL
	     : rdf + 2 + rdf[-2] + gldns_read_uint16(rdf) > pkt_end ? NULL
	     : rdf + 2 + rdf[-2] + gldns_read_uint16(rdf);
}
static getdns_return_t
hip_public_key_wire2dict(getdns_dict *dict, const uint8_t *rdf)
{
	return _getdns_dict_set_const_bindata(
	    dict, "public_key", gldns_read_uint16(rdf), rdf + 2 + rdf[-2]);
}
static getdns_return_t
hip_public_key_wire2list(getdns_list *list, const uint8_t *rdf)
{
	return _getdns_list_append_const_bindata(
	    list, gldns_read_uint16(rdf), rdf + 2 + rdf[-2]);
}
static getdns_return_t
hip_public_key_2wire(
    const getdns_bindata *value, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	if (rdata > rdf - 4 || rdata + 4 + rdata[0] != rdf)
		return GETDNS_RETURN_GENERIC_ERROR;
	if (value && value->size > 0xFFFF)
		return GETDNS_RETURN_INVALID_PARAMETER;
	if (!value || value->size == 0) {
		rdata[2] = rdata[3] = 0;
		*rdf_len = 0;
		return GETDNS_RETURN_GOOD;
	}
	if (value->size > *rdf_len) {
		*rdf_len = value->size;
		return GETDNS_RETURN_NEED_MORE_SPACE;
	}
	*rdf_len = value->size;
	gldns_write_uint16(rdata + 2, value->size);
	(void)memcpy(rdf, value->data, value->size);
	return GETDNS_RETURN_GOOD;
}
static getdns_return_t
hip_public_key_dict2wire(
    const getdns_dict *dict, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	getdns_bindata *value;

	if ((r = getdns_dict_get_bindata(dict, "public_key", &value)))
		return r;
	else
		return hip_public_key_2wire(value, rdata, rdf, rdf_len);
}
static getdns_return_t
hip_public_key_list2wire(
    const getdns_list *list, size_t i, uint8_t *rdata, uint8_t *rdf, size_t *rdf_len)
{
	getdns_return_t r;
	getdns_bindata *value;

	if ((r = getdns_list_get_bindata(list, i, &value)))
		return r;
	else
		return hip_public_key_2wire(value, rdata, rdf, rdf_len);
}
static _getdns_rdf_special hip_public_key = {
    hip_public_key_rdf_end,
    hip_public_key_wire2dict, hip_public_key_wire2list,
    hip_public_key_dict2wire, hip_public_key_list2wire
};


static _getdns_rdata_def          a_rdata[] = {
	{ "ipv4_address"                , GETDNS_RDF_A    }};
static _getdns_rdata_def         ns_rdata[] = {
	{ "nsdname"                     , GETDNS_RDF_N_C  }};
static _getdns_rdata_def         md_rdata[] = {
	{ "madname"                     , GETDNS_RDF_N_C  }};
static _getdns_rdata_def      cname_rdata[] = {
	{ "cname"                       , GETDNS_RDF_N_C  }};
static _getdns_rdata_def        soa_rdata[] = {
	{ "mname"                       , GETDNS_RDF_N_C  },
	{ "rname"                       , GETDNS_RDF_N_C  },
	{ "serial"                      , GETDNS_RDF_I4   },
	{ "refresh"                     , GETDNS_RDF_I4   },
	{ "retry"                       , GETDNS_RDF_I4   },
	{ "expire"                      , GETDNS_RDF_I4   },
	{ "minimum"                     , GETDNS_RDF_I4   }};
static _getdns_rdata_def         mg_rdata[] = {
	{ "mgmname"                     , GETDNS_RDF_N_C  }};
static _getdns_rdata_def         mr_rdata[] = {
	{ "newname"                     , GETDNS_RDF_N_C  }};
static _getdns_rdata_def       null_rdata[] = {
	{ "anything"                    , GETDNS_RDF_X    }};
static _getdns_rdata_def        wks_rdata[] = {
	{ "address"                     , GETDNS_RDF_A    },
	{ "protocol"                    , GETDNS_RDF_I1   },
	{ "bitmap"                      , GETDNS_RDF_X    }};
static _getdns_rdata_def        ptr_rdata[] = {
	{ "ptrdname"                    , GETDNS_RDF_N_C  }};
static _getdns_rdata_def      hinfo_rdata[] = {
	{ "cpu"                         , GETDNS_RDF_S    },
	{ "os"                          , GETDNS_RDF_S    }};
static _getdns_rdata_def      minfo_rdata[] = {
	{ "rmailbx"                     , GETDNS_RDF_N_C  },
	{ "emailbx"                     , GETDNS_RDF_N_C  }};
static _getdns_rdata_def         mx_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "exchange"                    , GETDNS_RDF_N_C  }};
static _getdns_rdata_def        txt_rdata[] = {
	{ "txt_strings"                 , GETDNS_RDF_S_M  }};
static _getdns_rdata_def         rp_rdata[] = {
	{ "mbox_dname"                  , GETDNS_RDF_N    },
	{ "txt_dname"                   , GETDNS_RDF_N    }};
static _getdns_rdata_def      afsdb_rdata[] = {
	{ "subtype"                     , GETDNS_RDF_I2   },
	{ "hostname"                    , GETDNS_RDF_N    }};
static _getdns_rdata_def        x25_rdata[] = {
	{ "psdn_address"                , GETDNS_RDF_S    }};
static _getdns_rdata_def       isdn_rdata[] = {
	{ "isdn_address"                , GETDNS_RDF_S    },
	{ "sa"                          , GETDNS_RDF_S    }};
static _getdns_rdata_def         rt_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "intermediate_host"           , GETDNS_RDF_N    }};
static _getdns_rdata_def       nsap_rdata[] = {
	{ "nsap"                        , GETDNS_RDF_X    }};
static _getdns_rdata_def        sig_rdata[] = {
	{ "sig_obsolete"                , GETDNS_RDF_X    }};
static _getdns_rdata_def        key_rdata[] = {
	{ "key_obsolete"                , GETDNS_RDF_X    }};
static _getdns_rdata_def         px_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "map822"                      , GETDNS_RDF_N    },
	{ "mapx400"                     , GETDNS_RDF_N    }};
static _getdns_rdata_def       gpos_rdata[] = {
	{ "longitude"                   , GETDNS_RDF_S    },
	{ "latitude"                    , GETDNS_RDF_S    },
	{ "altitude"                    , GETDNS_RDF_S    }};
static _getdns_rdata_def       aaaa_rdata[] = {
	{ "ipv6_address"                , GETDNS_RDF_AAAA }};
static _getdns_rdata_def        loc_rdata[] = {
	{ "loc_obsolete"                , GETDNS_RDF_X    }};
static _getdns_rdata_def        nxt_rdata[] = {
	{ "nxt_obsolete"                , GETDNS_RDF_X    }};
static _getdns_rdata_def        srv_rdata[] = {
	{ "priority"                    , GETDNS_RDF_I2   },
	{ "weight"                      , GETDNS_RDF_I2   },
	{ "port"                        , GETDNS_RDF_I2   },
	{ "target"                      , GETDNS_RDF_N    }};
static _getdns_rdata_def       atma_rdata[] = {
	{ "format"                      , GETDNS_RDF_X    }};
static _getdns_rdata_def      naptr_rdata[] = {
	{ "order"                       , GETDNS_RDF_I2   },
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "flags"                       , GETDNS_RDF_S    },
	{ "service"                     , GETDNS_RDF_S    },
	{ "regexp"                      , GETDNS_RDF_S    },
	{ "replacement"                 , GETDNS_RDF_N    }};
static _getdns_rdata_def         kx_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "exchanger"                   , GETDNS_RDF_N    }};
static _getdns_rdata_def       cert_rdata[] = {
	{ "type"                        , GETDNS_RDF_I2   },
	{ "key_tag"                     , GETDNS_RDF_I2   },
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "certificate_or_crl"          , GETDNS_RDF_B    }};
static _getdns_rdata_def         a6_rdata[] = {
	{ "a6_obsolete"                 , GETDNS_RDF_X    }};
static _getdns_rdata_def      dname_rdata[] = {
	{ "target"                      , GETDNS_RDF_N    }};
static _getdns_rdata_def        opt_rdata[] = {
	{ "options"                     , GETDNS_RDF_R    },
	{ "option_code"                 , GETDNS_RDF_I2   },
	{ "option_data"                 , GETDNS_RDF_X_S  }};
static _getdns_rdata_def        apl_rdata[] = {
	{ "apitems"                     , GETDNS_RDF_R    },
	{ "address_family"              , GETDNS_RDF_I2   },
	{ "prefix"                      , GETDNS_RDF_I1   },
	{ "n"                           , GETDNS_RDF_SPECIAL, &apl_n },
	{ "afdpart"                     , GETDNS_RDF_SPECIAL, &apl_afdpart }};
static _getdns_rdata_def         ds_rdata[] = {
	{ "key_tag"                     , GETDNS_RDF_I2   },
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "digest_type"                 , GETDNS_RDF_I1   },
	{ "digest"                      , GETDNS_RDF_X    }};
static _getdns_rdata_def      sshfp_rdata[] = {
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "fp_type"                     , GETDNS_RDF_I1   },
	{ "fingerprint"                 , GETDNS_RDF_X    }};
static _getdns_rdata_def   ipseckey_rdata[] = {
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "gateway_type"                , GETDNS_RDF_I1   },
	{ "precedence"                  , GETDNS_RDF_I1   },
	{ "gateway"                     , GETDNS_RDF_SPECIAL, &ipseckey_gateway },
	{ "public_key"                  , GETDNS_RDF_B    }};
static _getdns_rdata_def      rrsig_rdata[] = {
	{ "type_covered"                , GETDNS_RDF_I2   },
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "labels"                      , GETDNS_RDF_I1   },
	{ "original_ttl"                , GETDNS_RDF_I4   },
	{ "signature_expiration"        , GETDNS_RDF_T    },
	{ "signature_inception"         , GETDNS_RDF_T    },
	{ "key_tag"                     , GETDNS_RDF_I2   },
	{ "signers_name"                , GETDNS_RDF_N    },
	{ "signature"                   , GETDNS_RDF_B    }};
static _getdns_rdata_def       nsec_rdata[] = {
	{ "next_domain_name"            , GETDNS_RDF_N    },
	{ "type_bit_maps"               , GETDNS_RDF_X    }};
static _getdns_rdata_def     dnskey_rdata[] = {
	{ "flags"                       , GETDNS_RDF_I2   },
	{ "protocol"                    , GETDNS_RDF_I1   },
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "public_key"                  , GETDNS_RDF_B    }};
static _getdns_rdata_def      dhcid_rdata[] = {
	{ "dhcid_opaque"                , GETDNS_RDF_B    }};
static _getdns_rdata_def      nsec3_rdata[] = {
	{ "hash_algorithm"              , GETDNS_RDF_I1   },
	{ "flags"                       , GETDNS_RDF_I1   },
	{ "iterations"                  , GETDNS_RDF_I2   },
	{ "salt"                        , GETDNS_RDF_X_C  },
	{ "next_hashed_owner_name"      , GETDNS_RDF_B32_C},
	{ "type_bit_maps"               , GETDNS_RDF_X    }};
static _getdns_rdata_def nsec3param_rdata[] = {
	{ "hash_algorithm"              , GETDNS_RDF_I1   },
	{ "flags"                       , GETDNS_RDF_I1   },
	{ "iterations"                  , GETDNS_RDF_I2   },
	{ "salt"                        , GETDNS_RDF_X_C  }};
static _getdns_rdata_def       tlsa_rdata[] = {
	{ "certificate_usage"           , GETDNS_RDF_I1   },
	{ "selector"                    , GETDNS_RDF_I1   },
	{ "matching_type"               , GETDNS_RDF_I1   },
	{ "certificate_association_data", GETDNS_RDF_X    }};
static _getdns_rdata_def        hip_rdata[] = {
	{ "pk_algorithm"                , GETDNS_RDF_SPECIAL, &hip_pk_algorithm },
	{ "hit"                         , GETDNS_RDF_SPECIAL, &hip_hit },
	{ "public_key"                  , GETDNS_RDF_SPECIAL, &hip_public_key },
	{ "rendezvous_servers"          , GETDNS_RDF_N_M  }};
static _getdns_rdata_def        csync_rdata[] = {
	{ "serial"                      , GETDNS_RDF_I4   },
	{ "flags"                       , GETDNS_RDF_I2   },
	{ "type_bit_maps"               , GETDNS_RDF_X    }};
static _getdns_rdata_def        spf_rdata[] = {
	{ "text"                        , GETDNS_RDF_S_M  }};
static _getdns_rdata_def        nid_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "node_id"                     , GETDNS_RDF_AA   }};
static _getdns_rdata_def        l32_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "locator32"                   , GETDNS_RDF_A    }};
static _getdns_rdata_def        l64_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "locator64"                   , GETDNS_RDF_AA   }};
static _getdns_rdata_def         lp_rdata[] = {
	{ "preference"                  , GETDNS_RDF_I2   },
	{ "fqdn"                        , GETDNS_RDF_N    }};
static _getdns_rdata_def      eui48_rdata[] = {
	{ "eui48_address"               , GETDNS_RDF_X6   }};
static _getdns_rdata_def      eui64_rdata[] = {
	{ "eui64_address"               , GETDNS_RDF_X8   }};
static _getdns_rdata_def       tkey_rdata[] = {
	{ "algorithm"                   , GETDNS_RDF_N    },
	{ "inception"                   , GETDNS_RDF_T    },
	{ "expiration"                  , GETDNS_RDF_T    },
	{ "mode"                        , GETDNS_RDF_I2   },
	{ "error"                       , GETDNS_RDF_I2   },
	{ "key_data"                    , GETDNS_RDF_X_S  },
	{ "other_data"                  , GETDNS_RDF_X_S  }};
static _getdns_rdata_def       tsig_rdata[] = {
	{ "algorithm"                   , GETDNS_RDF_N    },
	{ "time_signed"                 , GETDNS_RDF_T6   },
	{ "fudge"                       , GETDNS_RDF_I2   },
	{ "mac"                         , GETDNS_RDF_X_S  },
	{ "original_id"                 , GETDNS_RDF_I2   },
	{ "error"                       , GETDNS_RDF_I2   },
	{ "other_data"                  , GETDNS_RDF_X_S  }};
static _getdns_rdata_def        uri_rdata[] = {
	{ "priority"                    , GETDNS_RDF_I2   },
	{ "weight"                      , GETDNS_RDF_I2   },
	{ "target"                      , GETDNS_RDF_S_L  }};
static _getdns_rdata_def        caa_rdata[] = {
	{ "flags"                       , GETDNS_RDF_I1   },
	{ "tag"                         , GETDNS_RDF_S    },
	{ "value"                       , GETDNS_RDF_S_L  }};
static _getdns_rdata_def        dlv_rdata[] = {
	{ "key_tag"                     , GETDNS_RDF_I2   },
	{ "algorithm"                   , GETDNS_RDF_I1   },
	{ "digest_type"                 , GETDNS_RDF_I1   },
	{ "digest"                      , GETDNS_RDF_X    }};

static _getdns_rr_def _getdns_rr_defs[] = {
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
	{      "CSYNC",      csync_rdata, ALEN(     csync_rdata) }, /* - 62 */
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
	{         NULL,             NULL, 0                      },
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

const _getdns_rr_def *
_getdns_rr_def_lookup(uint16_t rr_type)
{
	if (rr_type <= 257)
		return &_getdns_rr_defs[rr_type];
	else if (rr_type == 32768)
		return &_getdns_rr_defs[258];
	else if (rr_type == 32769)
		return &_getdns_rr_defs[259];
	return _getdns_rr_defs;
}

const char *
_getdns_rr_type_name(int rr_type)
{
	return _getdns_rr_def_lookup(rr_type)->name;
}

static void
write_int_rdata(gldns_buffer *buf, _getdns_rdf_type type, uint32_t value)
{
	size_t j;

	for (j = type & GETDNS_RDF_FIXEDSZ; j; j--)
		gldns_buffer_write_u8(buf,
		    (uint8_t)(value >> (8 * (j - 1))) & 0xff);
}

static void
write_bindata_rdata(gldns_buffer *buf,
    _getdns_rdf_type type, getdns_bindata *bindata)
{
	if (type & GETDNS_RDF_LEN_VAL)
		write_int_rdata(buf, type >> 8, bindata->size);

	gldns_buffer_write(buf, bindata->data, bindata->size);
}


static getdns_return_t
write_rdata_field(gldns_buffer *buf, uint8_t *rdata_start,
    const _getdns_rdata_def *rd_def, getdns_dict *rdata)
{
	getdns_return_t  r;
	getdns_list     *list;
	uint32_t         value;
	getdns_bindata  *bindata;
	size_t           i, rdf_len;

	if (rd_def->type & GETDNS_RDF_INTEGER) {
		if (!(rd_def->type & GETDNS_RDF_REPEAT)) {
			if ((r = getdns_dict_get_int(
			    rdata, rd_def->name, &value)))
				return r;
			else
				write_int_rdata(buf, rd_def->type, value);

		} else if ((r = getdns_dict_get_list(
		    rdata, rd_def->name, &list)))

			return r == GETDNS_RETURN_NO_SUCH_DICT_NAME
			          ? GETDNS_RETURN_GOOD : r;

		else for ( i = 0
			 ; GETDNS_RETURN_GOOD ==
			       (r = getdns_list_get_int(list, i, &value))
			 ; i++)
			write_int_rdata(buf, rd_def->type, value);

		
	} else if (rd_def->type & GETDNS_RDF_BINDATA) {


		if (!(rd_def->type & GETDNS_RDF_REPEAT)) {
			if ((r = getdns_dict_get_bindata(
			    rdata, rd_def->name, &bindata)))
				return r;
			else
				write_bindata_rdata(buf, rd_def->type, bindata);

		} else if ((r = getdns_dict_get_list(
		    rdata, rd_def->name, &list)))

			return r == GETDNS_RETURN_NO_SUCH_DICT_NAME
			          ? GETDNS_RETURN_GOOD : r;

		else for ( i = 0
			 ; GETDNS_RETURN_GOOD ==
			       (r = getdns_list_get_bindata(list, i, &bindata))
			 ; i++)
			write_bindata_rdata(buf, rd_def->type, bindata);


	} else if (!(rd_def->type & GETDNS_RDF_SPECIAL)) {
		/* Unknown rdata type */
		return GETDNS_RETURN_GENERIC_ERROR;

	} else if (!(rd_def->type & GETDNS_RDF_REPEAT)) {
		
		rdf_len = gldns_buffer_remaining(buf);
		r = rd_def->special->dict2wire(rdata, rdata_start,
		    gldns_buffer_current(buf), &rdf_len);
		if (r == GETDNS_RETURN_GOOD ||
		    r == GETDNS_RETURN_NEED_MORE_SPACE)
			gldns_buffer_skip(buf, rdf_len);
		if (r)
			return r;

	} else if ((r = getdns_dict_get_list(rdata, rd_def->name, &list))) {

		return r == GETDNS_RETURN_NO_SUCH_DICT_NAME
			  ? GETDNS_RETURN_GOOD : r;

	} else for ( i = 0; r == GETDNS_RETURN_GOOD; i++ ) {
		
		rdf_len = gldns_buffer_remaining(buf);
		r = rd_def->special->list2wire(list, i, rdata_start,
		    gldns_buffer_current(buf), &rdf_len);
		if (r == GETDNS_RETURN_GOOD ||
		    r == GETDNS_RETURN_NEED_MORE_SPACE)
			gldns_buffer_skip(buf, rdf_len);
	}

	return r != GETDNS_RETURN_NO_SUCH_LIST_ITEM ? r : GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_rr_dict2wire(const getdns_dict *rr_dict, gldns_buffer *buf)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	getdns_bindata *name;
	getdns_bindata *rdata_raw;
	getdns_dict *rdata;
	uint32_t rr_type;
	uint32_t rr_class = GETDNS_RRCLASS_IN;
	uint32_t rr_ttl = 0;
	const _getdns_rr_def *rr_def;
	const _getdns_rdata_def *rd_def, *rep_rd_def;
	int n_rdata_fields, rep_n_rdata_fields;
	size_t rdata_size_mark;
	uint8_t *rdata_start;
	getdns_list *list;
	size_t i;

	assert(rr_dict);
	assert(buf);

	if ((r = getdns_dict_get_bindata(rr_dict, "name", &name)))
		goto error;
	gldns_buffer_write(buf, name->data, name->size);

	if ((r = getdns_dict_get_int(rr_dict, "type", &rr_type)))
		goto error;
	gldns_buffer_write_u16(buf, (uint16_t)rr_type);

	(void) getdns_dict_get_int(rr_dict, "class", &rr_class);
	gldns_buffer_write_u16(buf, (uint16_t)rr_class);

	(void) getdns_dict_get_int(rr_dict, "ttl", &rr_ttl);
	gldns_buffer_write_u32(buf, rr_ttl);

	/* Does rdata contain compressed names?
	 * Because rdata_raw is unusable then.
	 */
	rr_def = _getdns_rr_def_lookup(rr_type);
	for ( rd_def = rr_def->rdata
	    , n_rdata_fields = rr_def->n_rdata_fields
	    ; n_rdata_fields ; n_rdata_fields-- , rd_def++ ) {

		if (rd_def->type & GETDNS_RDF_COMPRESSED)
			break;
	}

	if ((r = getdns_dict_get_dict(rr_dict, "rdata", &rdata)))
		goto error;

	if (n_rdata_fields == 0 && GETDNS_RETURN_GOOD ==
	    (r = getdns_dict_get_bindata(rdata, "rdata_raw", &rdata_raw))) {

		gldns_buffer_write_u16(buf, (uint16_t)rdata_raw->size);
		gldns_buffer_write(buf, rdata_raw->data, rdata_raw->size);

	} else if (n_rdata_fields || r == GETDNS_RETURN_NO_SUCH_DICT_NAME) {

		r = GETDNS_RETURN_GOOD;
		rdata_size_mark = gldns_buffer_position(buf);
		gldns_buffer_skip(buf, 2);
		rdata_start = gldns_buffer_current(buf);

		for ( rd_def = rr_def->rdata
		    , n_rdata_fields = rr_def->n_rdata_fields
		    ; n_rdata_fields ; n_rdata_fields-- , rd_def++ ) {

			if (rd_def->type == GETDNS_RDF_REPEAT)
				break;

			if ((r = write_rdata_field(buf,
			    rdata_start, rd_def, rdata)))
				break;
		}
		if (n_rdata_fields == 0 || r) { 
			/* pass */;

		} else if ((r = getdns_dict_get_list(
		    rdata, rd_def->name, &list))) {
			/* pass */;

		} else for ( i = 0
		           ; r == GETDNS_RETURN_GOOD
		           ; i++) {

			if ((r = getdns_list_get_dict(list, i, &rdata))) {
				if (r == GETDNS_RETURN_NO_SUCH_LIST_ITEM)
					r = GETDNS_RETURN_GOOD;
				break;
			}
			for ( rep_rd_def = rd_def + 1
			    , rep_n_rdata_fields = n_rdata_fields - 1
			    ; rep_n_rdata_fields
			    ; rep_n_rdata_fields--, rep_rd_def++ ) {

				if ((r = write_rdata_field(buf,
				    rdata_start, rep_rd_def, rdata)))
					break;
			}
		}
		gldns_buffer_write_u16_at(buf, rdata_size_mark,
		    (uint16_t)(gldns_buffer_position(buf)-rdata_size_mark-2));
	}
error:
	return r;
}

