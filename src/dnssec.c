/**
 *
 * /brief functions for DNSSEC
 *
 * In this file, the "dnssec_return_validation_chain" extension is implemented
 * (with the _getdns_get_validation_chain() function)
 * Also the function getdns_validate_dnssec is implemented.
 * DNSSEC validation as a stub combines those two functionalities, by first
 * fetching all the records that are necessary to be able to validate a
 * request (i.e. the "dnssec_return_validation_chain" extension) and then
 * performing DNSSEC validation for a request with those support records
 * (and a trust anchor of course).
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

/*
 * From the API:
 *
 * The "dnssec_return_validation_chain" extension as explained in section 3.1:
 *
 *	Applications that want to do their own validation will want to have the
 *	DNSSEC-related records for a particular response. Use the
 *	dnssec_return_validation_chain extension. The extension's value
 *	(an int) is set to GETDNS_EXTENSION_TRUE to cause a set of additional
 *	DNSSEC-related records needed for validation to be returned in the
 *	response object. This set comes as validation_chain (a list) at the top
 *	level of the response object. This list includes all resource record
 *	dicts for all the resource records (DS, DNSKEY and their RRSIGs) that
 *	are needed to perform the validation from the root up.
 *
 *
 * The getdns_validate_dnssec() function as explained in section 7:
 *
 *	If an application wants the API do perform DNSSEC validation without
 *	using the extensions, it can use the getdns_validate_dnssec() helper
 *	function.
 *
 *	getdns_return_t
 *	getdns_validate_dnssec(
 *		getdns_list     *record_to_validate,
 *		getdns_list     *bundle_of_support_records,
 *		getdns_list     *trust_anchor_records
 *	);
 *
 *	The record_to_validate is the resource record being validated together
 *	with the associated signatures. The API will use the resource records
 *	in bundle_of_support_records to construct the validation chain and the
 *	DNSKEY or DS records in trust_anchor_records as trust anchors. The
 * 	function returns one of GETDNS_DNSSEC_SECURE, GETDNS_DNSSEC_BOGUS,
 *	GETDNS_DNSSEC_INDETERMINATE, or GETDNS_DNSSEC_INSECURE. 
 */

/* Outline of operations in this file
 * ==================================
 *
 * Data structure to represent the delegation/referal hierarchy
 * ------------------------------------------------------------
 * Both the "dnssec_return_validation_chain" extension, and the 
 * getdns_validate_dnssec() function use the same structs to represent the 
 * involved pieces of the DNS in a hierarchical manner.
 *
 * However, the tree is not represented from the root, but from the RRsets that
 * need to be validated.  The RRset to validate is a member of the chain_head
 * struct for this.  The chain_head struct has a "next" member to form a linked
 * list of RRsets to validate.
 *
 * The chain_head struct also has a "parent" member to a linked list of 
 * chain_node structs (linked with the "parent" member of those chain_nodes).
 * For each label in the name of the rrset in a chain_head, is a chain_node,
 * all the way to the root.  The last chain_node is thus always the root, for
 * every chain_head.
 *
 * The construction functions for this datastructure make sure there is always
 * a single chain_node representing the same name.  They also make sure space
 * for chain_head + the number of extra chain_nodes needed is allocated in a
 * single region, so that on destruction one only has to free the chain_heads.
 *
 * A chain_node contains two RRset members, "dnskey" and "ds" which represent
 * the potential client side DNSKEYs and the parent side DS records of a 
 * potential zonecut at this point.  Whether or not there is an actual zone
 * cut is determined separately.  With the "dnssec_return_validation_chain"
 * extension by scheduling queries, and with the getdns_validation_dnssec()
 * function by provisioning the support records at the chain nodes.
 *
 * In the construction functions a chain_head is created for every RRset in
 * the answer and authority section of a given packet (except for synthesized
 * CNAMEs).  Furthermore, if the queries for name/class/type is not in the
 * packet, a chain_head for the non-existent rrset is created too, to that
 * it will be evaluated for non-existence later in the validation process.
 *
 * The chain_head and chain_node structs are defined in section:
 * "Validation Chain Data Structs".  The functions to construct the hierarchy
 * are defined in section "Validation Chain Construction".  When the 
 * construction functions are called for the purpose of the 
 * "dnssec_return_validation_chain" extension, queries to provision the
 * chain_nodes are scheduled.  Function theretofore are in section:
 * "Schedule Queries to Provision Validation Chain"
 *
 *
 * getdns_rrset
 * ------------
 * RRsets used in the structure described above are represented by the 
 * getdns_rrset struct.  They consist of name/rr_class and rr_type members
 * plus a reference to the wireformat packet that should contain the RRset.
 *
 * The actual RR's in the rrset and the signatures are only accessed via
 * iterators; substantiated with the rrtype_iter struct to iterate over RRs
 * in a getdns_rrset, and the rrsig_iter to iterate over the RRSIGs covering
 * the RRs in the getdns_rrset.
 *
 * The getdns_rrsets are already equiped with name/rr_class and rr_type when
 * constructing the linked list of chain_nodes up to the root for a chain_head.
 * They are substantiated with the wireformat packets that are returned with 
 * the queries that were sheduled in the context of the 
 * "dnssec_return_validation_chain" extension.
 *
 * Note that the NSEC(3) RRsets proving the non-existance of a getdns_rrset
 * can be found by processing that getdns_rrset, as it contains the pointer
 * to the wireformat data that should either contain the RRset or the proof
 * of non-existance.
 *
 * The getdns_validate_dnssec() function, after it constructed the chain_heads
 * hierarchy, creates an artifical packet for the support records and equips
 * all the ds and dnskey getdns_rrsets on the chain_nodes with this packet.
 *
 * The getdns_rrset + support function and data types are defined in section:
 * "getdns_rrset + Support Iterators"
 *
 *
 * Validation
 * ----------
 * Validation of a constructed chain is done by the 
 * chain_set_netreq_dnssec_status() function when validating in stub mode.
 * And with the chain_validate_dnssec() function when using the 
 * getdns_validate_dnssec() function.  They are the same, except that 
 * chain_set_netreq_dnssec_status() evaluates DNSSEC status per network
 * request and chain_validate_dnssec() does it for the whole chain.
 *
 * They both evaluate the DNSSEC status for each head in turn.  The worst
 * DNSSEC status determines the status of all heads evaluated.  Where
 * INSECURE is worse than SECURE, and BOGUS is worse than INSECURE.
 *
 * For each head, the closest (most labels still a parent of the head's name)
 * trust anchor is tried.  Without fitting trust anchors, DNSSEC_INDETERMINATE
 * is returned.
 *
 * Security status for a head (with a specific trust anchor) is evaluated by
 * first finding a authenticated keyset from the parent chain_nodes, and then
 * evaluating the rrset of the head (existent or not) with that keyset.
 *
 * Functions that implement DNSSEC validation are in section:
 * "DNSSEC Validation".
 *
 * Many functions are of key verification boolean return type; e.g.
 * key_proves_non_existance(), ds_authenticates_keys(), a_key_signed_rrset()
 * These will return the keytag identifying the key that was used to 
 * authenticate + 0x10000 to allow keytag 0.
 *
 * These returned keytag's are used later with function
 * append_rrs2val_chain_list() to return a "dnssec_validation_chain" that 
 * enumerates a single RRSIG per RRset.  This can be found in section:
 * "dnssec_return_validation_chain Extension".
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <openssl/sha.h>
#include "getdns/getdns.h"
#include "config.h"
#include "context.h"
#include "util-internal.h"
#include "types-internal.h"
#include "dnssec.h"
#include "rr-dict.h"
#include "gldns/str2wire.h"
#include "gldns/wire2str.h"
#include "gldns/keyraw.h"
#include "gldns/parseutil.h"
#include "general.h"
#include "dict.h"
#include "list.h"
#include "util/val_secalgo.h"

 /* Maximum number of canonical name redirections for one name */
#define MAX_CNAMES 100

#define SIGNATURE_VERIFIED         0x10000
#define NSEC3_ITERATION_COUNT_HIGH 0x20000
#define NO_SUPPORTED_ALGORITHMS    0x40000

/*******************  Frequently Used Utility Functions  *********************
 *****************************************************************************/

inline static size_t _dname_len(uint8_t *name)
{
	uint8_t *p;
	for (p = name; *p; p += *p + 1)
		/* pass */
		;
	return p - name + 1;
}

inline static size_t _dname_label_count(uint8_t *name)
{
	size_t c;
	for (c = 0; *name; name += *name + 1, c++)
		/* pass */
		;
	return c;
}

inline static int _dname_equal(const uint8_t *left, const uint8_t *right)
{
	return _getdns_dname_equal(left, right);
}

static int _dname_is_parent(
    const uint8_t * const parent, const uint8_t *subdomain)
{
	while (*subdomain) {
		if (_dname_equal(parent, subdomain))
			return 1;

		subdomain += *subdomain + 1;
	}
	return *parent == 0;
}

static uint8_t *_dname_label_copy(uint8_t *dst, const uint8_t *src, size_t dst_len)
{
	uint8_t *r = dst, i;

	if (!src || *src + 1 > dst_len)
		return NULL;

	for (i = (*dst++ = *src++); i ; i--)
		*dst++ = tolower(*src++);

	return r;
}

inline static void _dname_canonicalize(uint8_t *dname)
{
	uint8_t *next_label;

	while (*dname) {
		next_label = dname + *dname + 1;
		dname += 1;
		while (dname < next_label) {
			*dname = (uint8_t)tolower((unsigned char)*dname);
			dname++;
		}
	}
}

/* Fills the array pointed to by labels (of at least 128 uint8_t * pointers)
 * with pointers to labels in given dname in reversed order.  So that
 * labels[0] will point to the root.
 * labels[1] will point to the tld etc.
 * A pointer just past the last assigned array element will be returned.
 *
 * So if dname would be "www.getdnsapi.net"
 * labels[0] will be "."
 * labels[1] will be "net."
 * labels[2] will be "getdnsapi.net."
 * labels[3] will be "www.getdnsapi.net."
 * The returned value will be &labels[4]
 */
static uint8_t **reverse_labels(uint8_t *dname, uint8_t **labels)
{
	if (*dname)
		labels = reverse_labels(dname + *dname + 1, labels);
	*labels = dname;
	return labels + 1;
}

static uint8_t *dname_shared_parent(uint8_t *left, uint8_t *right)
{
	uint8_t *llabels[128], *rlabels[128], **last_llabel, **last_rlabel,
		**llabel, **rlabel, *l, *r, sz;

	last_llabel = reverse_labels(left, llabels);
	last_rlabel = reverse_labels(right, rlabels);

	/* Always at least one label (the root) */
	assert(last_llabel > llabels);
	assert(last_rlabel > rlabels);
	assert(*llabels[0] == 0);
	assert(*rlabels[0] == 0);

	for ( llabel = &llabels[1], rlabel = &rlabels[1]
	    ; llabel < last_llabel
	    ; llabel++, rlabel++ ) {

		sz = **llabel;
		if (   rlabel == last_rlabel 
		    || **llabel != **rlabel)
			return llabel[-1];

		for (l = *llabel+1, r = *rlabel+1; sz; l++, r++, sz-- ) 
			if (*l != *r && tolower((unsigned char)*l) !=
					tolower((unsigned char)*r))
				return llabel[-1];
	}
	return llabel[-1];
}

static int dname_compare(uint8_t *left, uint8_t *right)
{
	uint8_t *llabels[128], *rlabels[128], **last_llabel, **last_rlabel,
		**llabel, **rlabel, *l, *r, lsz, rsz;

	last_llabel = reverse_labels(left, llabels);
	last_rlabel = reverse_labels(right, rlabels);

	for ( llabel = llabels, rlabel = rlabels
	    ; llabel < last_llabel
	    ; llabel++, rlabel++ ) {

		if (rlabel == last_rlabel)
			return 1;

		for ( l = *llabel, lsz = *l++, r = *rlabel, rsz = *r++
		    ; lsz; l++, r++, lsz--, rsz-- ) {

			/* No compression pointers here */
			assert(lsz <= 63);
			assert(rsz <= 63);

			if (!rsz)
				return 1;
			if (*l != *r && tolower((unsigned char)*l) !=
					tolower((unsigned char)*r)) {
				if (tolower((unsigned char)*l) <
				    tolower((unsigned char)*r))
					return -1;
				return 1;
			}
		}
		if (rsz)
			return -1;
	}
	return rlabel == last_rlabel ? 0 : -1;
}

static int bitmap_has_type(_getdns_rdf_iter *bitmap, uint16_t rr_type)
{
	uint8_t *dptr, *dend;
	uint8_t window  = rr_type >> 8;
	uint8_t subtype = rr_type & 0xFF;

	if (!bitmap || (dptr = bitmap->pos) == (dend = bitmap->nxt))
		return 0;

	/* Type Bitmap = ( Window Block # | Bitmap Length | Bitmap ) +
	 *                 dptr[0]          dptr[1]         dptr[2:]
	 */
	while (dptr < dend && dptr[0] <= window) {
		if (dptr[0] == window && subtype / 8 < dptr[1] &&
		    dptr + dptr[1] + 2 <= dend)
			return dptr[2 + subtype / 8] & (0x80 >> (subtype % 8));
		dptr += dptr[1] + 2; /* next window */
	}
	return 0;
}

#if defined(SEC_DEBUG) && SEC_DEBUG
inline static void debug_sec_print_rr(const char *msg, _getdns_rr_iter *rr)
{
	char str_spc[8192], *str = str_spc;
	size_t str_len = sizeof(str_spc);
	uint8_t *data = rr->pos;
	size_t data_len = rr->nxt - rr->pos;

	if (!rr || !rr->pos) {
		DEBUG_SEC("%s<nil>\n", msg);
		return;
	}
	(void) gldns_wire2str_rr_scan(
	    &data, &data_len, &str, &str_len, rr->pkt, rr->pkt_end - rr->pkt);
	DEBUG_SEC("%s%s", msg, str_spc);
}
inline static void debug_sec_print_dname(const char *msg, uint8_t *label)
{
	char str[1024];

	if (label && gldns_wire2str_dname_buf(label, 256, str, sizeof(str)))
		DEBUG_SEC("%s%s\n", msg, str);
	else
		DEBUG_SEC("%s<nil>\n", msg);
}
inline static void debug_sec_print_pkt(
		const char *msg, uint8_t *pkt, size_t pkt_len)
{
	char *str;
	DEBUG_SEC("%s%s\n", msg, (str = gldns_wire2str_pkt(pkt, pkt_len)));
	if (str) free(str);
}
#else
#define debug_sec_print_rr(...) DEBUG_OFF(__VA_ARGS__)
#define debug_sec_print_dname(...) DEBUG_OFF(__VA_ARGS__)
#define debug_sec_print_pkt(...) DEBUG_OFF(__VA_ARGS__)
#endif


/*******************  getdns_rrset + Support Iterators  **********************
 *****************************************************************************/


/* Utility functions to read rr_type and rr_class from a rr iterator */
static inline uint16_t rr_iter_type(_getdns_rr_iter *rr)
{ return rr->rr_type + 2 <= rr->nxt ? gldns_read_uint16(rr->rr_type) : 0; }
static inline uint16_t rr_iter_class(_getdns_rr_iter *rr)
{ return rr->rr_type + 4 <= rr->nxt ? gldns_read_uint16(rr->rr_type + 2) : 0; }

/* Utility function to compare owner name of rr with name */
static int rr_owner_equal(_getdns_rr_iter *rr, uint8_t *name)
{
	uint8_t owner_spc[256], *owner;
	size_t  owner_len = sizeof(owner_spc);

	return (owner = _getdns_owner_if_or_as_decompressed(rr,  owner_spc
	                                                          , &owner_len))
	    && _dname_equal(owner, name);
}

/* First a few filter functions that filter a RR iterator to point only
 * to RRs with certain constraints (and moves on otherwise).
 */

/* Filter that only iterates over the ANSWER and AUTHORITY section */
static _getdns_rr_iter *rr_iter_ansauth(_getdns_rr_iter *rr)
{
	while (rr && rr->pos && !(
	    _getdns_rr_iter_section(rr) == GLDNS_SECTION_ANSWER ||
	    _getdns_rr_iter_section(rr) == GLDNS_SECTION_AUTHORITY))

		rr = _getdns_rr_iter_next(rr);

	return rr && rr->pos ? rr : NULL;
}

/* Filter that only iterates over RRs with a certain name/class/type */
static _getdns_rr_iter *rr_iter_name_class_type(_getdns_rr_iter *rr,
    uint8_t *name, uint16_t rr_class, uint16_t rr_type)
{
	while (rr_iter_ansauth(rr) && !(
	    rr_iter_type(rr)  == rr_type  &&
	    rr_iter_class(rr) == rr_class &&
	    rr_owner_equal(rr, name)))

		rr = _getdns_rr_iter_next(rr);

	return rr && rr->pos ? rr : NULL;
}

/* Filter that only iterates over RRs that do not have a name/class/type */
static _getdns_rr_iter *rr_iter_not_name_class_type(_getdns_rr_iter *rr,
    uint8_t *name, uint16_t rr_class, uint16_t rr_type)
{
	while (rr_iter_ansauth(rr) && (
	    rr_iter_type(rr)  == GETDNS_RRTYPE_RRSIG || (
	    rr_iter_type(rr)  == rr_type  &&
	    rr_iter_class(rr) == rr_class &&
	    rr_owner_equal(rr, name))))

		rr = _getdns_rr_iter_next(rr);
	
	return rr && rr->pos ? rr : NULL;
}

/* Filter that only iterates over RRs that are of type RRSIG, that cover
 * a RRset with a certain name/class/type
 */
static _getdns_rr_iter *rr_iter_rrsig_covering(_getdns_rr_iter *rr,
    uint8_t *name, uint16_t rr_class, uint16_t rr_type)
{
	while (rr_iter_ansauth(rr) && !(
	    rr_iter_type(rr)  == GETDNS_RRTYPE_RRSIG &&
	    rr_iter_class(rr) == rr_class &&
	    rr->rr_type + 12 <= rr->nxt &&
	    gldns_read_uint16(rr->rr_type + 10) == rr_type && 
	    rr_owner_equal(rr, name)))

		rr = _getdns_rr_iter_next(rr);

	return rr && rr->pos ? rr : NULL;
}

typedef struct getdns_rrset {
	uint8_t  *name;
	uint16_t  rr_class;
	uint16_t  rr_type;
	uint8_t  *pkt;
	size_t    pkt_len;
} getdns_rrset;

typedef struct rrtype_iter {
	_getdns_rr_iter  rr_i;
	getdns_rrset        *rrset;
} rrtype_iter;

typedef struct rrsig_iter {
	_getdns_rr_iter  rr_i;
	getdns_rrset        *rrset;
} rrsig_iter;

static rrtype_iter *rrtype_iter_next(rrtype_iter *i)
{
	return (rrtype_iter *) rr_iter_name_class_type(
	    _getdns_rr_iter_next(&i->rr_i),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type);
}

static rrtype_iter *rrtype_iter_init(rrtype_iter *i, getdns_rrset *rrset)
{
	i->rrset = rrset;
	return (rrtype_iter *) rr_iter_name_class_type(
	    _getdns_rr_iter_init(&i->rr_i, rrset->pkt, rrset->pkt_len ),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type);
}

inline static int rrset_has_rrs(getdns_rrset *rrset)
{
	rrtype_iter rr_spc;
	return rrtype_iter_init(&rr_spc, rrset) != NULL;
}

static rrsig_iter *rrsig_iter_next(rrsig_iter *i)
{
	return (rrsig_iter *) rr_iter_rrsig_covering(
	    _getdns_rr_iter_next(&i->rr_i),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type);
}

static rrsig_iter *rrsig_iter_init(rrsig_iter *i, getdns_rrset *rrset)
{
	i->rrset = rrset;
	return (rrsig_iter *) rr_iter_rrsig_covering(
	    _getdns_rr_iter_init(&i->rr_i, rrset->pkt, rrset->pkt_len),
	    i->rrset->name, i->rrset->rr_class, i->rrset->rr_type);
}

inline static int rrset_has_rrsigs(getdns_rrset *rrset)
{
	rrsig_iter rrsig;
	return rrsig_iter_init(&rrsig, rrset) != NULL;
}

#if defined(SEC_DEBUG) && SEC_DEBUG
static void debug_sec_print_rrset(const char *msg, getdns_rrset *rrset)
{
	char owner[1024];
	char buf_space[2048];
	gldns_buffer buf;
	rrtype_iter *rr, rr_space;
	rrsig_iter  *rrsig, rrsig_space;
	size_t i;

	if (!rrset) {
		DEBUG_SEC("<nil>");
		return;
	}
	gldns_buffer_init_frm_data(&buf, buf_space, sizeof(buf_space));
	if (gldns_wire2str_dname_buf(rrset->name, 256, owner, sizeof(owner)))
		gldns_buffer_printf(&buf, "%s ", owner);
	else	gldns_buffer_printf(&buf, "<nil> ");

	switch (rrset->rr_class) {
	case GETDNS_RRCLASS_IN	: gldns_buffer_printf(&buf, "IN ")  ; break;
	case GETDNS_RRCLASS_CH	: gldns_buffer_printf(&buf, "CH ")  ; break;
	case GETDNS_RRCLASS_HS	: gldns_buffer_printf(&buf, "HS ")  ; break;
	case GETDNS_RRCLASS_NONE: gldns_buffer_printf(&buf, "NONE "); break;
	case GETDNS_RRCLASS_ANY	: gldns_buffer_printf(&buf, "ANY ") ; break;
	default			: gldns_buffer_printf(&buf, "CLASS%d "
						          , rrset->rr_class);
				  break;
	}
	gldns_buffer_printf(&buf, "%s", _getdns_rr_type_name(rrset->rr_type));

	gldns_buffer_printf(&buf, ", rrs:");
	for ( rr = rrtype_iter_init(&rr_space, rrset), i = 1
	    ; rr
	    ; rr = rrtype_iter_next(rr), i++)
		gldns_buffer_printf(&buf, " %d", (int)i);

	gldns_buffer_printf(&buf, ", rrsigs:");
	for ( rrsig = rrsig_iter_init(&rrsig_space, rrset), i = 1
	    ; rrsig
	    ; rrsig = rrsig_iter_next(rrsig), i++)
		gldns_buffer_printf(&buf, " %d", (int)i);

	DEBUG_SEC("%s%s\n", msg, buf_space);
}
#else
#define debug_sec_print_rrset(...) DEBUG_OFF(__VA_ARGS__)
#endif

/* The rrset_iter manifests an iterator of a wireformat packet that will return
 * all unique rrsets within that packet in turn.
 */
typedef struct rrset_iter rrset_iter;
struct rrset_iter {
	getdns_rrset        rrset;
	uint8_t             name_spc[256];
	size_t              name_len;
	_getdns_rr_iter rr_i;
};

static rrset_iter *rrset_iter_init(rrset_iter *i, uint8_t *pkt, size_t pkt_len)
{
	_getdns_rr_iter *rr;

	i->rrset.name = i->name_spc;
	i->rrset.pkt = pkt;
	i->rrset.pkt_len = pkt_len;
	i->name_len = 0;

	for ( rr = _getdns_rr_iter_init(&i->rr_i, pkt, pkt_len)
	    ;(rr = rr_iter_ansauth(rr))
	    ; rr = _getdns_rr_iter_next(rr)) {

		if ((i->rrset.rr_type = rr_iter_type(rr))
		    == GETDNS_RRTYPE_RRSIG)
			continue;

		i->rrset.rr_class = rr_iter_class(rr);

		if (!(i->rrset.name = _getdns_owner_if_or_as_decompressed(
		    rr, i->name_spc, &i->name_len)))
			continue;

		return i;
	}
	return NULL;
}

static rrset_iter *rrset_iter_rewind(rrset_iter *i)
{
	return rrset_iter_init(i, i->rrset.pkt, i->rrset.pkt_len);
}

static rrset_iter *rrset_iter_next(rrset_iter *i)
{
	_getdns_rr_iter *rr;

	if (!(rr = i && i->rr_i.pos ? &i->rr_i : NULL))
		return NULL;

	if (!(rr = rr_iter_not_name_class_type(rr,
	    i->rrset.name, i->rrset.rr_class, i->rrset.rr_type)))
		return NULL;

	i->rrset.rr_type  = rr_iter_type(rr);
	i->rrset.rr_class = rr_iter_class(rr);
	if (!(i->rrset.name = _getdns_owner_if_or_as_decompressed(
		    rr, i->name_spc, &i->name_len)))

		/* This is safe, because rr_iter_not_name_class_type will shift
		 * the iterator forward because at least name does not match.
		 * Goal is to skip broken compression pointer issues but keep
		 * processing the packet.
		 */
		return rrset_iter_next(i);

	return i;
}

static getdns_rrset *rrset_iter_value(rrset_iter *i)
{
	if (!i)
		return NULL;
	if (!i->rr_i.pos)
		return NULL;
	return &i->rrset;
}

static getdns_rrset *rrset_by_type(
    rrset_iter *i_spc, getdns_network_req *netreq, uint16_t rr_type)
{
	rrset_iter   *i;
	getdns_rrset *rrset;

	for ( i = rrset_iter_init(i_spc,netreq->response,netreq->response_len)
	    ; i
	    ; i = rrset_iter_next(i)) {

		rrset = rrset_iter_value(i);
		if (rrset->rr_type == rr_type) /* Check class too? */
			return rrset;
	}
	return NULL;
}


/*********************  Validation Chain Data Structs  ***********************
 *****************************************************************************/

typedef struct chain_head chain_head;
typedef struct chain_node chain_node;

struct chain_head {
	struct mem_funcs  my_mf;

	chain_head         *next;
	chain_node         *parent;
	size_t              node_count; /* Number of nodes attached directly
	                                 * to this head.  For cleaning.  */
	getdns_rrset        rrset;
	getdns_network_req *netreq;
	int                 signer;

	uint8_t             name_spc[];
};

struct chain_node {
	chain_node  *parent;
	
	getdns_rrset        dnskey;
	getdns_network_req *dnskey_req;
	int                 dnskey_signer;

	getdns_rrset        ds;
	getdns_network_req *ds_req;
	int                 ds_signer;

	getdns_network_req *soa_req;

	chain_head  *chains;
};

/*********************  Validation Chain Construction  ***********************
 *****************************************************************************/

/* When construction is done in the context of stub validation, the requests
 * to equip the chain nodes with their RR sets are done alongside construction.
 * Hence they need to be enumerated before the construction functions.
 */
static void val_chain_sched(chain_head *head, uint8_t *dname);
static void val_chain_sched_ds(chain_head *head, uint8_t *dname);
static void val_chain_sched_signer(chain_head *head, rrsig_iter *rrsig);
static void val_chain_sched_soa(chain_head *head, uint8_t *dname);

static chain_head *add_rrset2val_chain(struct mem_funcs *mf,
    chain_head **chain_p, getdns_rrset *rrset, getdns_network_req *netreq)
{
	chain_head *head;
	uint8_t    *labels[128], **last_label, **label;

	size_t      max_labels; /* max labels in common */
	chain_head *max_head;
	chain_node *max_node;

	size_t      dname_len, head_sz, node_count, n;
	uint8_t    *dname, *region;
	chain_node *node;

	last_label = reverse_labels(rrset->name, labels);

	/* Try to find a chain with the most overlapping labels.
	 * max_labels will be the number of labels in common from the root
	 *            (so at least one; the root)
	 * max_head   will be the head of the chain with max # labels in common
	 */
	max_head = NULL;
	max_labels = 0;
	for (head = *chain_p; head; head = head->next) {
		/* Also, try to prevent adding double rrsets */
		if (   rrset->rr_class == head->rrset.rr_class
		    && rrset->rr_type  == head->rrset.rr_type
		    && rrset->pkt      == head->rrset.pkt
		    && rrset->pkt_len  == head->rrset.pkt_len
		    && _dname_equal(rrset->name, head->rrset.name))
			return NULL;

		for (label = labels; label < last_label; label++) {
			if (! _dname_is_parent(*label, head->rrset.name))
				break;
		}
		if (label - labels > max_labels) {
			max_labels = label - labels;
			max_head = head;
		}
	}
	/* Chain found.  Now set max_node to the point in the chain where nodes
	 *               will be common.
	 */
	if (max_head) {
		for ( node = max_head->parent, n = 0
		    ; node
		    ; node = node->parent, n++);

		for ( n -= max_labels, node = max_head->parent
		    ; n
		    ; n--, node = node->parent);

		max_node = node;
	} else
		max_node = NULL;

	/* node_count is the amount of nodes to still allocate.
	 * the last one's parent has to hook into the max_node.
	 */
	dname_len = *labels - last_label[-1] + 1;
	head_sz = (sizeof(chain_head) + dname_len + 7) / 8 * 8;
	node_count = last_label - labels - max_labels;
	DEBUG_SEC( "%zu labels in common. %zu labels to allocate\n"
	         , max_labels, node_count);

	if (! (region = GETDNS_XMALLOC(*mf, uint8_t, head_sz + 
	    node_count * sizeof(chain_node))))
		return NULL;
	
	/* Append the head on the linked list of heads */
	for (head = *chain_p; head && head->next; head = head->next)
		;
	if  (head)
		head = head->next = (chain_head *)region;
	else
		head = *chain_p   = (chain_head *)region;

	head->my_mf = *mf;
	head->next = NULL;
	head->rrset.name = head->name_spc;
	memcpy(head->name_spc, rrset->name, dname_len);
	head->rrset.rr_class = rrset->rr_class;
	head->rrset.rr_type = rrset->rr_type;
	head->rrset.pkt = rrset->pkt;
	head->rrset.pkt_len = rrset->pkt_len;
	head->netreq = netreq;
	head->signer = 0;
	head->node_count = node_count;

	if (!node_count) {
		head->parent = max_head->parent;
		return head;
	}

	/* Initialize the nodes */

	for ( head->parent = node = (chain_node *)(region + head_sz),
	      dname = head->rrset.name
	    ; node_count
	    ; node_count--, node = node->parent =&node[1], dname += *dname + 1) {

		node->ds.name         = dname;
		node->dnskey.name     = dname;
		node->ds.rr_class     = head->rrset.rr_class;
		node->dnskey.rr_class = head->rrset.rr_class;
		node->ds.rr_type      = GETDNS_RRTYPE_DS;
		node->dnskey.rr_type  = GETDNS_RRTYPE_DNSKEY;
		node->ds.pkt          = NULL;
		node->ds.pkt_len      = 0;
		node->dnskey.pkt      = NULL;
		node->dnskey.pkt_len  = 0;
		node->ds_req          = NULL;
		node->dnskey_req      = NULL;
		node->soa_req         = NULL;
		node->ds_signer       = 0;
		node->dnskey_signer   = 0;

		node->chains          = *chain_p;
	}
	/* On the first chain, max_node == NULL.
	 * Schedule a root DNSKEY query, we always need that.
	 */
	if (!(node[-1].parent = max_node))
		val_chain_sched(head, (uint8_t *)"\0");

	return head;
}

static int is_synthesized_cname(getdns_rrset *cname)
{
	rrset_iter *i, i_spc;
	getdns_rrset *dname;
	rrtype_iter rr_spc, *rr;
	_getdns_rdf_iter rdf_spc, *rdf;
	rrtype_iter drr_spc, *drr;
	_getdns_rdf_iter drdf_spc, *drdf;
	uint8_t cname_rdata_spc[256], *cname_rdata,
	        dname_rdata_spc[256], *dname_rdata,
		synth_name[256],
	       *synth_name_end = synth_name + sizeof(synth_name) - 1, *s, *c;
	size_t cname_rdata_len = sizeof(cname_rdata_spc),
	       dname_rdata_len = sizeof(dname_rdata_len),
	       cname_labels, dname_labels;

	/* Synthesized CNAMEs don't have RRSIGs */
	if (   cname->rr_type != GETDNS_RRTYPE_CNAME
	    || rrset_has_rrsigs(cname))
		return 0;

	/* Get canonical name rdata field */
	if (   !(rr = rrtype_iter_init(&rr_spc, cname))
	    || !(rdf = _getdns_rdf_iter_init(&rdf_spc, &rr->rr_i))
	    || !(cname_rdata = _getdns_rdf_if_or_as_decompressed(
			    rdf, cname_rdata_spc, &cname_rdata_len)))
		return 0;

	/* Find a matching DNAME */
	for ( i = rrset_iter_init(&i_spc, cname->pkt, cname->pkt_len)
	    ; i
	    ; i = rrset_iter_next(i)) {

		dname = rrset_iter_value(i);
		if (   dname->rr_type != GETDNS_RRTYPE_DNAME
		    /* DNAME->owner is parent of CNAME->owner */
		    || !_dname_is_parent(dname->name, cname->name))
			continue;


		dname_labels = _dname_label_count(dname->name);
		cname_labels = _dname_label_count(cname->name);

		/* Synthesize the canonical name.
		 * First copy labels(cname) - labels(dname) labels from 
		 * CNAME's owner name, then append DNAME rdata field.
		 * If it matches CNAME's rdata field then it was synthesized
		 * with this DNAME.
		 */
		cname_labels -= dname_labels;
		for ( c = cname->name, s = synth_name
		    ; cname_labels && s +  *c + 1 < synth_name_end
		    ; cname_labels--, c += *c + 1, s += *s + 1 ) {

			memcpy(s, c, *c + 1);
		}
		if (cname_labels)
			continue;

		/* Get DNAME's rdata field */
		if (   !(drr = rrtype_iter_init(&drr_spc, dname))
		    || !(drdf=_getdns_rdf_iter_init(&drdf_spc,&drr->rr_i))
		    || !(dname_rdata = _getdns_rdf_if_or_as_decompressed(
				    drdf, dname_rdata_spc, &dname_rdata_len)))
			continue;

		if (s + _dname_len(dname_rdata) > synth_name_end)
			continue;

		memcpy(s, dname_rdata, _dname_len(dname_rdata));
		debug_sec_print_dname("Synthesized name: ", synth_name);
		debug_sec_print_dname("  Canonical name: ", cname_rdata);
		if (_dname_equal(synth_name, cname_rdata))
			return 1;
	}
	return 0;
}

/* Create the validation chain structure for the given packet.
 * When netreq is set, queries will be scheduled for the DS
 * and DNSKEY RR's for the nodes on the validation chain.
 *
 * Scheduling is as follows.
 * If the RRset has a signature, signer name is followed to schedule DS/DNSKEY.
 * Otherwise, if the RRSET is a SOA, owner name is followed to schedule DS
 * Otherwise, if the RRset is a CNAME, a SOA query is scheduled for the parent
 * Otherwise, a SOA query is scheduled for the owner name.
 *
 * When a SOA query was successful, a query for DS will follow for that
 * owner name.
 */
static void add_pkt2val_chain(struct mem_funcs *mf,
    chain_head **chain_p, uint8_t *pkt, size_t pkt_len,
    getdns_network_req *netreq)
{
	rrset_iter *i, i_spc;
	getdns_rrset *rrset;
	rrsig_iter *rrsig, rrsig_spc;
	size_t n_rrsigs;
	chain_head *head;

	assert(pkt);
	assert(pkt_len >= GLDNS_HEADER_SIZE);

	/* For all things with signatures, create a chain */

	/* For all things without signature, find SOA (zonecut) and query DS */

	for ( i = rrset_iter_init(&i_spc, pkt, pkt_len)
	    ; i
	    ; i = rrset_iter_next(i)) {

		rrset = rrset_iter_value(i);
		debug_sec_print_rrset("rrset: ", rrset);

		/* Schedule validation for everything, except from DNAME
		 * synthesized CNAME's 
		 */
		if (is_synthesized_cname(rrset))
			continue;

		if (!(head = add_rrset2val_chain(mf, chain_p, rrset, netreq)))
			continue;

		for ( rrsig = rrsig_iter_init(&rrsig_spc, rrset), n_rrsigs = 0
		    ; rrsig
		    ; rrsig = rrsig_iter_next(rrsig), n_rrsigs++) {
			
			/* Signature, so lookup DS/DNSKEY at signer's name */
			val_chain_sched_signer(head, rrsig);
		}
		if (n_rrsigs)
			continue;

		/* No signatures found for this RRset */
		if (rrset->rr_type == GETDNS_RRTYPE_SOA)
			val_chain_sched_ds(head, rrset->name);
		else if (rrset->rr_type == GETDNS_RRTYPE_CNAME)
			val_chain_sched_soa(head, rrset->name + *rrset->name + 1);
		else
			val_chain_sched_soa(head, rrset->name);
	}
}

/* For NOERROR/NODATA or NXDOMAIN responses add extra rrset to 
 * the validation chain so the denial of existence will be
 * checked eventually.
 * But only if we know the question of course...
 */
static void add_question2val_chain(struct mem_funcs *mf,
    chain_head **chain_p, uint8_t *pkt, size_t pkt_len,
    uint8_t *qname, uint16_t qtype, uint16_t qclass,
    getdns_network_req *netreq)
{
	getdns_rrset q_rrset;
	uint8_t cname_spc[256];
	size_t cname_len = sizeof(cname_spc);
	size_t anti_loop;
	_getdns_rdf_iter rdf_spc, *rdf;
	rrtype_iter *rr, rr_spc;

	chain_head *head;

	assert(pkt);
	assert(pkt_len >= GLDNS_HEADER_SIZE);
	assert(qname);

	/* First find the canonical name for the question */
	q_rrset.name     = qname;
	q_rrset.rr_type  = GETDNS_RRTYPE_CNAME;
	q_rrset.rr_class = qclass;
	q_rrset.pkt      = pkt;
	q_rrset.pkt_len  = pkt_len;

	for (anti_loop = MAX_CNAMES; anti_loop; anti_loop--) {
		if (!(rr = rrtype_iter_init(&rr_spc, &q_rrset)))
			break;
		if (!(rdf = _getdns_rdf_iter_init(&rdf_spc, &rr->rr_i)))
			break;
		q_rrset.name = _getdns_rdf_if_or_as_decompressed(
				rdf, cname_spc, &cname_len);
	}

	/* If the qtype was a CNAME, and we got one, we'r done.
	 * We asked for it directly, so no redirection applies.
	 * Otherwise we have to check the referred to name/qtype.
	 */
	if (qtype == GETDNS_RRTYPE_CNAME && q_rrset.name != qname)
		return;

	q_rrset.rr_type  = qtype;
	if (!(rr = rrtype_iter_init(&rr_spc, &q_rrset))) {
		/* No answer for the question.  Add a head for this rrset
		 * anyway, to validate proof of non-existance, or to find
		 * proof that the packet is insecure.
		 */
		debug_sec_print_rrset("Adding NX rrset: ", &q_rrset);
		head = add_rrset2val_chain(mf, chain_p, &q_rrset, netreq);

		/* On empty packet, find SOA (zonecut) for the qname */
		if (head && GLDNS_ANCOUNT(pkt) == 0 && GLDNS_NSCOUNT(pkt) == 0)

			val_chain_sched_soa(head, q_rrset.name);
	}
}


/*************  Schedule Queries to Provision Validation Chain ***************
 *****************************************************************************/

static void check_chain_complete(chain_head *chain);
static void val_chain_node_soa_cb(getdns_dns_req *dnsreq);
static void val_chain_sched_soa_node(chain_node *node)
{
	getdns_context *context;
	getdns_eventloop *loop;
	getdns_dns_req *dnsreq;
	char  name[1024];

	context = node->chains->netreq->owner->context;
	loop    = node->chains->netreq->owner->loop;

	if (!gldns_wire2str_dname_buf(node->ds.name, 256, name, sizeof(name)))
		return;

	DEBUG_SEC("schedule SOA lookup for %s\n", name);

	if (! node->soa_req &&
	    ! _getdns_general_loop(context, loop, name, GETDNS_RRTYPE_SOA,
	    dnssec_ok_checking_disabled, node, &dnsreq, NULL,
	    val_chain_node_soa_cb))

		node->soa_req     = dnsreq->netreqs[0];
}

/* A SOA lookup is scheduled as a last resort.  No signatures were found and
 * no SOA in the authority section.  If a SOA query returns an actual SOA
 * answer, then a DS/DNSKEY lookup will follow the acquire the link of the
 * authentication chain.
 */
static void val_chain_sched_soa(chain_head *head, uint8_t *dname)
{
	chain_node *node;

	if (!head->netreq)
		return;

	if (!*dname)
		return;

	for ( node = head->parent
	    ; node && !_dname_equal(dname, node->ds.name)
	    ; node = node->parent);

	if (node)
		val_chain_sched_soa_node(node);
}

static void val_chain_node_cb(getdns_dns_req *dnsreq);
static void val_chain_sched_node(chain_node *node)
{
	getdns_context *context;
	getdns_eventloop *loop;
	getdns_dns_req *dnsreq;
	char  name[1024];

	context = node->chains->netreq->owner->context;
	loop    = node->chains->netreq->owner->loop;

	if (!gldns_wire2str_dname_buf(node->ds.name, 256, name, sizeof(name)))
		return;

	DEBUG_SEC("schedule DS & DNSKEY lookup for %s\n", name);

	if (! node->dnskey_req /* not scheduled */ &&
	    ! _getdns_general_loop(context, loop, name, GETDNS_RRTYPE_DNSKEY,
	    dnssec_ok_checking_disabled, node, &dnsreq, NULL, val_chain_node_cb))

		node->dnskey_req     = dnsreq->netreqs[0];

	if (! node->ds_req && node->parent /* not root */ &&
	    ! _getdns_general_loop(context, loop, name, GETDNS_RRTYPE_DS,
	    dnssec_ok_checking_disabled, node, &dnsreq, NULL, val_chain_node_cb))

		node->ds_req = dnsreq->netreqs[0];
}

static void val_chain_sched(chain_head *head, uint8_t *dname)
{
	chain_node *node;

	if (!head->netreq)
		return;

	for ( node = head->parent
	    ; node && !_dname_equal(dname, node->ds.name)
	    ; node = node->parent);
	if (node)
		val_chain_sched_node(node);
}

static void val_chain_sched_ds_node(chain_node *node)
{
	getdns_context *context;
	getdns_eventloop *loop;
	getdns_dns_req *ds_req;
	char  name[1024];

	context = node->chains->netreq->owner->context;
	loop    = node->chains->netreq->owner->loop;

	if (!gldns_wire2str_dname_buf(node->ds.name, 256, name, sizeof(name)))
		return;

	DEBUG_SEC("schedule DS lookup for %s\n", name);

	if (! node->ds_req && node->parent /* not root */ &&
	    ! _getdns_general_loop(context, loop, name, GETDNS_RRTYPE_DS,
	    dnssec_ok_checking_disabled, node, &ds_req, NULL, val_chain_node_cb))

		node->ds_req = ds_req->netreqs[0];
}

static void val_chain_sched_ds(chain_head *head, uint8_t *dname)
{
	chain_node *node;

	if (!head->netreq)
		return;

	for ( node = head->parent
	    ; node && !_dname_equal(dname, node->ds.name)
	    ; node = node->parent);
	if (node)
		val_chain_sched_ds_node(node);
}

static void val_chain_sched_signer_node(chain_node *node, rrsig_iter *rrsig)
{
	_getdns_rdf_iter rdf_spc, *rdf;
	uint8_t signer_spc[256], *signer;
	size_t signer_len;
	
	if (!(rdf = _getdns_rdf_iter_init_at(&rdf_spc, &rrsig->rr_i, 7)))
		return;

	if (!(signer = _getdns_rdf_if_or_as_decompressed(
	    rdf, signer_spc, &signer_len)))
		return;

	while (node && !_dname_equal(signer, node->ds.name))
		node = node->parent;
	if (node)
		val_chain_sched_node(node);
}

static void val_chain_sched_signer(chain_head *head, rrsig_iter *rrsig)
{
	if (!head->netreq)
		return;

	val_chain_sched_signer_node(head->parent, rrsig);
}

static void val_chain_node_cb(getdns_dns_req *dnsreq)
{
	chain_node *node = (chain_node *)dnsreq->user_pointer;
	getdns_network_req *netreq = dnsreq->netreqs[0];
	rrset_iter *i, i_spc;
	getdns_rrset *rrset;
	rrsig_iter  *rrsig, rrsig_spc;
	size_t n_signers;

	_getdns_context_clear_outbound_request(dnsreq);
	switch (netreq->request_type) {
	case GETDNS_RRTYPE_DS    : node->ds.pkt     = netreq->response;
	                           node->ds.pkt_len = netreq->response_len;
	                           break;
	case GETDNS_RRTYPE_DNSKEY: node->dnskey.pkt     = netreq->response;
	                           node->dnskey.pkt_len = netreq->response_len;
	default                  : check_chain_complete(node->chains);
				   return;
	}
	n_signers = 0;
	for ( i = rrset_iter_init(&i_spc,netreq->response,netreq->response_len)
	    ; i
	    ; i = rrset_iter_next(i)) {

		rrset = rrset_iter_value(i);

		if (rrset->rr_type != GETDNS_RRTYPE_DS     &&
		    rrset->rr_type != GETDNS_RRTYPE_NSEC   &&
		    rrset->rr_type != GETDNS_RRTYPE_NSEC3)
			continue;

		for ( rrsig = rrsig_iter_init(&rrsig_spc, rrset)
		    ; rrsig; rrsig = rrsig_iter_next(rrsig)) {

			val_chain_sched_signer_node(node, rrsig);
			n_signers++;
		}
	}
	if (netreq->request_type == GETDNS_RRTYPE_DS && n_signers == 0)
		/* No signed DS and no signed proof of non-existance.
		 * Search further up the tree...
		 */
		val_chain_sched_soa_node(node->parent);

	check_chain_complete(node->chains);
}


static void val_chain_node_soa_cb(getdns_dns_req *dnsreq)
{
	chain_node *node = (chain_node *)dnsreq->user_pointer;
	getdns_network_req *netreq = dnsreq->netreqs[0];
	rrset_iter i_spc;
	getdns_rrset *rrset;

	_getdns_context_clear_outbound_request(dnsreq);

	if ((rrset = rrset_by_type(&i_spc, netreq, GETDNS_RRTYPE_SOA))) {

		while (node &&
		    ! _dname_equal(node->ds.name, rrset->name))
			node = node->parent;

		if (node)
			val_chain_sched_ds_node(node);
		else {
			/* SOA for a different name */
			node = (chain_node *)dnsreq->user_pointer;
			val_chain_sched_soa_node(node->parent);
		}

	} else if (node->parent)
		val_chain_sched_soa_node(node->parent);

	check_chain_complete(node->chains);
}


/***************************  DNSSEC Validation  *****************************
 *****************************************************************************/


/* Returns whether a key in set dnskey is used to sign rrset.
 * Only keytag and signer name is compared.  The signature is not verified.
 */
static int key_matches_signer(getdns_rrset *dnskey, getdns_rrset *rrset)
{
	rrtype_iter rr_spc, *rr;
	rrsig_iter rrsig_spc, *rrsig;
	uint16_t keytag;
	_getdns_rdf_iter rdf_spc, *rdf;
	uint8_t signer_spc[256], *signer;
	size_t signer_len = sizeof(signer_spc);

	assert(dnskey->rr_type == GETDNS_RRTYPE_DNSKEY);


	for ( rr = rrtype_iter_init(&rr_spc, dnskey)
	    ; rr ; rr = rrtype_iter_next(rr) ) {


		/* Enough space to at least read algorithm field? */
		if (rr->rr_i.nxt < rr->rr_i.rr_type + 14)
			continue;

		/* Then we have at least 4 bytes to calculate keytag */
		keytag = gldns_calc_keytag_raw(rr->rr_i.rr_type + 10,
				rr->rr_i.nxt - rr->rr_i.rr_type - 10);

		for ( rrsig = rrsig_iter_init(&rrsig_spc, rrset)
		    ; rrsig ; rrsig = rrsig_iter_next(rrsig) ) {

			if (/* Space for keytag & signer in rrsig rdata? */
			       rrsig->rr_i.nxt >= rrsig->rr_i.rr_type + 28

			    /* Does Algorithm match */
			    && rrsig->rr_i.rr_type[12] == rr->rr_i.rr_type[13]

			    /* Does the keytag match? */
			    && gldns_read_uint16(rrsig->rr_i.rr_type + 26)
					    == keytag

			    /* Does the signer name match? */
			    && (rdf = _getdns_rdf_iter_init_at(
					    &rdf_spc, &rrsig->rr_i, 7))

			    && (signer = _getdns_rdf_if_or_as_decompressed(
					    rdf, signer_spc, &signer_len))

			    && _dname_equal(dnskey->name, signer))

				return keytag;
		}
	}
	return 0;
}

static size_t _rr_uncompressed_rdata_size(rrtype_iter *rr)
{
	_getdns_rdf_iter *rdf, rdf_spc;
	uint8_t decompressed[256];
	size_t sz = 0, decompressed_sz;

	for ( rdf = _getdns_rdf_iter_init(&rdf_spc, &rr->rr_i)
	    ; rdf
	    ; rdf = _getdns_rdf_iter_next(rdf)) {

		if ((rdf->rdd_pos->type & GETDNS_RDF_N_C) == GETDNS_RDF_N_C) {
			decompressed_sz = sizeof(decompressed);
			if (_getdns_rdf_if_or_as_decompressed(
			    rdf, decompressed, &decompressed_sz))
				sz += decompressed_sz;
		} else
			sz += rdf->nxt - rdf->pos;
	}
	return sz;
}

static size_t _rr_rdata_size(rrtype_iter *rr)
{
	const _getdns_rr_def *rr_def;
	size_t i;

	rr_def = _getdns_rr_def_lookup(gldns_read_uint16(rr->rr_i.rr_type));

	for (i = 0; i < rr_def->n_rdata_fields; i++)
		if ((rr_def->rdata[i].type & GETDNS_RDF_N_C) == GETDNS_RDF_N_C)
			return _rr_uncompressed_rdata_size(rr);

	/* assert(gldns_read_uint16(rr->rr_type+8) == rr->nxt-rr->rr_type-10);
	 */
	return rr->rr_i.nxt - rr->rr_i.rr_type - 10;
}

/* Iterate byte by byte over rdata canonicalizing dname's */
typedef struct canon_rdata_iter {
	_getdns_rdf_iter  rdf_spc;
	_getdns_rdf_iter *rdf;
	uint8_t           cdname[256]; /* Canonical dname */
	uint8_t          *pos;
	size_t            len;
} canon_rdata_iter;

inline static void canon_rdata_iter_field_init(canon_rdata_iter *i)
{
	for (;;) {
		if ((i->rdf->rdd_pos->type & GETDNS_RDF_N) == GETDNS_RDF_N) {
			i->len = sizeof(i->cdname);
			if ((i->pos = _getdns_rdf_if_or_as_decompressed(
			    i->rdf, i->cdname, &i->len)))
				_dname_canonicalize(i->pos);
		} else {
			i->pos = i->rdf->pos;
			i->len = i->rdf->nxt - i->rdf->pos;
		}
		if (i->len || !(i->rdf = _getdns_rdf_iter_next(i->rdf)))
			return;
	}
}

inline static void canon_rdata_iter_init(canon_rdata_iter*i,_getdns_rr_iter*rr)
{
	if ((i->rdf = _getdns_rdf_iter_init(&i->rdf_spc, rr)))
		canon_rdata_iter_field_init(i);
}

inline static int canon_rdata_iter_data(canon_rdata_iter *i)
{
	return i->rdf != NULL;
}

inline static uint8_t canon_rdata_iter_byte(canon_rdata_iter *i)
{
	return *i->pos;
}

inline static void canon_rdata_iter_next(canon_rdata_iter *i)
{
	if (--i->len == 0 && (i->rdf = _getdns_rdf_iter_next(i->rdf)))
		canon_rdata_iter_field_init(i);
	else
		i->pos++;
}

inline static int _dnssec_rdata_to_canonicalize(uint16_t rr_type)
{
	return rr_type == GLDNS_RR_TYPE_NS    || rr_type == GLDNS_RR_TYPE_MD
	    || rr_type == GLDNS_RR_TYPE_MF    || rr_type == GLDNS_RR_TYPE_CNAME
	    || rr_type == GLDNS_RR_TYPE_SOA   || rr_type == GLDNS_RR_TYPE_MB
	    || rr_type == GLDNS_RR_TYPE_MG    || rr_type == GLDNS_RR_TYPE_MR
	    || rr_type == GLDNS_RR_TYPE_PTR   || rr_type == GLDNS_RR_TYPE_MINFO
	    || rr_type == GLDNS_RR_TYPE_MX    || rr_type == GLDNS_RR_TYPE_RP
	    || rr_type == GLDNS_RR_TYPE_AFSDB || rr_type == GLDNS_RR_TYPE_RT
	    || rr_type == GLDNS_RR_TYPE_SIG   || rr_type == GLDNS_RR_TYPE_PX
	    || rr_type == GLDNS_RR_TYPE_NXT   || rr_type == GLDNS_RR_TYPE_NAPTR
	    || rr_type == GLDNS_RR_TYPE_KX    || rr_type == GLDNS_RR_TYPE_SRV
	    || rr_type == GLDNS_RR_TYPE_DNAME || rr_type == GLDNS_RR_TYPE_RRSIG;
}

static int _rr_iter_rdata_cmp(const void *a, const void *b)
{
	_getdns_rr_iter *x = (_getdns_rr_iter *)a;
	_getdns_rr_iter *y = (_getdns_rr_iter *)b;

	uint16_t rr_type = gldns_read_uint16(x->rr_type);
	size_t x_rdata_len, y_rdata_len;
	int r;

	canon_rdata_iter p, q;

	assert(rr_type == gldns_read_uint16(y->rr_type));

	if (!_dnssec_rdata_to_canonicalize(rr_type)) {
		/* Memory compare of rdata */
		x_rdata_len = x->nxt - x->rr_type - 10;
		y_rdata_len = y->nxt - y->rr_type - 10;
		if ((r = memcmp(x->rr_type + 10, y->rr_type + 10,
		    x_rdata_len < y_rdata_len ? x_rdata_len : y_rdata_len)))
			return r;
		return x_rdata_len < y_rdata_len ? -1 :
		       x_rdata_len > y_rdata_len ?  1 : 0;
	}
	for ( canon_rdata_iter_init(&p, x), canon_rdata_iter_init(&q, y)
	    ; canon_rdata_iter_data(&p)  && canon_rdata_iter_data(&q)
	    ; canon_rdata_iter_next(&p)   , canon_rdata_iter_next(&q) ) {
		
		if (canon_rdata_iter_byte(&p) != canon_rdata_iter_byte(&q))
			return canon_rdata_iter_byte(&p) >
			       canon_rdata_iter_byte(&q) ? 1 : -1;
	}
	return canon_rdata_iter_data(&p) ?  1
	     : canon_rdata_iter_data(&q) ? -1 : 0;
}

/* Verifies the signature rrsig for rrset rrset with key key.
 * When the rrset was a wildcard expansion (rrsig labels < labels owner name),
 * nc_name will be set to the next closer (within rrset->name).
 */
#define VAL_RRSET_SPC_SZ 1024
static int _getdns_verify_rrsig(struct mem_funcs *mf,
    getdns_rrset *rrset, rrsig_iter *rrsig, rrtype_iter *key, uint8_t **nc_name)
{
	int r;
	int to_skip;
	_getdns_rr_iter  val_rrset_spc[VAL_RRSET_SPC_SZ];
	_getdns_rr_iter *val_rrset = val_rrset_spc;
	rrtype_iter rr_spc, *rr;
	size_t n_rrs, i, valbuf_sz, owner_len;
	_getdns_rdf_iter *signer, signer_spc, *rdf, rdf_spc;
	uint8_t valbuf_spc[4096], *valbuf_buf = valbuf_spc;
	uint8_t cdname_spc[256], *cdname, owner[256];
	size_t cdname_len, pos;
	uint32_t orig_ttl;
	gldns_buffer valbuf;
	char *reason;

	/* nc_name should already have been initialized by the parent! */
	assert(nc_name);
	assert(!*nc_name);

	if (!(signer = _getdns_rdf_iter_init_at(&signer_spc, &rrsig->rr_i, 7)))
		return 0;
	valbuf_sz = signer->nxt - rrsig->rr_i.rr_type - 10;

	if ((owner_len = _dname_len(rrset->name)) > 255)
		return 0;

	for (;;) {
		for ( rr = rrtype_iter_init(&rr_spc, rrset), n_rrs = 0
		    ; rr
		    ; rr = rrtype_iter_next(rr), n_rrs++) {

			if (val_rrset == val_rrset_spc) {
				valbuf_sz += owner_len
				          +  2 /* type */
				          +  2 /* class */
				          +  4 /* Orig TTL */
					  +  2 /* Rdata len */
				          +  _rr_rdata_size(rr);
				if (n_rrs < VAL_RRSET_SPC_SZ)
					val_rrset[n_rrs] = rr->rr_i;
			} else
				val_rrset[n_rrs] = rr->rr_i;
		}
		/* Did everything fit? Then break */
		if (val_rrset != val_rrset_spc || n_rrs <= VAL_RRSET_SPC_SZ)
			break;

		/* More space needed for val_rrset */
		val_rrset = GETDNS_XMALLOC(*mf, _getdns_rr_iter, n_rrs);
	}
	DEBUG_SEC( "sizes: %zu rrs, %zu bytes for validation buffer\n"
	         , n_rrs, valbuf_sz);

	qsort(val_rrset, n_rrs, sizeof(_getdns_rr_iter), _rr_iter_rdata_cmp);

	if (valbuf_sz >= sizeof(valbuf_spc))
		valbuf_buf = GETDNS_XMALLOC(*mf, uint8_t, valbuf_sz);

	gldns_buffer_init_frm_data(&valbuf, valbuf_buf, valbuf_sz);
	gldns_buffer_write(&valbuf,
	    rrsig->rr_i.rr_type + 10, signer->nxt - rrsig->rr_i.rr_type - 10);
	_dname_canonicalize(gldns_buffer_at(&valbuf, 18));

	orig_ttl = gldns_read_uint32(rrsig->rr_i.rr_type + 14);

	(void) memcpy(owner, rrset->name, owner_len);
	_dname_canonicalize(owner);

	if (!_dnssec_rdata_to_canonicalize(rrset->rr_type))
		for (i = 0; i < n_rrs; i++) {
			gldns_buffer_write(&valbuf, owner, owner_len);
			gldns_buffer_write_u16(&valbuf, rrset->rr_type);
			gldns_buffer_write_u16(&valbuf, rrset->rr_class);
			gldns_buffer_write_u32(&valbuf, orig_ttl);
			gldns_buffer_write(&valbuf, val_rrset[i].rr_type + 8,
			    val_rrset[i].nxt - val_rrset[i].rr_type - 8);
		}
	else for (i = 0; i < n_rrs; i++) {
		gldns_buffer_write(&valbuf, owner, owner_len);
		gldns_buffer_write_u16(&valbuf, rrset->rr_type);
		gldns_buffer_write_u16(&valbuf, rrset->rr_class);
		gldns_buffer_write_u32(&valbuf, orig_ttl);
		pos = gldns_buffer_position(&valbuf);
		gldns_buffer_skip(&valbuf, 2);
		for ( rdf = _getdns_rdf_iter_init(&rdf_spc, &val_rrset[i])
		    ; rdf
		    ; rdf = _getdns_rdf_iter_next(rdf) ) {
			if (!(rdf->rdd_pos->type & GETDNS_RDF_N)) {
				gldns_buffer_write(
				    &valbuf, rdf->pos, rdf->nxt - rdf->pos);
				continue;
			}
			cdname_len = sizeof(cdname);
			if (!(cdname = _getdns_rdf_if_or_as_decompressed(
			    rdf, cdname_spc, &cdname_len)))
				continue;
			gldns_buffer_write(&valbuf, cdname, cdname_len);
			_dname_canonicalize(
			    gldns_buffer_current(&valbuf) - cdname_len);
		}
		gldns_buffer_write_u16_at(&valbuf, pos, 
		    (uint16_t)(gldns_buffer_position(&valbuf) - pos - 2));
	}
	DEBUG_SEC( "written to valbuf: %zu bytes\n"
	         , gldns_buffer_position(&valbuf));
	assert(gldns_buffer_position(&valbuf) == valbuf_sz);

	r = _getdns_verify_canonrrset(&valbuf, key->rr_i.rr_type[13],
	    signer->nxt, rrsig->rr_i.nxt - signer->nxt,
	    key->rr_i.rr_type+14, key->rr_i.nxt - key->rr_i.rr_type-14,
	    &reason);

#if defined(SEC_DEBUG) && SEC_DEBUG
	if (r == 0)
		DEBUG_SEC("verification failed: %s\n", reason);
#endif
	if (val_rrset != val_rrset_spc)
		GETDNS_FREE(*mf, val_rrset);
	if (valbuf_buf != valbuf_spc)
		GETDNS_FREE(*mf, valbuf_buf);
	if (!r)
		return 0;

	/* Verification has already been done, so the labels rdata field is
	 * definitely readable
	 */
	assert(rrsig->rr_i.rr_type + 14 <= rrsig->rr_i.nxt);

	/* If the number of labels in the owner name mathes the "labels" rdata
	 * field, then this was not a wildcard expansion, and everything is
	 * good.
	 */
	if ((size_t)rrsig->rr_i.rr_type[13] == _dname_label_count(rrset->name))
		return 1;

	/* This is a valid wildcard expansion.  Calculate and return the 
	 * "Next closer" name, because we need another NSEC to cover it.
	 * (except for rrsigs for NSECs, but those are dealt with later)
	 */
	to_skip = (int)_dname_label_count(rrset->name)
		- (int)rrsig->rr_i.rr_type[13] - 1;

	for ( *nc_name = rrset->name
	    ; to_skip > 0
	    ; *nc_name += **nc_name + 1, to_skip--);

	return 1;
}

/* Calculates NSEC3 hash for name, and stores that into label */
static uint8_t *_getdns_nsec3_hash_label(uint8_t *label, size_t label_len,
    uint8_t *name, uint8_t algorithm, uint16_t iterations, uint8_t *salt)
{
	uint8_t buf[512], *dst, *eob;
	const uint8_t *src;
	uint8_t md[SHA_DIGEST_LENGTH + 256];

	assert(SHA_DIGEST_LENGTH + 256 < sizeof(buf));

	if (algorithm != GLDNS_SHA1)
		return NULL;

	for ( src = name, dst = buf, eob = buf + sizeof(buf)
	    ; *src && dst + *src < eob
	    ;  src += *src + 1, dst += *dst + 1 )
		_dname_label_copy(dst, src, eob - dst);

	if (*src || dst + *salt >= eob)
		return NULL;
	*dst++ = 0;
	(void)memcpy(dst, salt + 1, *salt);
	dst += *salt;

	(void)SHA1(buf, dst - buf, md);
	if (iterations) {
		(void)memcpy(buf + SHA_DIGEST_LENGTH, salt + 1, *salt);
		while (iterations--) {
			(void)memcpy(buf, md, SHA_DIGEST_LENGTH);
			SHA1(buf, SHA_DIGEST_LENGTH + *salt, md);
		}
	}
	*label = gldns_b32_ntop_extended_hex(
	    md, SHA_DIGEST_LENGTH, (char *)label + 1, label_len - 1);

	return label;
}

static uint8_t *name2nsec3_label(
    getdns_rrset *nsec3, uint8_t *name, uint8_t *label, size_t label_len)
{
	rrsig_iter rrsig_spc, *rrsig;
	_getdns_rdf_iter rdf_spc, *rdf;
	uint8_t signer_spc[256], *signer;
	size_t signer_len = sizeof(signer_spc);
	rrtype_iter rr_spc, *rr;

	if (/* With the "first" signature */
	       (rrsig = rrsig_iter_init(&rrsig_spc, nsec3))

	    /* Access the signer name rdata field (7th) */
	    && (rdf = _getdns_rdf_iter_init_at(
			    &rdf_spc, &rrsig->rr_i, 7))

	    /* Verify & decompress */
	    && (signer = _getdns_rdf_if_or_as_decompressed(
			    rdf, signer_spc, &signer_len))

	    /* signer of the NSEC3 is direct parent for this NSEC3? */
	    && _dname_equal(
		    signer, nsec3->name + *nsec3->name + 1)

	    /* signer of the NSEC3 is parent of name? */
	    && _dname_is_parent(signer, name)

	    /* Initialize rr for getting NSEC3 rdata fields */
	    && (rr = rrtype_iter_init(&rr_spc, nsec3))
	    
	    /* Check for available space to get rdata fields */
	    && rr->rr_i.rr_type + 15 <= rr->rr_i.nxt
	    && rr->rr_i.rr_type + 14 + rr->rr_i.rr_type[14] <= rr->rr_i.nxt)

		/* Get the hashed label */
		return _getdns_nsec3_hash_label(label, label_len, name,
			    rr->rr_i.rr_type[10],
			    gldns_read_uint16(rr->rr_i.rr_type + 12),
			    rr->rr_i.rr_type + 14);
	return NULL;
}


static int nsec3_iteration_count_high(rrtype_iter *dnskey, getdns_rrset *nsec3)
{
	rrtype_iter rr_spc, *rr;
	size_t bits;

	/* No NSEC3, then iteration count is not too high */
	if (nsec3->rr_type != GETDNS_RRTYPE_NSEC3)
		return 0;

	/* Enough space to at least read algorithm field? 
	 * Without key data iteration count is definitely too high.
	 */
	if (dnskey->rr_i.nxt < dnskey->rr_i.rr_type + 14)
		return 1;

	if (/* Initialize rr for getting NSEC3 rdata fields */
	      !(rr = rrtype_iter_init(&rr_spc, nsec3))
	    
	    /* Check for available space to get rdata fields */
	    || rr->rr_i.rr_type + 14 > rr->rr_i.nxt)
		return 1;
	
	bits = gldns_rr_dnskey_key_size_raw(dnskey->rr_i.rr_type + 10,
	    dnskey->rr_i.nxt - dnskey->rr_i.rr_type - 10,
	    dnskey->rr_i.rr_type[13]);

	if (bits > 2048)
		return gldns_read_uint16(rr->rr_i.rr_type + 12) > 2500;
	else if (bits > 1024)
		return gldns_read_uint16(rr->rr_i.rr_type + 12) > 500;
	else
		return gldns_read_uint16(rr->rr_i.rr_type + 12) > 150;
}

static int check_dates(int32_t now, int32_t skew, int32_t exp, int32_t inc)
{
	return (exp - inc > 0) && (inc - now < skew) && (now - exp < skew);
}

/* Returns whether dnskey signed rrset.  If the rrset was a valid wildcard
 * expansion, nc_name will point to the next closer part of the name in rrset.
 */
static int dnskey_signed_rrset(struct mem_funcs *mf, time_t now, uint32_t skew,
    rrtype_iter *dnskey, getdns_rrset *rrset, uint8_t **nc_name)
{
	rrsig_iter rrsig_spc, *rrsig;
	_getdns_rdf_iter rdf_spc, *rdf;
	uint8_t signer_spc[256], *signer;
	size_t signer_len = sizeof(signer_spc);
	uint16_t keytag;

	assert(dnskey->rrset->rr_type == GETDNS_RRTYPE_DNSKEY);
	assert(nc_name);

	*nc_name = NULL;

	/* Enough space to at least read algorithm field? */
	if (dnskey->rr_i.nxt < dnskey->rr_i.rr_type + 14)
		return 0;

	/* Then we have at least 4 bytes to calculate keytag */
	keytag = gldns_calc_keytag_raw(dnskey->rr_i.rr_type + 10,
			dnskey->rr_i.nxt - dnskey->rr_i.rr_type - 10);

	for ( rrsig = rrsig_iter_init(&rrsig_spc, rrset)
	    ; rrsig ; rrsig = rrsig_iter_next(rrsig) ) {

		if (/* Space for keytag & signer in rrsig rdata? */
		        rrsig->rr_i.nxt >= rrsig->rr_i.rr_type + 28

		    /* Does Algorithm match */
		    && rrsig->rr_i.rr_type[12] == dnskey->rr_i.rr_type[13]

		    /* Does the keytag match? */
		    && gldns_read_uint16(rrsig->rr_i.rr_type + 26) == keytag

		    /* Signature still (or already) valid? */
		    && check_dates(now, skew,
			    gldns_read_uint32(rrsig->rr_i.rr_type + 18),
			    gldns_read_uint32(rrsig->rr_i.rr_type + 22))

		    /* Does the signer name match? */
		    && (rdf = _getdns_rdf_iter_init_at(
				    &rdf_spc, &rrsig->rr_i, 7))

		    && (signer = _getdns_rdf_if_or_as_decompressed(
				    rdf, signer_spc, &signer_len))

		    && _dname_equal(dnskey->rrset->name, signer)

		    /* Does the signature verify? */
		    && _getdns_verify_rrsig(mf, rrset,rrsig,dnskey,nc_name)) {

			debug_sec_print_rr("key ", &dnskey->rr_i);
			debug_sec_print_rrset("signed ", rrset);

			/* Signal insecurity by too high nsec3 iteration 
			 * count with NSEC3_ITERATION_COUNT_HIGH
			 * bit in return value.
			 */
			return ( nsec3_iteration_count_high(dnskey, rrset)
			       ? NSEC3_ITERATION_COUNT_HIGH
			       : SIGNATURE_VERIFIED
			       ) | keytag;
		}
	}
	return 0;
}

static int find_nsec_covering_name(
    struct mem_funcs *mf, time_t now, uint32_t skew,
    getdns_rrset *dnskey, getdns_rrset *rrset, uint8_t *name, int *opt_out);

/* Returns whether a dnskey for keyset signed rrset. */
static int a_key_signed_rrset(struct mem_funcs *mf, time_t now, uint32_t skew,
    getdns_rrset *keyset, getdns_rrset *rrset)
{
	rrtype_iter dnskey_spc, *dnskey;
	uint8_t *nc_name;
	int keytag;

	assert(keyset->rr_type == GETDNS_RRTYPE_DNSKEY);

	for ( dnskey = rrtype_iter_init(&dnskey_spc, keyset)
	    ; dnskey ; dnskey = rrtype_iter_next(dnskey) ) {

		if (!(keytag = dnskey_signed_rrset(mf, now, skew,
		    dnskey, rrset, &nc_name)))
			continue;

		if (!nc_name) /* Not a wildcard, then success! */
			return keytag;

		/* Wildcard RRSIG for a NSEC on the wildcard.
		 * There is no more specific!
		 */
		if (rrset->rr_type == GETDNS_RRTYPE_NSEC &&
		    rrset->name[0] == 1 && rrset->name[1] == '*')
			return keytag;

		debug_sec_print_rrset("wildcard expanded to: ", rrset);
		debug_sec_print_dname("Find NSEC covering the more sepecific: "
				, nc_name);

		if (find_nsec_covering_name(
		    mf, now, skew, keyset, rrset, nc_name, NULL))
			return keytag;
	}
	return 0;
}

/* Returns whether a DS in ds_set matches a dnskey in dnskey_set which in turn
 * signed the dnskey set.
 */
static int ds_authenticates_keys(struct mem_funcs *mf,
    time_t now, uint32_t skew, getdns_rrset *ds_set, getdns_rrset *dnskey_set)
{
	rrtype_iter dnskey_spc, *dnskey;
	rrtype_iter ds_spc, *ds;
	uint16_t keytag;
	uint8_t *nc_name;
	size_t valid_dsses = 0, supported_dsses = 0;
	uint8_t max_supported_digest = 0;
	int max_supported_result = 0;
	unsigned char digest_spc[256], *digest;
	unsigned char digest_buf_spc[2048], *digest_buf;
	size_t digest_len, digest_buf_len, dnskey_owner_len;

	assert(ds_set->rr_type == GETDNS_RRTYPE_DS);
	assert(dnskey_set->rr_type == GETDNS_RRTYPE_DNSKEY);
	
	/* The ds_set is already authenticated! */

	if (!_dname_equal(ds_set->name, dnskey_set->name))
		return 0;

	debug_sec_print_rrset("ds_authenticates_keys DS: ", ds_set);
	debug_sec_print_rrset("ds_authenticates_keys DNSKEY: ", dnskey_set);

	if ((dnskey_owner_len = _dname_len(dnskey_set->name)) >= 255)
		return 0;

	(void) memcpy(digest_buf_spc, dnskey_set->name, dnskey_owner_len);
	_dname_canonicalize(digest_buf_spc);

	for ( dnskey = rrtype_iter_init(&dnskey_spc, dnskey_set)
	    ; dnskey ; dnskey = rrtype_iter_next(dnskey)) {

		/* Enough space to at least read algorithm field? */
		if (dnskey->rr_i.nxt < dnskey->rr_i.rr_type + 14)
			continue;

		keytag = gldns_calc_keytag_raw(dnskey->rr_i.rr_type + 10,
				dnskey->rr_i.nxt - dnskey->rr_i.rr_type - 10);

		for ( ds = rrtype_iter_init(&ds_spc, ds_set)
		    ; ds ; ds = rrtype_iter_next(ds)) {

			if (/* Space for keytag, algorithm & digest type? */
			       ds->rr_i.nxt < ds->rr_i.rr_type + 14

			    /* Does algorithm match? */
			    || ds->rr_i.rr_type[12] != dnskey->rr_i.rr_type[13]

			    /* Does the keytag match? */
			    || gldns_read_uint16(ds->rr_i.rr_type+10)!=keytag)

				continue;

			valid_dsses++;

			if (/* Algorithm is not RSAMD5 (deprecated) */
			       ds->rr_i.rr_type[12] == GLDNS_RSAMD5

			    /* Algorithm is supported */
			    || !_getdns_dnskey_algo_id_is_supported(
				    ds->rr_i.rr_type[12])

			    /* Digest is supported */
			    || !(digest_len = _getdns_ds_digest_size_supported(
				    ds->rr_i.rr_type[13])))

				continue;

			digest = digest_len <= sizeof(digest_spc) ? digest_spc
			    : GETDNS_XMALLOC(*mf, unsigned char, digest_len);

			digest_buf_len = dnskey->rr_i.nxt
			               - dnskey->rr_i.rr_type - 10
			               + dnskey_owner_len;
			digest_buf = digest_buf_len <= sizeof(digest_buf_spc)
			    ? digest_buf_spc
			    : GETDNS_XMALLOC(*mf, unsigned char, digest_buf_len);

			if (digest_buf != digest_buf_spc)
				(void) memcpy(digest_buf,
				    digest_buf_spc, dnskey_owner_len);

			(void) memcpy(digest_buf + dnskey_owner_len,
			    dnskey->rr_i.rr_type + 10,
			    dnskey->rr_i.nxt - dnskey->rr_i.rr_type - 10);

			if (!_getdns_secalgo_ds_digest(ds->rr_i.rr_type[13],
			    digest_buf, digest_buf_len, digest)) {

				if (digest != digest_spc)
					GETDNS_FREE(*mf, digest);
				if (digest_buf != digest_buf_spc)
					GETDNS_FREE(*mf, digest_buf);
				continue;
			}
			supported_dsses++;

			/* The result of the best digest type counts!
			 * We'll assume higher is better for now.
			 * So, continue with next DS if...
			 */
			if (/* we already had a better digest earlier */
			       ds->rr_i.rr_type[13] < max_supported_digest

			    /* or we had the same digest and it already gave
			     * a match  (to a key in dnskey_set which
			     *           authenticated the dnskey_set).
			     */
			    || (   ds->rr_i.rr_type[13] == max_supported_digest
				&& max_supported_result)) {
				if (digest != digest_spc)
					GETDNS_FREE(*mf, digest);
				if (digest_buf != digest_buf_spc)
					GETDNS_FREE(*mf, digest_buf);

				DEBUG_SEC("Better DS available\n");
				continue;
			}
			max_supported_digest = ds->rr_i.rr_type[13];
			max_supported_result = 0;

			if (digest_len != ds->rr_i.nxt - ds->rr_i.rr_type-14
			    || memcmp(digest, ds->rr_i.rr_type+14, digest_len) != 0) {
				if (digest != digest_spc)
					GETDNS_FREE(*mf, digest);
				if (digest_buf != digest_buf_spc)
					GETDNS_FREE(*mf, digest_buf);

				DEBUG_SEC("HASH length mismatch %zu != %zu\n",
					digest_len, ds->rr_i.nxt - ds->rr_i.rr_type-14);
				continue;
			}
			/* Match! */
			if (digest != digest_spc)
				GETDNS_FREE(*mf, digest);
			if (digest_buf != digest_buf_spc)
				GETDNS_FREE(*mf, digest_buf);

			if (!dnskey_signed_rrset(mf, now, skew,
			    dnskey, dnskey_set, &nc_name)
			    || nc_name /* No DNSKEY's on wildcards! */) {

				debug_sec_print_rrset("keyset did not "
				    "authenticate: ", dnskey_set);
				continue;
			}
			debug_sec_print_rrset(
			    "keyset authenticated: ", dnskey_set);
			max_supported_result = SIGNATURE_VERIFIED | keytag;
		}
	}
	DEBUG_SEC("valid_dsses: %zu, supported_dsses: %zu\n",
			valid_dsses, supported_dsses);
	if (valid_dsses && !supported_dsses)
		return NO_SUPPORTED_ALGORITHMS;
	else
		return max_supported_result;
}

static int nsec_covers_name(
    getdns_rrset *nsec, uint8_t *name, uint8_t **ce_name)
{
	uint8_t owner_spc[256], *owner;
	size_t owner_len = sizeof(owner_spc);
	uint8_t next_spc[256], *next;
	size_t next_len = sizeof(next_spc);
	rrtype_iter rr_spc, *rr;
	_getdns_rdf_iter rdf_spc, *rdf;
	int nsec_cmp;
	uint8_t *common1, *common2;

	if (/* Get owner and next, nicely decompressed */
	       !(rr = rrtype_iter_init(&rr_spc, nsec))
	    || !(rdf = _getdns_rdf_iter_init(&rdf_spc, &rr->rr_i))
	    || !(owner = _getdns_owner_if_or_as_decompressed(
			    &rr->rr_i, owner_spc, &owner_len))
	    || !(next = _getdns_rdf_if_or_as_decompressed(
			    rdf, next_spc, &next_len)))
		return 0;

	debug_sec_print_dname("nsec owner: ", owner);
	debug_sec_print_dname("name      : ", name);
	debug_sec_print_dname("nsec next : ", next);

	if (ce_name) {
		common1 = dname_shared_parent(name, owner);
		common2 = dname_shared_parent(name, next);
		*ce_name = _dname_label_count(common1)
		         > _dname_label_count(common2) ? common1 : common2;
		debug_sec_print_dname("nsec closest encloser: ", *ce_name);
	}

	nsec_cmp = dname_compare(owner, next);
	if (nsec_cmp < 0) {
		/* Regular NSEC 
		 * >= so it can match the wildcard
		 * (for wildcard NODATA proofs).
		 */
		return dname_compare(name, owner) >= 0
		    && dname_compare(name, next)  <  0;

	} else if (nsec_cmp > 0) {
		/* The wrap around nsec.  So NSEC->nxt == zone.name.
		 * qname must be a subdomain of that.
		 */
		return dname_compare(name, owner) >= 0
		    && _dname_is_parent(next, name) && dname_compare(next, name);

	} else {
		/* This nsec is the only nsec.
		 * zone.name NSEC zone.name, disproves everything else,
		 * but only for subdomains of that zone.
		 * (also no zone.name == qname of course)
		 */
		return _dname_is_parent(owner, name) && dname_compare(owner, name);
	}
}

static int nsec3_matches_name(getdns_rrset *nsec3, uint8_t *name)
{
	uint8_t label[64], owner[64];

	if (name2nsec3_label(nsec3, name, label, sizeof(label))
	    && _dname_label_copy(owner, nsec3->name, sizeof(owner)))

		return *nsec3->name == label[0] /* Labels same size? */
		    && memcmp(owner + 1, label + 1, label[0]) == 0;

	return 0;
}

static int nsec3_covers_name(getdns_rrset *nsec3, uint8_t *name, int *opt_out)
{
	uint8_t label[65], next[65], owner[65];
	rrtype_iter rr_spc, *rr;
	_getdns_rdf_iter rdf_spc, *rdf;
	int nsz = 0, nsec_cmp;

	if (!name2nsec3_label(nsec3, name, label, sizeof(label)-1))
		return 0;

	label[label[0]+1] = 0;

	if (   !(rr = rrtype_iter_init(&rr_spc, nsec3))
	    || !(rdf = _getdns_rdf_iter_init_at(&rdf_spc, &rr->rr_i, 4))
	    || rdf->pos + *rdf->pos + 1 > rdf->nxt
	    || (nsz = gldns_b32_ntop_extended_hex(rdf->pos + 1, *rdf->pos,
		    (char *)next + 1, sizeof(next)-2)) < 0
	    || *nsec3->name > sizeof(owner) - 2
	    || !_dname_label_copy(owner, nsec3->name, sizeof(owner)-1)) {

		DEBUG_SEC("Error getting NSEC3 owner & next labels\n");
		return 0;
	}
	owner[owner[0]+1] = 0;
	next[(next[0] = (uint8_t)nsz)+1] = 0;

	if (opt_out)
		*opt_out = (rr->rr_i.rr_type[11] & 1) != 0;

	debug_sec_print_dname("NSEC3 for: ", name);
	debug_sec_print_dname("       is: ", label);
	debug_sec_print_dname("inbetween: ", owner);
	debug_sec_print_dname("      and: ", next);

	nsec_cmp = dname_compare(owner, next);
	if (nsec_cmp >= 0) {
		/* The wrap around and apex-only nsec case */
		return dname_compare(label, owner) > 0
		    || dname_compare(label, next) < 0;
	} else {
		assert(nsec_cmp < 0);
		/* The normal case
		 * >= so it can match the wildcard
		 * (for wildcard NODATA proofs).
		 */
		return dname_compare(label, owner) >= 0
		    && dname_compare(label, next)  <  0;
	}
}

static int find_nsec_covering_name(
    struct mem_funcs *mf, time_t now, uint32_t skew,
    getdns_rrset *dnskey, getdns_rrset *rrset, uint8_t *name, int *opt_out)
{
	rrset_iter i_spc, *i;
	getdns_rrset *n;
	rrtype_iter nsec_spc, *nsec_rr;
	_getdns_rdf_iter bitmap_spc, *bitmap;
	int keytag;

	if (opt_out)
		*opt_out = 0;

	for ( i = rrset_iter_init(&i_spc, rrset->pkt, rrset->pkt_len)
	    ; i ; i = rrset_iter_next(i)) {

		if ((n = rrset_iter_value(i))->rr_type == GETDNS_RRTYPE_NSEC3

		    /* Get the bitmap rdata field */
		    && (nsec_rr = rrtype_iter_init(&nsec_spc, n))
		    && (bitmap = _getdns_rdf_iter_init_at(
				    &bitmap_spc, &nsec_rr->rr_i, 5))

		    && (keytag = a_key_signed_rrset(mf, now, skew, dnskey, n))
		    && (   keytag & NSEC3_ITERATION_COUNT_HIGH

		        || (   nsec3_covers_name(n, name, opt_out)
			    /* NSEC should cover, but not match name...
			     * Unless it is wildcard match, but then we have to
			     * check that rrset->rr_type is not enlisted,
			     * because otherwise it should have matched the
			     * wildcard.
			     * 
			     * Also no CNAME... cause that should have matched too.
			     */

		            && (    !nsec3_matches_name(n, name)
		                || (   name[0] == 1 && name[1] == (uint8_t)'*'
		                    && !bitmap_has_type(bitmap, rrset->rr_type)
		                    && !bitmap_has_type(bitmap,
					    GETDNS_RRTYPE_CNAME)
		                   )
		               )
		           )
		       )
		    ) {

			debug_sec_print_rrset("NSEC3:   ", n);
			debug_sec_print_dname("covered: ", name);

			return keytag;
		}
		if ((n = rrset_iter_value(i))->rr_type == GETDNS_RRTYPE_NSEC
		    && nsec_covers_name(n, name, NULL)

		    /* Get the bitmap rdata field */
		    && (nsec_rr = rrtype_iter_init(&nsec_spc, n))
		    && (bitmap = _getdns_rdf_iter_init_at(
				    &bitmap_spc, &nsec_rr->rr_i, 1))

		    /* NSEC should cover, but not match name...
		     * Unless it is wildcard match, but then we have to check
		     * that rrset->rr_type is not enlisted, because otherwise
		     * it should have matched the wildcard.
		     * 
		     * Also no CNAME... cause that should have matched too.
		     */
		    && (    !_dname_equal(n->name, name)
		        || (   name[0] == 1 && name[1] == (uint8_t)'*'
		            && !bitmap_has_type(bitmap, rrset->rr_type)
		            && !bitmap_has_type(bitmap, GETDNS_RRTYPE_CNAME)
		           )
		       )

		    /* When qname is a subdomain of the NSEC owner, make
		     * sure there is no DNAME, and no delegation point
		     * there.
		     */
		    && (   !_dname_is_parent(n->name, name)
		        || (   !bitmap_has_type(bitmap, GETDNS_RRTYPE_DNAME)
		            && (   !bitmap_has_type(bitmap, GETDNS_RRTYPE_NS)
		                ||  bitmap_has_type(bitmap, GETDNS_RRTYPE_SOA)
		               )
		           )
		       )

		    && (keytag = a_key_signed_rrset(mf,now,skew, dnskey, n))) {

			debug_sec_print_rrset("NSEC:   ", n);
			debug_sec_print_dname("covered: ", name);

			return keytag;
		}
	}
	return 0;
}

static int nsec3_find_next_closer(
    struct mem_funcs *mf, time_t now, uint32_t skew,
    getdns_rrset *dnskey, getdns_rrset *rrset, uint8_t *nc_name, int *opt_out)
{
	uint8_t wc_name[256] = { 1, (uint8_t)'*' };
	int my_opt_out, keytag;

	if (opt_out)
		*opt_out = 0;

	if (!(keytag = find_nsec_covering_name(
	    mf, now, skew, dnskey, rrset, nc_name, &my_opt_out))) {
		/* TODO: At least google doesn't return next_closer on wildcard
		 * nodata for DS query.  And in fact returns even bogus for,
		 * for example bladiebla.xavier.nlnet.nl DS.
		 */
		return 0;
	}
	if (opt_out)
		*opt_out = my_opt_out;

	/* Wild card not needed on a "covering" NODATA response,
	 * because of opt-out?
	 *
	 * We check for opt-out bit, because rcode is unreliable...
	 * ... the checked packet might be artificially constructed
	 * (if we came here via getdns_validate_dnssec) in which case
	 * rcode is always NOERROR.
	 */
	if (my_opt_out || keytag & NSEC3_ITERATION_COUNT_HIGH)
		return keytag;

	nc_name += *nc_name + 1;
	if (_dname_len(nc_name) > sizeof(wc_name) - 2)
		return 0;
	else
		(void) memcpy(wc_name + 2, nc_name, _dname_len(nc_name));

	return find_nsec_covering_name(
	    mf, now, skew, dnskey, rrset, wc_name, opt_out);
}

/* 
 * Does a key from keyset dnskey prove the nonexistence of the (name, type)
 * tuple in rrset?
 *
 * On success returns the keytag + SIGNATURE_VERIFIED (0x10000) of the key
 * that signed the proof.
 * Or in case there were NSEC3's with too high iteration count for the
 * verifying key: it returns keytag + NSEC3_ITERATION_COUNT_HIGH (0x20000)
 */
static int key_proves_nonexistance(
    struct mem_funcs *mf, time_t now, uint32_t skew,
    getdns_rrset *keyset, getdns_rrset *rrset, int *opt_out)
{
	getdns_rrset nsec_rrset, *cover, *ce;
	rrtype_iter nsec_spc, *nsec_rr;
	_getdns_rdf_iter bitmap_spc, *bitmap;
	rrset_iter i_spc, *i;
	uint8_t *ce_name, *nc_name;
	uint8_t wc_name[256] = { 1, (uint8_t)'*' };
	int keytag;

	assert(keyset->rr_type == GETDNS_RRTYPE_DNSKEY);

	if (opt_out)
		*opt_out = 0;

	/* The NSEC NODATA case
	 * ====================
	 * NSEC has same ownername as the rrset to deny.
	 * Only the rr_type is missing from the bitmap.
	 */
	nsec_rrset = *rrset;
	nsec_rrset.rr_type = GETDNS_RRTYPE_NSEC;

	if (/* A NSEC RR exists at the owner name of rrset */
	      (nsec_rr = rrtype_iter_init(&nsec_spc, &nsec_rrset))

	    /* Get the bitmap rdata field */
	    && (bitmap = _getdns_rdf_iter_init_at(
			    &bitmap_spc, &nsec_rr->rr_i, 1))

	    /* At least the rr_type of rrset should be missing from it */
	    && !bitmap_has_type(bitmap, rrset->rr_type)

	    /* If the name is a CNAME, then we should have gotten the CNAME,
	     * So no CNAME bit either.
	     */
	    && !bitmap_has_type(bitmap, GETDNS_RRTYPE_CNAME)

	    /* In case of a DS query, make sure we have the parent side NSEC
	     * and not the child (so no SOA).
	     * Except for the root that is checked by itself.
	     */
	    && (    rrset->rr_type != GETDNS_RRTYPE_DS
	        || !bitmap_has_type(bitmap, GETDNS_RRTYPE_SOA)
		|| *rrset->name == 0
	       )

	    /* If not a DS query, then make sure the NSEC does not contain NS,
	     * or if it does, then also contains SOA, otherwise we have a parent
	     * side delegation point NSEC where we should have gotten a child 
	     * side NSEC!
	     */
	    && (    rrset->rr_type == GETDNS_RRTYPE_DS
		|| !bitmap_has_type(bitmap, GETDNS_RRTYPE_NS)
		||  bitmap_has_type(bitmap, GETDNS_RRTYPE_SOA))

	    /* And a valid signature please */
	    && (keytag = a_key_signed_rrset(mf,now,skew,keyset,&nsec_rrset))) {

		debug_sec_print_rrset("NSEC NODATA proof for: ", rrset);
		return keytag;
	}
	/* More NSEC NODATA cases
	 * ======================
	 * There are a few NSEC NODATA cases where qname doesn't match
	 * NSEC->name:
	 *
	 * - An empty non terminal (ENT) will result in a NSEC covering the
	 *   qname, where qname > NSEC->name and ce(qname) is parent of NXT.
	 *   This case is handled below after the covering NSEC is found.
	 *
	 * - Or a wildcard match without the type.  The wildcard owner name
	 *   match has special handing in the find_nsec_covering_name function.
	 *   We still expect a NSEC covering the name though.
	 */

	/* The NSEC Name error case
	 * ========================
	 * - First find the NSEC that covers the owner name.
	 */
	for ( i = rrset_iter_init(&i_spc, rrset->pkt, rrset->pkt_len)
	    ; i ; i = rrset_iter_next(i)) {

		cover = rrset_iter_value(i);

		if (/* Is cover an NSEC rrset? */
		       cover->rr_type != GETDNS_RRTYPE_NSEC

		    /* Does it cover the name */
		    || !nsec_covers_name(cover, rrset->name, &ce_name)

		    /* But not a match (because that would be NODATA case) */
		    || _dname_equal(cover->name, rrset->name)

		    /* Get the bitmap rdata field */
		    || !(nsec_rr = rrtype_iter_init(&nsec_spc, cover))
		    || !(bitmap = _getdns_rdf_iter_init_at(
				    &bitmap_spc, &nsec_rr->rr_i, 1))

		    /* When qname is a subdomain of the NSEC owner, make
		     * sure there is no DNAME, and no delegation point
		     * there.
		     */
		    || (   _dname_is_parent(cover->name, rrset->name)
		        && (   bitmap_has_type(bitmap, GETDNS_RRTYPE_DNAME)
		            || (    bitmap_has_type(bitmap, GETDNS_RRTYPE_NS)
		                && !bitmap_has_type(bitmap, GETDNS_RRTYPE_SOA)
		               )
		           )
		       )

		    /* And a valid signature please (as always) */
		    || !(keytag = a_key_signed_rrset(
					    mf, now, skew, keyset, cover)))
			continue;

		/* We could have found a NSEC covering an Empty Non Terminal.
		 * In that case no NSEC covering the wildcard is needed.
		 * Because it was actually a NODATA proof.
		 *
		 * Empty NON terminals can be identified, by
		 * qname > NSEC->name && NSEC->nxt is subdomain of qname.
		 *
		 * nsec_covers_name() will set ce_name to qname when NSEC->nxt
		 * is a subdomain of qname.
		 */
		if (   dname_compare(rrset->name, cover->name) > 0
		    && dname_compare(rrset->name, ce_name) == 0) {

			debug_sec_print_dname("Empty Non Terminal: ", ce_name);
			return keytag;
		}

		debug_sec_print_dname("Closest Encloser: ", ce_name);

		if (_dname_len(ce_name) > sizeof(wc_name) - 2)
			return 0;
		else
			(void) memcpy(wc_name+2, ce_name, _dname_len(ce_name));

		debug_sec_print_dname("        Wildcard: ", wc_name);

		return find_nsec_covering_name(
		    mf, now, skew, keyset, rrset, wc_name, NULL);
	}

	/* The NSEC3 NODATA case
	 * =====================
	 * NSEC3 has same (hashed) ownername as the rrset to deny.
	 */
	for ( i = rrset_iter_init(&i_spc, rrset->pkt, rrset->pkt_len)
	    ; i ; i = rrset_iter_next(i)) {

		/* ce is potentially the NSEC3 that matches complete qname
		 * (so is also the closest encloser)
		 */
		ce = rrset_iter_value(i);
		if (    ce->rr_type == GETDNS_RRTYPE_NSEC3

		    /* A NSEC3 RR exists at the owner name of rrset
		     * (this is always true)
		     */
		    && (nsec_rr = rrtype_iter_init(&nsec_spc, ce))

		    /* Get the bitmap rdata field */
		    && (bitmap = _getdns_rdf_iter_init_at(
				    &bitmap_spc, &nsec_rr->rr_i, 5))

		    /* At least the rr_type of rrset should be missing */
		    && !bitmap_has_type(bitmap, rrset->rr_type)

		    /* If the name is a CNAME, then we should have gotten it,
		     * So no CNAME bit either.
		     */
		    && !bitmap_has_type(bitmap, GETDNS_RRTYPE_CNAME)

		    /* In case of a DS query, make sure we have the parent side
		     * NSEC and not the child (so no SOA).
		     * (except for the root...)
		     */
		    && (    rrset->rr_type != GETDNS_RRTYPE_DS
			|| !bitmap_has_type(bitmap, GETDNS_RRTYPE_SOA)
		        || *rrset->name == 0
		       )

		    /* If not a DS query, then make sure the NSEC does not
		     * contain NS, or if it does, then also contains SOA, 
		     * otherwise we have a parent side delegation point NSEC
		     * where we should have gotten a child side NSEC!
		     */
		    && (    rrset->rr_type == GETDNS_RRTYPE_DS
			|| !bitmap_has_type(bitmap, GETDNS_RRTYPE_NS)
			||  bitmap_has_type(bitmap, GETDNS_RRTYPE_SOA))

		    /* It must have a valid signature */
		    && (keytag = a_key_signed_rrset(mf, now, skew, keyset, ce))

		    /* The qname must match the NSEC3 */
		    && (   keytag & NSEC3_ITERATION_COUNT_HIGH
		        || nsec3_matches_name(ce, rrset->name))) {

			debug_sec_print_rrset("NSEC3 No Data for: ", rrset);
			return keytag;
		}
	}
	/* More NSEC3 NODATA cases
	 * ======================
	 * There are a few NSEC NODATA cases where qname doesn't match
	 * NSEC->name:
	 *
	 * - NSEC3 ownername match for qtype == NSEC3 (TODO?)
	 * - Wildcard NODATA (wildcard owner name match has special handing 
	 *                    find_nsec_covering_name())
	 */

	/* The NSEC3 Name error case
	 * ========================+
	 * First find the closest encloser.
	 */
	for ( nc_name = rrset->name, ce_name = rrset->name + *rrset->name + 1
	    ; *ce_name ; nc_name = ce_name, ce_name += *ce_name + 1) {

		for ( i = rrset_iter_init(&i_spc, rrset->pkt, rrset->pkt_len)
		    ; i ; i = rrset_iter_next(i)) {

			if (   (ce = rrset_iter_value(i))->rr_type
					!= GETDNS_RRTYPE_NSEC3

			    /* Get the bitmap rdata field */
			    || !(nsec_rr = rrtype_iter_init(&nsec_spc, ce))
			    || !(bitmap = _getdns_rdf_iter_init_at(
					    &bitmap_spc, &nsec_rr->rr_i, 1))

			    /* No DNAME or delegation point at the closest
			     * encloser.
			     *
			     * TODO: Ask Wouter
			     * Unbound val_nsec3:1024 finishes insecurely
			     * here (instead of bogus) when DS is also missing.
			     * Should we not have followed the delegation then
			     * too?
			     * The NSEC could come from a parent zone!
			     * 
			     */
			    || bitmap_has_type(bitmap, GETDNS_RRTYPE_DNAME)
			    || (    bitmap_has_type(bitmap, GETDNS_RRTYPE_NS)
			        && !bitmap_has_type(bitmap, GETDNS_RRTYPE_SOA)
			       )

			    || !(keytag = a_key_signed_rrset(
						    mf, now, skew, keyset, ce))
			    || (   !(keytag & NSEC3_ITERATION_COUNT_HIGH)
			        && !nsec3_matches_name(ce, ce_name)))
				continue;

			debug_sec_print_rrset("Closest Encloser: ", ce);
			debug_sec_print_dname("Closest Encloser: ", ce_name);
			debug_sec_print_dname("     Next closer: ", nc_name);

			if (    keytag & NSEC3_ITERATION_COUNT_HIGH
			    || (keytag = nsec3_find_next_closer(mf, now, skew,
					    keyset, rrset, nc_name, opt_out)))

				return keytag;
		}
	}
	return 0;
}

/* Ascend up to the root along chain_nodes.  Try to find a keyset
 * authenticated by a key in ta rrset (trust anchor).  When we found one,
 * descend back down, authenticating more specific keysets along the chain.
 *
 * The most specific keyset is returned in keys.  Also a DNSSEC status is
 * returned.  BOGUS if no keyset could be found.  INSECURE if the 
 * non-existence of a DS along the path is proofed, and SECURE otherwise.
 */
static int chain_node_get_trusted_keys(
    struct mem_funcs *mf, time_t now, uint32_t skew,
    chain_node *node, getdns_rrset *ta, getdns_rrset **keys)
{
	int s, keytag;

	/* Ascend up to the root */
	if (! node)
		return GETDNS_DNSSEC_BOGUS;
	
	else if (ta->rr_type == GETDNS_RRTYPE_DS) {
		
		if ((keytag = ds_authenticates_keys(
		    mf, now, skew, ta, &node->dnskey))) {
			*keys = &node->dnskey;
			node->dnskey_signer = keytag;
			return keytag & NO_SUPPORTED_ALGORITHMS
			     ? GETDNS_DNSSEC_INSECURE
			     : GETDNS_DNSSEC_SECURE;
		}

	} else if (ta->rr_type == GETDNS_RRTYPE_DNSKEY) {

		/* ta is KSK */
		if ((keytag = a_key_signed_rrset(
		    mf, now, skew, ta, &node->dnskey))) {
			*keys = &node->dnskey;
			node->dnskey_signer = keytag;
			return GETDNS_DNSSEC_SECURE;
		}
		/* ta is parent's ZSK */
		if ((keytag = key_proves_nonexistance(
		    mf, now, skew, ta, &node->ds, NULL))) {
			node->ds_signer = keytag;
			return GETDNS_DNSSEC_INSECURE;
		}

		if ((keytag = a_key_signed_rrset(mf,now,skew,ta,&node->ds))) {
			node->ds_signer = keytag;
			if ((keytag = ds_authenticates_keys(
			    mf, now, skew, &node->ds, &node->dnskey))) {
				*keys = &node->dnskey;
				node->dnskey_signer = keytag;
				return keytag & NO_SUPPORTED_ALGORITHMS
				     ? GETDNS_DNSSEC_INSECURE
				     : GETDNS_DNSSEC_SECURE;
			}
			return GETDNS_DNSSEC_BOGUS;
		}
	} else
		return GETDNS_DNSSEC_BOGUS;

	if (GETDNS_DNSSEC_SECURE != (s = chain_node_get_trusted_keys(
	    mf, now, skew, node->parent, ta, keys)))
		return s;

	/* keys is an authenticated dnskey rrset always now (i.e. ZSK) */
	ta = *keys;
	/* Back down to the head */
	if ((keytag = key_proves_nonexistance(
	    mf, now, skew, ta, &node->ds, NULL))) {
		node->ds_signer = keytag;
		return GETDNS_DNSSEC_INSECURE;
	}
	if (key_matches_signer(ta, &node->ds)) {
		
		if ((node->ds_signer = a_key_signed_rrset(
						mf, now, skew, ta, &node->ds))
		   && (keytag = ds_authenticates_keys(
				mf, now, skew, &node->ds, &node->dnskey))){

			*keys = &node->dnskey;
			node->dnskey_signer = keytag;
			return keytag & NO_SUPPORTED_ALGORITHMS
			     ? GETDNS_DNSSEC_INSECURE
			     : GETDNS_DNSSEC_SECURE;
		}
		return GETDNS_DNSSEC_BOGUS;
	}
	/* If we are on a zone cut, we must return BOGUS, because there should
	 * have been a more specific DS set.  We can be sure of a zone cut if
	 * a request for the DSset was sent (because they are done only for
	 * signer names and when there was a SOA) or if we do have a DS,
	 * but not signed with a current trusted key.
	 *
	 * For the getdns_validate_dnssec case, we must make sure to insert
	 * an empty DS for this name in the validation chain... so it can
	 * be used for the support_records parameter.
	 */
	if (node->ds_req || rrset_has_rrs(&node->ds))
		return GETDNS_DNSSEC_BOGUS;

	/* Not at a zone cut, the trusted keyset must be authenticating
	 * something below (closer to head) this node.
	 */
	return GETDNS_DNSSEC_SECURE;
}

/* The DNSSEC status of the rrset of head is evaluated with trust anchor ta.
 * For this first a secure keyset is looked up, with which the keyset is 
 * evaluated.
 */
static int chain_head_validate_with_ta(struct mem_funcs *mf,
    time_t now, uint32_t skew, chain_head *head, getdns_rrset *ta)
{
	getdns_rrset *keys;
	int s, keytag, opt_out;

	debug_sec_print_rrset("validating ", &head->rrset);
	debug_sec_print_rrset("with trust anchor ", ta);

	if ((s = chain_node_get_trusted_keys(
	    mf, now, skew, head->parent, ta, &keys)) != GETDNS_DNSSEC_SECURE)
			return s;

	if (rrset_has_rrs(&head->rrset)) {
		if ((keytag = a_key_signed_rrset(
		    mf, now, skew, keys, &head->rrset))) {
			head->signer = keytag;
			return GETDNS_DNSSEC_SECURE;

		} else if (!rrset_has_rrsigs(&head->rrset)
				&& (keytag = key_proves_nonexistance(mf, now,
					skew, keys, &head->rrset, &opt_out))
				&& opt_out) {

			head->signer = keytag;
			return GETDNS_DNSSEC_INSECURE;
		}
	} else if ((keytag = key_proves_nonexistance(mf, now, skew,
					keys, &head->rrset, &opt_out))) {
		head->signer = keytag;
		return opt_out || (keytag & NSEC3_ITERATION_COUNT_HIGH)
		     ? GETDNS_DNSSEC_INSECURE : GETDNS_DNSSEC_SECURE;
	}
	return GETDNS_DNSSEC_BOGUS;
}

/* The DNSSEC status of the rrset in head is evaluated by trying the trust
 * anchors in tas in turn.  The best outcome counts.
 */
static int chain_head_validate(struct mem_funcs *mf, time_t now, uint32_t skew,
    chain_head *head, rrset_iter *tas)
{
	rrset_iter *i;
	getdns_rrset *ta, dnskey_ta, ds_ta;
	rrset_iter closest_ta;
	int closest_labels, s = GETDNS_DNSSEC_INDETERMINATE;
	size_t ta_labels, supported_algorithms;
	rrtype_iter rr_spc, *rr;

	/* Find the TA closest to the head's RRset name */
	closest_labels = -1;
	for (i = rrset_iter_rewind(tas); i ;i = rrset_iter_next(i)) {
		ta = rrset_iter_value(i);

		if ((ta->rr_type == GETDNS_RRTYPE_DNSKEY ||
		     ta->rr_type == GETDNS_RRTYPE_DS) 
		    && _dname_is_parent(ta->name, head->rrset.name)
		    && (int)(ta_labels = _dname_label_count(ta->name))
		                       > closest_labels ) {

			closest_labels = (int)ta_labels;
			closest_ta = *i;
			if (i->rrset.name == i->name_spc)
				closest_ta.rrset.name = closest_ta.name_spc;
		}
	}
	DEBUG_SEC("closest labels for TA: %d\n", closest_labels);
	if (closest_labels == -1)
		return GETDNS_DNSSEC_INDETERMINATE;

	ta = rrset_iter_value(&closest_ta);
	dnskey_ta = *ta;
	dnskey_ta.rr_type = GETDNS_RRTYPE_DNSKEY;
	ds_ta = *ta;
	ds_ta.rr_type = GETDNS_RRTYPE_DS;

	if (!rrset_has_rrs(&dnskey_ta)) 
		return chain_head_validate_with_ta(mf,now,skew,head,&ds_ta);

	/* Does the selected DNSKEY set have supported algorithms? */
	supported_algorithms = 0;
	for ( rr = rrtype_iter_init(&rr_spc, ta)
	    ; rr; rr = rrtype_iter_next(rr)) {

		if (   rr->rr_i.rr_type + 14 <= rr->rr_i.nxt
		    && _getdns_dnskey_algo_id_is_supported(
			    rr->rr_i.rr_type[13]))

			supported_algorithms++;
	}
	if (!supported_algorithms) {
		if (rrset_has_rrs(&ds_ta))
			return chain_head_validate_with_ta(
			    mf, now, skew, head, &ds_ta);

		return GETDNS_DNSSEC_INSECURE;
	}
	s = chain_head_validate_with_ta(mf, now, skew, head, &dnskey_ta);
	if (rrset_has_rrs(&ds_ta)) {
		switch (chain_head_validate_with_ta(mf,now,skew,head,&ds_ta)) {
		case GETDNS_DNSSEC_SECURE  : s = GETDNS_DNSSEC_SECURE;
		case GETDNS_DNSSEC_INSECURE: if (s != GETDNS_DNSSEC_SECURE)
						     s = GETDNS_DNSSEC_INSECURE;
					     break;
		case GETDNS_DNSSEC_BOGUS   : if (s != GETDNS_DNSSEC_SECURE &&
						 s != GETDNS_DNSSEC_INSECURE)
						     s = GETDNS_DNSSEC_BOGUS;
					     break;
		default                    : break;
		}
	}
	return s;
}

/* The DNSSEC status of the network requests which constructed the chain is
 * evaluated by processing each head in turn.  The worst outcome per network request
 * is the dnssec status for that network request.
 */
static void chain_set_netreq_dnssec_status(chain_head *chain, rrset_iter *tas)
{
	chain_head *head;

	/* The netreq status is the worst for any head */
	for (head = chain; head; head = head->next) {
		if (!head->netreq)
			continue;

		switch (chain_head_validate(priv_getdns_context_mf(
		    head->netreq->owner->context), time(NULL),
		    head->netreq->owner->context->dnssec_allowed_skew,
		    head, tas)) {

		case GETDNS_DNSSEC_SECURE:
			if (head->netreq->dnssec_status ==
			    GETDNS_DNSSEC_INDETERMINATE)
				head->netreq->dnssec_status =
				    GETDNS_DNSSEC_SECURE;
			break;

		case GETDNS_DNSSEC_INSECURE:
			if (head->netreq->dnssec_status != GETDNS_DNSSEC_BOGUS)
				head->netreq->dnssec_status =
					GETDNS_DNSSEC_INSECURE;
			break;

		case GETDNS_DNSSEC_BOGUS :
			head->netreq->dnssec_status = GETDNS_DNSSEC_BOGUS;
			break;

		default:
			break;
		}
	}
}

/* The DNSSEC status of all heads for a chain structure is evaluated by 
 * processing each head in turn.  The worst outcome is the dnssec status for
 * the whole.
 */
static int chain_validate_dnssec(struct mem_funcs *mf,
    time_t now, uint32_t skew, chain_head *chain, rrset_iter *tas)
{
	int s = GETDNS_DNSSEC_INDETERMINATE, t;
	chain_head *head;

	/* The netreq status is the worst for any head */
	for (head = chain; head; head = head->next) {
		t = chain_head_validate(mf, now, skew, head, tas);
		switch (t) {
		case GETDNS_DNSSEC_SECURE:
			if (s == GETDNS_DNSSEC_INDETERMINATE)
				s = GETDNS_DNSSEC_SECURE;
			break;

		case GETDNS_DNSSEC_INSECURE:
			if (s != GETDNS_DNSSEC_BOGUS)
				s = GETDNS_DNSSEC_INSECURE;
			break;

		case GETDNS_DNSSEC_BOGUS :
			s = GETDNS_DNSSEC_BOGUS;
			break;

		default:
			break;
		}
	}
	DEBUG_SEC("chain_validate_dnssec() returning %d\n", s);
	return s;
}


/****************  dnssec_return_validation_chain Extension ******************
 *****************************************************************************/

static size_t count_outstanding_requests(chain_head *head)
{
	size_t count;
	chain_node *node;

	if (!head)
		return 0;

	for ( node = head->parent, count = 0
	    ; node
	    ; node = node->parent) {

		if (node->dnskey_req &&
		    node->dnskey_req->state != NET_REQ_FINISHED &&
		    node->dnskey_req->state != NET_REQ_CANCELED)
			count++;

		if (node->ds_req &&
		    node->ds_req->state != NET_REQ_FINISHED &&
		    node->ds_req->state != NET_REQ_CANCELED)
			count++;

		if (node->soa_req &&
		    node->soa_req->state != NET_REQ_FINISHED &&
		    node->soa_req->state != NET_REQ_CANCELED)
			count++;
	}
	return count + count_outstanding_requests(head->next);
}

static void append_rrs2val_chain_list(getdns_context *ctxt,
    getdns_list *val_chain_list, getdns_network_req *netreq, int signer)
{
	rrset_iter *i, i_spc;
	getdns_rrset *rrset;
	rrtype_iter *rr, rr_spc;
	rrsig_iter  *rrsig, rrsig_spc;
	getdns_dict *rr_dict;

	for ( i = rrset_iter_init(&i_spc,netreq->response,netreq->response_len)
	    ; i
	    ; i = rrset_iter_next(i)) {

		rrset = rrset_iter_value(i);

		if (rrset->rr_type != GETDNS_RRTYPE_DNSKEY &&
		    rrset->rr_type != GETDNS_RRTYPE_DS     &&
		    rrset->rr_type != GETDNS_RRTYPE_NSEC   &&
		    rrset->rr_type != GETDNS_RRTYPE_NSEC3)
			continue;

		for ( rr = rrtype_iter_init(&rr_spc, rrset)
		    ; rr; rr = rrtype_iter_next(rr)) {

			if (!(rr_dict = _getdns_rr_iter2rr_dict(
			    &ctxt->mf, &rr->rr_i)))
				continue;

			(void)_getdns_list_append_dict(val_chain_list, rr_dict);
			getdns_dict_destroy(rr_dict);
		}
		for ( rrsig = rrsig_iter_init(&rrsig_spc, rrset)
		    ; rrsig; rrsig = rrsig_iter_next(rrsig)) {

			if (/* No space for keytag & signer in rrsig rdata? */
			       rrsig->rr_i.nxt < rrsig->rr_i.rr_type + 28

			    /* We have a signer and it doesn't match? */
			    || ((signer & 0xFFFF) &&
			        gldns_read_uint16(rrsig->rr_i.rr_type + 26)
					    != (signer & 0xFFFF))

			    /* Could not convert to rr_dict */
			    || !(rr_dict = _getdns_rr_iter2rr_dict(
						&ctxt->mf, &rrsig->rr_i)))
				continue;

			(void)_getdns_list_append_dict(val_chain_list, rr_dict);
			getdns_dict_destroy(rr_dict);
		}
	}
}

static void append_empty_ds2val_chain_list(
    getdns_context *context, getdns_list *val_chain_list, getdns_rrset *ds)
{
	getdns_dict *rr_dict;
	getdns_bindata bindata;
	getdns_dict *rdata_dict;

	if (!(rr_dict = getdns_dict_create_with_context(context)))
		return;

	bindata.size = _dname_len(ds->name);
	bindata.data = ds->name;
	(void) getdns_dict_set_bindata(rr_dict, "name", &bindata);
	(void) getdns_dict_set_int(rr_dict, "class", ds->rr_class);
	(void) getdns_dict_set_int(rr_dict, "type", ds->rr_type);
	(void) getdns_dict_set_int(rr_dict, "ttl", 0);

	if (!(rdata_dict = getdns_dict_create_with_context(context))) {
		getdns_dict_destroy(rr_dict);
		return;
	}
	bindata.size = 0;
	bindata.data = NULL;
	(void) getdns_dict_set_bindata(rdata_dict, "rdata_raw", &bindata);
	getdns_dict_destroy(rdata_dict);

	(void)_getdns_list_append_dict(val_chain_list, rr_dict);
	getdns_dict_destroy(rr_dict);
}

static void check_chain_complete(chain_head *chain)
{
	getdns_dns_req *dnsreq;
	getdns_context *context;
	size_t o, node_count;
	chain_head *head, *next;
	chain_node *node;
	getdns_list *val_chain_list;
	getdns_dict *response_dict;
	rrset_iter tas_iter;

	if ((o = count_outstanding_requests(chain)) > 0) {
		DEBUG_SEC("%zu outstanding requests\n", o);
		return;
	}
	DEBUG_SEC("Chain done!\n");
	dnsreq = chain->netreq->owner;
	context = dnsreq->context;

#ifdef STUB_NATIVE_DNSSEC
	/* Perform validation only on GETDNS_RESOLUTION_STUB (unbound_id == -1)
	 * Or when asked for the validation chain (to identify the RRSIGs that
	 * signed the RRSETs, so that only those will be included in the
	 * validation chain)
	 * In any case we must have a trust anchor.
	 */
	if ((   chain->netreq->unbound_id == -1
	     || dnsreq->dnssec_return_validation_chain)
	    && context->trust_anchors)

		chain_set_netreq_dnssec_status(chain,rrset_iter_init(&tas_iter,
		    context->trust_anchors, context->trust_anchors_len));
#else
	if (dnsreq->dnssec_return_validation_chain
	    && context->trust_anchors)

		(void) chain_validate_dnssec(priv_getdns_context_mf(context),
		    time(NULL), context->dnssec_allowed_skew,
		    chain, rrset_iter_init( &tas_iter
		                          , context->trust_anchors
		                          , context->trust_anchors_len));
#endif
	val_chain_list = dnsreq->dnssec_return_validation_chain
		? getdns_list_create_with_context(context) : NULL;

	/* Walk chain to add values to val_chain_list and to cleanup */
	for ( head = chain; head ; head = next ) {
		next = head->next;
		for ( node_count = head->node_count, node = head->parent
		    ; node_count
		    ; node_count--, node = node->parent ) {

			if (node->dnskey_req) {
				append_rrs2val_chain_list(
				    context, val_chain_list,
				    node->dnskey_req, node->dnskey_signer);
				_getdns_dns_req_free(node->dnskey_req->owner);
			}
			if (node->ds_req) {
				append_rrs2val_chain_list(
				    context, val_chain_list,
				    node->ds_req, node->ds_signer);

				if (!node->ds_signer &&
				    !rrset_has_rrs(&node->ds)) {
					/* Add empty DS, to prevent less
					 * specific to be able to authenticate
					 * below a zone cut (closer to head)
					 */
					append_empty_ds2val_chain_list(
					    context, val_chain_list,
					    &node->ds);
				}
				_getdns_dns_req_free(node->ds_req->owner);
			}
			if (node->soa_req) {
				_getdns_dns_req_free(node->soa_req->owner);
			}
		}
		GETDNS_FREE(head->my_mf, head);
	}

	response_dict = _getdns_create_getdns_response(dnsreq);
	if (val_chain_list) {
		(void) getdns_dict_set_list(
		    response_dict, "validation_chain", val_chain_list);
		getdns_list_destroy(val_chain_list);
	}

	/* Final user callback */
	_getdns_call_user_callback(dnsreq, response_dict);
}


void _getdns_get_validation_chain(getdns_dns_req *dnsreq)
{
	getdns_network_req *netreq, **netreq_p;
	chain_head *chain = NULL;

	for (netreq_p = dnsreq->netreqs; (netreq = *netreq_p) ; netreq_p++) {
		if (!  netreq->response
		    || netreq->response_len < GLDNS_HEADER_SIZE
		    || ( GLDNS_RCODE_WIRE(netreq->response)
			 != GETDNS_RCODE_NOERROR &&
			 GLDNS_RCODE_WIRE(netreq->response)
			 != GETDNS_RCODE_NXDOMAIN) ) {

			netreq->dnssec_status = GETDNS_DNSSEC_INSECURE;
			continue;
		}
		add_pkt2val_chain( &dnsreq->my_mf, &chain
		                 , netreq->response, netreq->response_len
				 , netreq
		                 );
		add_question2val_chain( &dnsreq->my_mf, &chain
		                      , netreq->response, netreq->response_len
		                      , netreq->owner->name
		                      , netreq->request_type
		                      , netreq->request_class
				      , netreq
		                      );
	}
	if (chain)
		check_chain_complete(chain);
	else
		_getdns_call_user_callback(dnsreq,
		    _getdns_create_getdns_response(dnsreq));
}


/*******************  getdns_validate_dnssec() Function  *********************
 *****************************************************************************/


static int wire_validate_dnssec(struct mem_funcs *mf,
    time_t now, uint32_t skew, uint8_t *to_val, size_t to_val_len,
    uint8_t *support, size_t support_len, uint8_t *tas, size_t tas_len)
{
	chain_head *chain, *head, *next_head;
	chain_node *node;

	uint8_t qname_spc[256], *qname = NULL;
	size_t qname_len = sizeof(qname_spc);
	uint16_t qtype = 0, qclass = GETDNS_RRCLASS_IN;

	_getdns_rr_iter rr_spc, *rr;
	rrset_iter tas_iter;

	int s;


	if (to_val_len < GLDNS_HEADER_SIZE)
		return GETDNS_RETURN_GENERIC_ERROR;

#if defined(SEC_DEBUG) && SEC_DEBUG
	char *str = gldns_wire2str_pkt(to_val, to_val_len);
	DEBUG_SEC("to validate: %s\n", str);
	free(str);
#endif

	if (GLDNS_RCODE_WIRE(to_val) != GETDNS_RCODE_NOERROR &&
	    GLDNS_RCODE_WIRE(to_val) != GETDNS_RCODE_NXDOMAIN)
		return GETDNS_DNSSEC_INSECURE;

	if (GLDNS_QDCOUNT(to_val) == 0 && GLDNS_ANCOUNT(to_val) == 0)
		return GETDNS_RETURN_GENERIC_ERROR;

	chain = NULL;
	/* First create a chain (head + nodes) for each rr in the answer and
	 * authority section of the fake to_val packet.
	 */
	add_pkt2val_chain(mf, &chain, to_val, to_val_len, NULL);

	/* For each question in the question section add a chain head.
	 */
	if (   (rr = _getdns_rr_iter_init(&rr_spc, to_val, to_val_len))
	    && _getdns_rr_iter_section(rr) == GLDNS_SECTION_QUESTION
	    && (qname = _getdns_owner_if_or_as_decompressed(
			    rr, qname_spc, &qname_len))
	    && rr->nxt >= rr->rr_type + 4) {

		qtype = gldns_read_uint16(rr->rr_type);
		qclass = gldns_read_uint16(rr->rr_type + 2);

		add_question2val_chain(mf, &chain, to_val, to_val_len,
		    qname, qtype, qclass, NULL);
	}

	/* Now equip the nodes with the support records wireformat */
	for (head = chain; head; head = head->next) {
		for (node = head->parent; node; node = node->parent) {

			node->dnskey.pkt = support;
			node->dnskey.pkt_len = support_len;
			node->ds.pkt = support;
			node->ds.pkt_len = support_len;
		}
	}
	s = chain_validate_dnssec(
	    mf, now, skew, chain, rrset_iter_init(&tas_iter, tas, tas_len));

	/* Cleanup the chain */
	for (head = chain; head; head = next_head) {
		next_head = head->next;
		GETDNS_FREE(*mf, head);
	}
	return s;
}

/*
 * getdns_validate_dnssec
 *
 */
getdns_return_t
getdns_validate_dnssec(getdns_list *records_to_validate,
    getdns_list *support_records,
    getdns_list *trust_anchors)
{
	uint8_t to_val_buf[4096], *to_val,
		support_buf[4096], *support,
		tas_buf[4096], *tas;

	size_t to_val_len = sizeof(to_val_buf),
	       support_len = sizeof(support_buf),
	       tas_len = sizeof(tas_buf);

	int r = GETDNS_RETURN_MEMORY_ERROR;
	struct mem_funcs *mf;

	size_t i;
	getdns_dict *reply;

	time_t now;
	uint32_t skew;

#if defined(SEC_DEBUG) && SEC_DEBUG
	fflush(stdout);
#endif

	if (!records_to_validate || !support_records || !trust_anchors)
		return GETDNS_RETURN_INVALID_PARAMETER;
	mf = &records_to_validate->mf;
	now = time(NULL);
	skew = 0;

	/* First convert everything to wire format
	 */
	if (!(support = _getdns_list2wire(support_records,
	    support_buf, &support_len, mf)))
		return GETDNS_RETURN_MEMORY_ERROR;

	if (!(tas = _getdns_list2wire(trust_anchors,
	    tas_buf, &tas_len, mf)))
		goto exit_free_support;

	if (!(to_val = _getdns_list2wire(records_to_validate,
	    to_val_buf, &to_val_len, mf)))
		goto exit_free_tas;

	if ((r = wire_validate_dnssec(mf, now, skew, to_val, to_val_len,
	    support,support_len, tas,tas_len)) != GETDNS_RETURN_GENERIC_ERROR)
		goto exit_free_to_val;

	for (i = 0; !getdns_list_get_dict(records_to_validate,i,&reply); i++) {

		DEBUG_SEC("REPLY %zu, r: %d\n", i, r);
		if (to_val != to_val_buf)
			GETDNS_FREE(*mf, to_val);
		to_val_len = sizeof(to_val_buf);

		if (!(to_val = _getdns_reply2wire(
		    reply, to_val_buf, &to_val_len, mf)))
			continue;

		r = GETDNS_DNSSEC_INDETERMINATE;
		switch (wire_validate_dnssec(mf, now, skew,
		    to_val, to_val_len, support, support_len, tas, tas_len)) {
		case GETDNS_DNSSEC_SECURE:
			if (r == GETDNS_DNSSEC_INDETERMINATE)
				r = GETDNS_DNSSEC_SECURE;
			break;
		case GETDNS_DNSSEC_INSECURE:
			if (r != GETDNS_DNSSEC_BOGUS)
				r = GETDNS_DNSSEC_INSECURE;
			break;
		case GETDNS_DNSSEC_BOGUS:
			r = GETDNS_DNSSEC_BOGUS;
			break;
		default:
			break;
		}
	}
	DEBUG_SEC("REPLY %zu, r: %d\n", i, r);

exit_free_to_val:
	if (to_val != to_val_buf)
		GETDNS_FREE(*mf, to_val);
exit_free_tas:
	if (tas != tas_buf)
		GETDNS_FREE(*mf, tas);
exit_free_support:
	if (support != support_buf)
		GETDNS_FREE(*mf, support);

	return r;
}


/******************  getdns_root_trust_anchor() Function  ********************
 *****************************************************************************/

uint16_t
_getdns_parse_ta_file(time_t *ta_mtime, gldns_buffer *gbuf)
{

	struct gldns_file_parse_state pst;
	struct stat st;
	uint8_t rr[8192]; /* Reasonable size for a single DNSKEY or DS RR */
	size_t len, dname_len;
	FILE *in;
	uint16_t ta_count = 0;
	size_t pkt_start;

	if (stat(TRUST_ANCHOR_FILE, &st) != 0)
		return 0;

	if (ta_mtime)
		*ta_mtime = st.st_mtime;

	if (!(in = fopen(TRUST_ANCHOR_FILE, "r")))
		return 0;

	memset(&pst, 0, sizeof(pst));
	pst.default_ttl = 3600;
	pst.lineno = 1;

	pkt_start = gldns_buffer_position(gbuf);
	/* Empty header */
	gldns_buffer_write_u32(gbuf, 0);
	gldns_buffer_write_u32(gbuf, 0);
	gldns_buffer_write_u32(gbuf, 0);

	while (!feof(in)) {
		len = sizeof(rr);
		dname_len = 0;
		if (gldns_fp2wire_rr_buf(in, rr, &len, &dname_len, &pst))
			break;
		if (len == 0)  /* empty, $TTL, $ORIGIN */
			continue;
		if (gldns_wirerr_get_type(rr, len, dname_len) 
		    != GLDNS_RR_TYPE_DS &&
		    gldns_wirerr_get_type(rr, len, dname_len)
		    != GLDNS_RR_TYPE_DNSKEY)
			continue;

		gldns_buffer_write(gbuf, rr, len);
		ta_count++;
	}
	fclose(in);
	gldns_buffer_write_u16_at(gbuf, pkt_start+GLDNS_ANCOUNT_OFF, ta_count);

	return ta_count;
}

getdns_list *
getdns_root_trust_anchor(time_t *utc_date_of_anchor)
{
	gldns_buffer *gbuf;
	getdns_list *ta_rrs;
	
	if (!(ta_rrs = getdns_list_create()))
		return NULL;

	if (!(gbuf = gldns_buffer_new(4096)))
		goto error_free_ta_rrs;

	if (!_getdns_parse_ta_file(utc_date_of_anchor, gbuf))
		goto error_free_gbuf;

	_getdns_wire2list( gldns_buffer_begin(gbuf)
	                 , gldns_buffer_position(gbuf), ta_rrs);

	gldns_buffer_free(gbuf);
	return ta_rrs;

error_free_gbuf:
	gldns_buffer_free(gbuf);
error_free_ta_rrs:
	getdns_list_destroy(ta_rrs);
	return NULL;
}

/* dnssec.c */
