/**
 *
 * \file rbtree.h
 * /brief Alternative symbol names for unbound's rbtree.h
 *
 */
/*
 * Copyright (c) 2017, NLnet Labs, the getdns team
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
#ifndef VAL_SECALGO_H_SYMBOLS
#define VAL_SECALGO_H_SYMBOLS
#define sldns_buffer			gldns_buffer
#define nsec3_hash_algo_size_supported	_getdns_nsec3_hash_algo_size_supported
#define secalgo_nsec3_hash		_getdns_secalgo_nsec3_hash
#define secalgo_hash_sha256		_getdns_secalgo_hash_sha256
#define ds_digest_size_supported	_getdns_ds_digest_size_supported
#define secalgo_ds_digest		_getdns_secalgo_ds_digest
#define dnskey_algo_id_is_supported	_getdns_dnskey_algo_id_is_supported
#define verify_canonrrset		_getdns_verify_canonrrset
#define sec_status			_getdns_sec_status
#define sec_status_secure		_getdns_sec_status_secure
#define sec_status_insecure		_getdns_sec_status_insecure
#define sec_status_unchecked		_getdns_sec_status_unchecked
#define sec_status_bogus		_getdns_sec_status_bogus

enum sec_status { sec_status_bogus     = 0
                , sec_status_unchecked = 0
                , sec_status_insecure  = 0
		, sec_status_secure    = 1 };
#define NSEC3_HASH_SHA1			0x01

#define	LDNS_SHA1			GLDNS_SHA1
#define	LDNS_SHA256			GLDNS_SHA256
#define LDNS_SHA384			GLDNS_SHA384
#define LDNS_HASH_GOST			GLDNS_HASH_GOST
#define LDNS_RSAMD5			GLDNS_RSAMD5
#define LDNS_DSA			GLDNS_DSA
#define LDNS_DSA_NSEC3			GLDNS_DSA_NSEC3
#define LDNS_RSASHA1			GLDNS_RSASHA1
#define LDNS_RSASHA1_NSEC3		GLDNS_RSASHA1_NSEC3
#define LDNS_RSASHA256			GLDNS_RSASHA256
#define LDNS_RSASHA512			GLDNS_RSASHA512
#define LDNS_ECDSAP256SHA256		GLDNS_ECDSAP256SHA256
#define LDNS_ECDSAP384SHA384		GLDNS_ECDSAP384SHA384
#define LDNS_ECC_GOST			GLDNS_ECC_GOST
#define sldns_key_EVP_load_gost_id	gldns_key_EVP_load_gost_id
#define sldns_digest_evp		gldns_digest_evp
#define sldns_key_buf2dsa_raw		gldns_key_buf2dsa_raw
#define sldns_key_buf2rsa_raw		gldns_key_buf2rsa_raw
#define sldns_gost2pkey_raw		gldns_gost2pkey_raw
#define sldns_ecdsa2pkey_raw		gldns_ecdsa2pkey_raw
#define sldns_buffer_begin		gldns_buffer_begin
#define sldns_buffer_limit		gldns_buffer_limit
#include "util/orig-headers/val_secalgo.h"
#endif
