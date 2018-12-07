/**
 *
 * \file tls.c
 * @brief getdns TLS functions
 */

/*
 * Copyright (c) 2018, NLnet Labs
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

#include <gnutls/x509.h>

#include "config.h"

#include "debug.h"
#include "context.h"

#include "tls.h"

static getdns_return_t error_may_want_read_write(_getdns_tls_connection* conn, int err)
{
	switch (err) {
	case GNUTLS_E_INTERRUPTED:
	case GNUTLS_E_AGAIN:
	case GNUTLS_E_WARNING_ALERT_RECEIVED:
	case GNUTLS_E_GOT_APPLICATION_DATA:
		if (gnutls_record_get_direction(conn->tls) == 0)
			return GETDNS_RETURN_TLS_WANT_READ;
		else
			return GETDNS_RETURN_TLS_WANT_WRITE;

	default:
		return GETDNS_RETURN_GENERIC_ERROR;
	}
}

static getdns_return_t get_gnu_mac_algorithm(int algorithm, gnutls_mac_algorithm_t* gnualg)
{
	switch (algorithm) {
	case GETDNS_HMAC_MD5   : *gnualg = GNUTLS_MAC_MD5   ; break;
	case GETDNS_HMAC_SHA1  : *gnualg = GNUTLS_MAC_SHA1  ; break;
	case GETDNS_HMAC_SHA224: *gnualg = GNUTLS_MAC_SHA224; break;
	case GETDNS_HMAC_SHA256: *gnualg = GNUTLS_MAC_SHA256; break;
	case GETDNS_HMAC_SHA384: *gnualg = GNUTLS_MAC_SHA384; break;
	case GETDNS_HMAC_SHA512: *gnualg = GNUTLS_MAC_SHA512; break;
	default                : return GETDNS_RETURN_GENERIC_ERROR;
	}

	return GETDNS_RETURN_GOOD;
}

static _getdns_tls_x509* _getdns_tls_x509_new(struct mem_funcs* mfs, gnutls_datum_t cert)
{
	_getdns_tls_x509* res;

	res = GETDNS_MALLOC(*mfs, _getdns_tls_x509);
	if (res)
		res->tls = cert;

	return res;
}

void _getdns_tls_init()
{
	gnutls_global_init();
}

_getdns_tls_context* _getdns_tls_context_new(struct mem_funcs* mfs)
{
	_getdns_tls_context* res;

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_context)))
		return NULL;

	return res;
}

getdns_return_t _getdns_tls_context_free(struct mem_funcs* mfs, _getdns_tls_context* ctx)
{
	if (!ctx)
		return GETDNS_RETURN_INVALID_PARAMETER;
	GETDNS_FREE(*mfs, ctx);
	return GETDNS_RETURN_GOOD;
}

void _getdns_tls_context_dane_init(_getdns_tls_context* ctx)
{
	(void) ctx;
}

getdns_return_t _getdns_tls_context_set_min_proto_1_2(_getdns_tls_context* ctx)
{
	(void) ctx;
	return GETDNS_RETURN_NOT_IMPLEMENTED;
}

getdns_return_t _getdns_tls_context_set_cipher_list(_getdns_tls_context* ctx, const char* list)
{
	(void) list;

	if (!ctx)
		return GETDNS_RETURN_INVALID_PARAMETER;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_context_set_curves_list(_getdns_tls_context* ctx, const char* list)
{
	(void) list;

	if (!ctx)
		return GETDNS_RETURN_INVALID_PARAMETER;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_context_set_ca(_getdns_tls_context* ctx, const char* file, const char* path)
{
	(void) file;
	(void) path;

	if (!ctx)
		return GETDNS_RETURN_INVALID_PARAMETER;
	return GETDNS_RETURN_GOOD;
}

_getdns_tls_connection* _getdns_tls_connection_new(struct mem_funcs* mfs, _getdns_tls_context* ctx, int fd)
{
	_getdns_tls_connection* res;
	int r;

	if (!ctx)
		return NULL;

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_connection)))
		return NULL;

	res->shutdown = 0;

	r = gnutls_certificate_allocate_credentials(&res->cred);
	if (r == GNUTLS_E_SUCCESS)
		gnutls_certificate_set_x509_system_trust(res->cred);
	if (r == GNUTLS_E_SUCCESS)
		r = gnutls_init(&res->tls, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
	if (r == GNUTLS_E_SUCCESS)
		r = gnutls_set_default_priority(res->tls);
	if (r == GNUTLS_E_SUCCESS)
		r = gnutls_credentials_set(res->tls, GNUTLS_CRD_CERTIFICATE, res->cred);
	if (r != GNUTLS_E_SUCCESS) {
		_getdns_tls_connection_free(mfs, res);
		return NULL;
	}

	gnutls_transport_set_int(res->tls, fd);
	return res;
}

getdns_return_t _getdns_tls_connection_free(struct mem_funcs* mfs, _getdns_tls_connection* conn)
{
	if (!conn || !conn->tls)
		return GETDNS_RETURN_INVALID_PARAMETER;

	gnutls_deinit(conn->tls);
	gnutls_certificate_free_credentials(conn->cred);
	GETDNS_FREE(*mfs, conn);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_shutdown(_getdns_tls_connection* conn)
{
	if (!conn || !conn->tls)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (conn->shutdown == 0) {
		gnutls_bye(conn->tls, GNUTLS_SHUT_WR);
		conn->shutdown++;
	} else {
		gnutls_bye(conn->tls, GNUTLS_SHUT_RDWR);
		conn->shutdown++;
	}

	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_set_cipher_list(_getdns_tls_connection* conn, const char* list)
{
	(void) list;

	if (!conn || !conn->tls)
		return GETDNS_RETURN_INVALID_PARAMETER;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_set_curves_list(_getdns_tls_connection* conn, const char* list)
{
	(void) list;

	if (!conn || !conn->tls)
		return GETDNS_RETURN_INVALID_PARAMETER;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_set_session(_getdns_tls_connection* conn, _getdns_tls_session* s)
{
	int r;

	if (!conn || !conn->tls || !s)
		return GETDNS_RETURN_INVALID_PARAMETER;

	r = gnutls_session_set_data(conn->tls, s->tls.data, s->tls.size);
	if (r != GNUTLS_E_SUCCESS)
		return GETDNS_RETURN_GENERIC_ERROR;
	return GETDNS_RETURN_GOOD;
}

_getdns_tls_session* _getdns_tls_connection_get_session(struct mem_funcs* mfs, _getdns_tls_connection* conn)
{
	_getdns_tls_session* res;
	int r;

	if (!conn || !conn->tls)
		return NULL;

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_session)))
		return NULL;

	r = gnutls_session_get_data2(conn->tls, &res->tls);
	if (r != GNUTLS_E_SUCCESS) {
		GETDNS_FREE(*mfs, res);
		return NULL;
	}

	return res;
}

const char* _getdns_tls_connection_get_version(_getdns_tls_connection* conn)
{
	if (!conn || !conn->tls)
		return NULL;

	return gnutls_protocol_get_name(gnutls_protocol_get_version(conn->tls));
}

getdns_return_t _getdns_tls_connection_do_handshake(_getdns_tls_connection* conn)
{
	int r;

	if (!conn || !conn->tls)
		return GETDNS_RETURN_INVALID_PARAMETER;

	r = gnutls_handshake(conn->tls);
	if (r == GNUTLS_E_SUCCESS)
		return GETDNS_RETURN_GOOD;
	else
		return error_may_want_read_write(conn, r);
}

_getdns_tls_x509* _getdns_tls_connection_get_peer_certificate(struct mem_funcs* mfs, _getdns_tls_connection* conn)
{
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size;

	if (!conn || !conn->tls)
		return NULL;

	cert_list = gnutls_certificate_get_peers(conn->tls, &cert_list_size);
	if (cert_list == NULL)
		return NULL;

	return _getdns_tls_x509_new(mfs, *cert_list);
}

getdns_return_t _getdns_tls_connection_is_session_reused(_getdns_tls_connection* conn)
{
	if (!conn || !conn->tls)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (gnutls_session_is_resumed(conn->tls) != 0)
		return GETDNS_RETURN_GOOD;
	else
		return GETDNS_RETURN_TLS_CONNECTION_FRESH;
}

getdns_return_t _getdns_tls_connection_setup_hostname_auth(_getdns_tls_connection* conn, const char* auth_name)
{
	int r;

	if (!conn || !conn->tls || !auth_name)
		return GETDNS_RETURN_INVALID_PARAMETER;

	r = gnutls_server_name_set(conn->tls, GNUTLS_NAME_DNS, auth_name, strlen(auth_name));
	if (r != GNUTLS_E_SUCCESS)
		return GETDNS_RETURN_GENERIC_ERROR;

	gnutls_session_set_verify_cert(conn->tls, auth_name, 0);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_set_host_pinset(_getdns_tls_connection* conn, const char* auth_name, const sha256_pin_t* pinset)
{
	(void) pinset;

	if (!conn || !conn->tls || !auth_name)
		return GETDNS_RETURN_INVALID_PARAMETER;

	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_certificate_verify(_getdns_tls_connection* conn, long* errnum, const char** errmsg)
{
	(void) errnum;
	(void) errmsg;

	if (!conn || !conn->tls)
		return GETDNS_RETURN_INVALID_PARAMETER;

	return GETDNS_RETURN_GOOD;
}


getdns_return_t _getdns_tls_connection_read(_getdns_tls_connection* conn, uint8_t* buf, size_t to_read, size_t* read)
{
	ssize_t sread;

	if (!conn || !conn->tls || !read)
		return GETDNS_RETURN_INVALID_PARAMETER;

	sread = gnutls_record_recv(conn->tls, buf, to_read);
	if (sread < 0)
		return error_may_want_read_write(conn, sread);

	*read = sread;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_connection_write(_getdns_tls_connection* conn, uint8_t* buf, size_t to_write, size_t* written)
{
	int swritten;

	if (!conn || !conn->tls || !written)
		return GETDNS_RETURN_INVALID_PARAMETER;

	swritten = gnutls_record_send(conn->tls, buf, to_write);
	if (swritten < 0)
		return error_may_want_read_write(conn, swritten);

	*written = swritten;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_session_free(struct mem_funcs* mfs, _getdns_tls_session* s)
{
	if (!s)
		return GETDNS_RETURN_INVALID_PARAMETER;
	GETDNS_FREE(*mfs, s);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t _getdns_tls_get_api_information(getdns_dict* dict)
{
	if (! getdns_dict_set_int(
	    dict, "gnutls_version_number", GNUTLS_VERSION_NUMBER)

	    && ! getdns_dict_util_set_string(
	    dict, "gnutls_version_string", GNUTLS_VERSION)
		)
		return GETDNS_RETURN_GOOD;
	return GETDNS_RETURN_GENERIC_ERROR;
}

void _getdns_tls_x509_free(struct mem_funcs* mfs, _getdns_tls_x509* cert)
{
	if (cert)
		GETDNS_FREE(*mfs, cert);
}

int _getdns_tls_x509_to_der(struct mem_funcs* mfs, _getdns_tls_x509* cert, getdns_bindata* bindata)
{
	gnutls_x509_crt_t crt;
	size_t s;

	if (!cert || gnutls_x509_crt_init(&crt) != GNUTLS_E_SUCCESS)
		return 0;

	gnutls_x509_crt_import(crt, &cert->tls, GNUTLS_X509_FMT_DER);
	gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_DER, NULL, &s);

	if (!bindata) {
		gnutls_x509_crt_deinit(crt);
		return s;
	}

	bindata->data = GETDNS_XMALLOC(*mfs, uint8_t, s);
	if (!bindata->data) {
		gnutls_x509_crt_deinit(crt);
		return 0;
	}

	gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_DER, bindata->data, &s);
	bindata->size = s;
	gnutls_x509_crt_deinit(crt);
	return s;
}

unsigned char* _getdns_tls_hmac_hash(struct mem_funcs* mfs, int algorithm, const void* key, size_t key_size, const void* data, size_t data_size, size_t* output_size)
{
	gnutls_mac_algorithm_t alg;
	unsigned int md_len;
	unsigned char* res;

	if (get_gnu_mac_algorithm(algorithm, &alg) != GETDNS_RETURN_GOOD)
		return NULL;

	md_len = gnutls_hmac_get_len(alg);
	res = (unsigned char*) GETDNS_XMALLOC(*mfs, unsigned char, md_len);
	if (!res)
		return NULL;

	(void) gnutls_hmac_fast(alg, key, key_size, data, data_size, res);

	if (output_size)
		*output_size = md_len;
	return res;
}

_getdns_tls_hmac* _getdns_tls_hmac_new(struct mem_funcs* mfs, int algorithm, const void* key, size_t key_size)
{
	gnutls_mac_algorithm_t alg;
	_getdns_tls_hmac* res;

	if (get_gnu_mac_algorithm(algorithm, &alg) != GETDNS_RETURN_GOOD)
		return NULL;

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_hmac)))
		return NULL;

	if (gnutls_hmac_init(&res->tls, alg, key, key_size) < 0) {
		GETDNS_FREE(*mfs, res);
		return NULL;
	}
	res->md_len = gnutls_hmac_get_len(alg);
	return res;
}

getdns_return_t _getdns_tls_hmac_add(_getdns_tls_hmac* h, const void* data, size_t data_size)
{
	if (!h || !h->tls || !data)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (gnutls_hmac(h->tls, data, data_size) < 0)
		return GETDNS_RETURN_GENERIC_ERROR;
	else
		return GETDNS_RETURN_GOOD;
}

unsigned char* _getdns_tls_hmac_end(struct mem_funcs* mfs, _getdns_tls_hmac* h, size_t* output_size)
{
	unsigned char* res;

	if (!h || !h->tls)
		return NULL;

	res = (unsigned char*) GETDNS_XMALLOC(*mfs, unsigned char, h->md_len);
	if (!res)
		return NULL;

	gnutls_hmac_deinit(h->tls, res);
	if (output_size)
		*output_size = h->md_len;

	GETDNS_FREE(*mfs, h);
	return res;
}

void _getdns_tls_sha1(const void* data, size_t data_size, unsigned char* buf)
{
	gnutls_hash_fast(GNUTLS_DIG_SHA1, data, data_size, buf);
}

void _getdns_tls_cookie_sha256(uint32_t secret, void* addr, size_t addrlen, unsigned char* buf, size_t* buflen)
{
	gnutls_hash_hd_t digest;

	gnutls_hash_init(&digest, GNUTLS_DIG_SHA256);
	gnutls_hash(digest, &secret, sizeof(secret));
	gnutls_hash(digest, addr, addrlen);
	gnutls_hash_deinit(digest, buf);
	*buflen = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
}

/* tls.c */
