/**
 *
 * \file tls.c
 * @brief getdns TLS functions
 */

/*
 * Copyright (c) 2018-2020, NLnet Labs
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/psa_util.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include "config.h"

#include "debug.h"
#include "context.h"

#include "tls.h"

/* No ABI guarantee across mbedTLS major (or, outside LTS, minor)
 * versions, and no runtime way to check it. mbedTLS structs are not
 * opaque-constructed, so we need to embed them.
 * Linking against a mismatched libmbedtls version can cause memory
 * corruption or link failures. Handle with care. */

/* Max ciphersuite IDs collected by apply_connection_ciphersuites(). */
#define GETDNS_MBEDTLS_MAX_CIPHERSUITES 128

/* RFC7525 AEAD suites, in mbedTLS's own ciphersuite names: cipher_list
 * is the TLS1.2 ECDHE+AEAD set, cipher_suites the TLS1.3 set.
 * Used as-is if set_cipher_list()/set_cipher_suites() is called with NULL. */
static char const *const _getdns_tls_context_default_cipher_list =
    "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:"
    "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:"
    "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:"
    "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256:"
    "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:"
    "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256";

static char const *const _getdns_tls_context_default_cipher_suites =
    "TLS1-3-AES-256-GCM-SHA384:"
    "TLS1-3-AES-128-GCM-SHA256:" "TLS1-3-CHACHA20-POLY1305-SHA256";

/* mbedTLS has no "use the system trust store" call; fall back to probing
 * well-known bundle locations when no explicit ca_trust_file/path is set. */
static char const *const _getdns_tls_default_ca_bundle_paths[] = {
	"/etc/ssl/certs/ca-certificates.crt",	/* Debian/Ubuntu/OpenWrt/Gentoo */
	"/etc/pki/tls/certs/ca-bundle.crt",	/* Fedora/RHEL */
	"/etc/ssl/cert.pem",	/* Alpine, OpenBSD, macOS Homebrew */
	"/etc/ssl/ca-bundle.pem",	/* openSUSE */
	NULL
};

static char *
getdns_strdup(struct mem_funcs *mfs, const char *s)
{
	char *res;

	if (!s)
		return NULL;

	res = GETDNS_XMALLOC(*mfs, char, strlen(s) + 1);
	if (!res)
		return NULL;
	strcpy(res, s);
	return res;
}

/* mbedTLS 4.x only implements TLS1.2/1.3; older versions clamp up. */
static int
_getdns_tls_version2mbedtls_version(getdns_tls_version_t v)
{
	switch (v) {
	case GETDNS_TLS1_3:
		return MBEDTLS_SSL_VERSION_TLS1_3;
	default:
		return MBEDTLS_SSL_VERSION_TLS1_2;
	}
}

static void
apply_connection_tls_version(_getdns_tls_connection *conn)
{
	getdns_tls_version_t min = conn->min_tls;
	getdns_tls_version_t max = conn->max_tls;

	if (!min)
		min = conn->ctx->min_tls;
	if (!max)
		max = conn->ctx->max_tls;

	mbedtls_ssl_conf_min_tls_version(&conn->conf,
	    min ? _getdns_tls_version2mbedtls_version(min)
	    : MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_max_tls_version(&conn->conf,
	    max ? _getdns_tls_version2mbedtls_version(max)
	    : MBEDTLS_SSL_VERSION_TLS1_3);
}

/* Accepts mbedTLS's own ciphersuite names ("TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"),
 * colon/comma separated. Unrecognized names are skipped and logged; if none match,
 * mbedTLS's own default ciphersuite set stays in effect.
 * cipher_list and cipher_suites both feed the same mbedTLS ciphersuite ID list. */
static void
apply_connection_ciphersuites(_getdns_tls_connection *conn)
{
	const char *lists[2];
	int ids[GETDNS_MBEDTLS_MAX_CIPHERSUITES];
	size_t n = 0;
	size_t i;

	lists[0] =
	    conn->cipher_list ? conn->cipher_list : conn->ctx->cipher_list;
	lists[1] =
	    conn->cipher_suites ? conn->cipher_suites : conn->ctx->
	    cipher_suites;

	for (i = 0; i < 2 && n + 1 < GETDNS_MBEDTLS_MAX_CIPHERSUITES; i++) {
		char *copy, *saveptr, *tok;

		if (!lists[i])
			continue;
		if (!(copy = getdns_strdup(conn->mfs, lists[i])))
			continue;
		for (tok = strtok_r(copy, ":,", &saveptr); tok;
		    tok = strtok_r(NULL, ":,", &saveptr)) {
			int id = mbedtls_ssl_get_ciphersuite_id(tok);

			if (id == 0) {
				_getdns_log(conn->log,
				    GETDNS_LOG_UPSTREAM_STATS,
				    GETDNS_LOG_WARNING,
				    "%s: unrecognized mbedTLS ciphersuite "
				    "name \"%s\", skipping\n",
				    STUB_DEBUG_SETUP_TLS, tok);
				continue;
			}
			if (n + 1 < GETDNS_MBEDTLS_MAX_CIPHERSUITES)
				ids[n++] = id;
		}
		GETDNS_FREE(*conn->mfs, copy);
	}

	GETDNS_FREE(*conn->mfs, conn->ciphersuite_ids);
	conn->ciphersuite_ids = NULL;
	if (n == 0)
		return;

	ids[n] = 0;
	if (!(conn->ciphersuite_ids = GETDNS_XMALLOC(*conn->mfs, int, n + 1)))
		    return;
	memcpy(conn->ciphersuite_ids, ids, (n + 1) * sizeof(int));
	mbedtls_ssl_conf_ciphersuites(&conn->conf, conn->ciphersuite_ids);
}

static getdns_return_t
error_may_want_read_write(int err)
{
	switch (err) {
	case MBEDTLS_ERR_SSL_WANT_READ:
		return GETDNS_RETURN_TLS_WANT_READ;
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		return GETDNS_RETURN_TLS_WANT_WRITE;
	default:
		return GETDNS_RETURN_GENERIC_ERROR;
	}
}

/* getdns owns and connects the fd itself, so plain send()/recv() wrappers
 * are enough - no need for mbedTLS's net_sockets module. */
static int
bio_send(void *p_ctx, const unsigned char *buf, size_t len)
{
	int fd = *(int *) p_ctx;
	ssize_t ret = send(fd, buf, len, 0);

	if (ret >= 0)
		return (int) ret;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	if (errno == EINTR)
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	return -1;
}

static int
bio_recv(void *p_ctx, unsigned char *buf, size_t len)
{
	int fd = *(int *) p_ctx;
	ssize_t ret = recv(fd, buf, len, 0);

	if (ret >= 0)
		return (int) ret;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return MBEDTLS_ERR_SSL_WANT_READ;
	if (errno == EINTR)
		return MBEDTLS_ERR_SSL_WANT_READ;
	return -1;
}

void
_getdns_tls_init()
{
	(void) psa_crypto_init();
}

_getdns_tls_context *
_getdns_tls_context_new(struct mem_funcs *mfs, const getdns_log_config *log)
{
	_getdns_tls_context *res;

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_context)))
		                    return NULL;

	res->mfs = mfs;
	res->cipher_list = res->cipher_suites = res->curve_list = NULL;
	res->min_tls = res->max_tls = 0;
	res->ca_trust_file = NULL;
	res->ca_trust_path = NULL;
	res->have_ca_chain = 0;
	mbedtls_x509_crt_init(&res->ca_chain);
	res->log = log;

	return res;
}

getdns_return_t
_getdns_tls_context_free(struct mem_funcs *mfs, _getdns_tls_context *ctx)
{
	if (!ctx)
		return GETDNS_RETURN_INVALID_PARAMETER;

	mbedtls_x509_crt_free(&ctx->ca_chain);
	GETDNS_FREE(*mfs, ctx->ca_trust_path);
	GETDNS_FREE(*mfs, ctx->ca_trust_file);
	GETDNS_FREE(*mfs, ctx->curve_list);
	GETDNS_FREE(*mfs, ctx->cipher_suites);
	GETDNS_FREE(*mfs, ctx->cipher_list);
	GETDNS_FREE(*mfs, ctx);
	return GETDNS_RETURN_GOOD;
}

void
_getdns_tls_context_pinset_init(_getdns_tls_context *ctx)
{
	(void) ctx;		/* unused parameter */
}

getdns_return_t
_getdns_tls_context_set_min_max_tls_version(_getdns_tls_context *ctx,
    getdns_tls_version_t min, getdns_tls_version_t max)
{
	if (!ctx)
		return GETDNS_RETURN_INVALID_PARAMETER;
	ctx->min_tls = min;
	ctx->max_tls = max;
	return GETDNS_RETURN_GOOD;
}

const char *
_getdns_tls_context_get_default_cipher_list()
{
	return _getdns_tls_context_default_cipher_list;
}

getdns_return_t
_getdns_tls_context_set_cipher_list(_getdns_tls_context *ctx, const char *list)
{
	if (!ctx)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!list)
		list = _getdns_tls_context_default_cipher_list;

	GETDNS_FREE(*ctx->mfs, ctx->cipher_list);
	ctx->cipher_list = getdns_strdup(ctx->mfs, list);
	return GETDNS_RETURN_GOOD;
}

const char *
_getdns_tls_context_get_default_cipher_suites()
{
	return _getdns_tls_context_default_cipher_suites;
}

getdns_return_t
_getdns_tls_context_set_cipher_suites(_getdns_tls_context *ctx,
    const char *list)
{
	if (!ctx)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!list)
		list = _getdns_tls_context_default_cipher_suites;

	GETDNS_FREE(*ctx->mfs, ctx->cipher_suites);
	ctx->cipher_suites = getdns_strdup(ctx->mfs, list);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_context_set_curves_list(_getdns_tls_context *ctx, const char *list)
{
	if (!ctx)
		return GETDNS_RETURN_INVALID_PARAMETER;

	GETDNS_FREE(*ctx->mfs, ctx->curve_list);
	ctx->curve_list = getdns_strdup(ctx->mfs, list);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_context_set_ca(_getdns_tls_context *ctx, const char *file,
    const char *path)
{
	int r;

	if (!ctx)
		return GETDNS_RETURN_INVALID_PARAMETER;

	GETDNS_FREE(*ctx->mfs, ctx->ca_trust_file);
	ctx->ca_trust_file = getdns_strdup(ctx->mfs, file);
	GETDNS_FREE(*ctx->mfs, ctx->ca_trust_path);
	ctx->ca_trust_path = getdns_strdup(ctx->mfs, path);

	mbedtls_x509_crt_free(&ctx->ca_chain);
	mbedtls_x509_crt_init(&ctx->ca_chain);
	ctx->have_ca_chain = 0;

	if (!file && !path) {
		size_t i;
		for (i = 0; _getdns_tls_default_ca_bundle_paths[i]; i++) {
			if (mbedtls_x509_crt_parse_file(&ctx->ca_chain,
				_getdns_tls_default_ca_bundle_paths[i]) >= 0) {
				ctx->have_ca_chain = 1;
				break;
			}
			mbedtls_x509_crt_free(&ctx->ca_chain);
			mbedtls_x509_crt_init(&ctx->ca_chain);
		}
		if (!ctx->have_ca_chain)
			_getdns_log(ctx->log, GETDNS_LOG_UPSTREAM_STATS,
			    GETDNS_LOG_WARNING, "%s: %s\n",
			    STUB_DEBUG_SETUP_TLS,
			    "No CA trust file/path configured, and no system CA "
			    "bundle found in well-known locations; strict TLS "
			    "authentication will fail until one is configured.");
		return GETDNS_RETURN_GOOD;
	}

	if (file) {
		r = mbedtls_x509_crt_parse_file(&ctx->ca_chain, file);
		if (r < 0)
			return GETDNS_RETURN_GENERIC_ERROR;
		ctx->have_ca_chain = 1;
	}
	if (path) {
		r = mbedtls_x509_crt_parse_path(&ctx->ca_chain, path);
		if (r < 0)
			return GETDNS_RETURN_GENERIC_ERROR;
		ctx->have_ca_chain = 1;
	}
	return GETDNS_RETURN_GOOD;
}

_getdns_tls_connection *
_getdns_tls_connection_new(struct mem_funcs *mfs, _getdns_tls_context *ctx,
    int fd, const getdns_log_config *log)
{
	_getdns_tls_connection *res;
	static const char *alpn_protos[] = { "dot", NULL };

	if (!ctx)
		return NULL;

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_connection)))
		                       return NULL;

	res->shutdown = 0;
	res->ctx = ctx;
	res->mfs = mfs;
	res->fd = fd;
	res->cipher_list = res->cipher_suites = res->curve_list = NULL;
	res->min_tls = res->max_tls = 0;
	res->ciphersuite_ids = NULL;
	res->pins = NULL;
	res->npins = 0;
	res->log = log;

	mbedtls_ssl_config_init(&res->conf);
	mbedtls_ssl_init(&res->ssl);

	if (mbedtls_ssl_config_defaults(&res->conf, MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
		goto failed;

#if MBEDTLS_VERSION_MAJOR < 4
	// PSA-internal in 4.x
	mbedtls_ssl_conf_rng(&res->conf, mbedtls_psa_get_random,
	    MBEDTLS_PSA_RANDOM_STATE);
#endif

	/* Default accept-all; hostname auth switches this to REQUIRED, pinset
	 * auth is checked by hand in _getdns_tls_connection_certificate_verify(). */
	mbedtls_ssl_conf_authmode(&res->conf, MBEDTLS_SSL_VERIFY_NONE);

	if (ctx->have_ca_chain)
		mbedtls_ssl_conf_ca_chain(&res->conf, &ctx->ca_chain, NULL);

	apply_connection_tls_version(res);
	apply_connection_ciphersuites(res);

	if (mbedtls_ssl_conf_alpn_protocols(&res->conf, alpn_protos) != 0)
		goto failed;

	if (mbedtls_ssl_setup(&res->ssl, &res->conf) != 0)
		goto failed;

	mbedtls_ssl_set_bio(&res->ssl, &res->fd, bio_send, bio_recv, NULL);

	return res;

      failed:
	_getdns_tls_connection_free(mfs, res);
	return NULL;
}

getdns_return_t
_getdns_tls_connection_free(struct mem_funcs *mfs,
    _getdns_tls_connection *conn)
{
	if (!conn)
		return GETDNS_RETURN_INVALID_PARAMETER;

	mbedtls_ssl_free(&conn->ssl);
	mbedtls_ssl_config_free(&conn->conf);
	GETDNS_FREE(*mfs, conn->pins);
	GETDNS_FREE(*mfs, conn->curve_list);
	GETDNS_FREE(*mfs, conn->cipher_suites);
	GETDNS_FREE(*mfs, conn->cipher_list);
	GETDNS_FREE(*mfs, conn->ciphersuite_ids);
	GETDNS_FREE(*mfs, conn);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_connection_shutdown(_getdns_tls_connection *conn)
{
	if (!conn)
		return GETDNS_RETURN_INVALID_PARAMETER;

	(void) mbedtls_ssl_close_notify(&conn->ssl);
	conn->shutdown++;

	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_connection_set_min_max_tls_version(_getdns_tls_connection *conn,
    getdns_tls_version_t min, getdns_tls_version_t max)
{
	if (!conn)
		return GETDNS_RETURN_INVALID_PARAMETER;
	conn->min_tls = min;
	conn->max_tls = max;
	apply_connection_tls_version(conn);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_connection_set_cipher_list(_getdns_tls_connection *conn,
    const char *list)
{
	if (!conn)
		return GETDNS_RETURN_INVALID_PARAMETER;

	GETDNS_FREE(*conn->mfs, conn->cipher_list);
	conn->cipher_list = list ? getdns_strdup(conn->mfs, list) : NULL;
	apply_connection_ciphersuites(conn);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_connection_set_cipher_suites(_getdns_tls_connection *conn,
    const char *list)
{
	if (!conn)
		return GETDNS_RETURN_INVALID_PARAMETER;

	GETDNS_FREE(*conn->mfs, conn->cipher_suites);
	conn->cipher_suites = list ? getdns_strdup(conn->mfs, list) : NULL;
	apply_connection_ciphersuites(conn);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_connection_set_curves_list(_getdns_tls_connection *conn,
    const char *list)
{
	if (!conn)
		return GETDNS_RETURN_INVALID_PARAMETER;

	GETDNS_FREE(*conn->mfs, conn->curve_list);
	conn->curve_list = list ? getdns_strdup(conn->mfs, list) : NULL;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_connection_set_session(_getdns_tls_connection *conn,
    _getdns_tls_session *s)
{
	mbedtls_ssl_session session;
	int r;

	if (!conn || !s || !s->data)
		return GETDNS_RETURN_INVALID_PARAMETER;

	mbedtls_ssl_session_init(&session);
	r = mbedtls_ssl_session_load(&session, s->data, s->len);
	if (r == 0)
		r = mbedtls_ssl_set_session(&conn->ssl, &session);
	mbedtls_ssl_session_free(&session);

	return r == 0 ? GETDNS_RETURN_GOOD : GETDNS_RETURN_GENERIC_ERROR;
}

_getdns_tls_session *
_getdns_tls_connection_get_session(struct mem_funcs *mfs,
    _getdns_tls_connection *conn)
{
	_getdns_tls_session *res;
	mbedtls_ssl_session session;
	size_t needed = 0;

	if (!conn)
		return NULL;

	mbedtls_ssl_session_init(&session);
	if (mbedtls_ssl_get_session(&conn->ssl, &session) != 0)
		goto failed;
	if (mbedtls_ssl_session_save(&session, NULL, 0,
		&needed) != MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL || needed == 0)
		goto failed;

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_session)))
		                    goto failed;
	res->data = GETDNS_XMALLOC(*mfs, unsigned char, needed);
	if (!res->data) {
		GETDNS_FREE(*mfs, res);
		goto failed;
	}
	if (mbedtls_ssl_session_save(&session, res->data, needed,
		&res->len) != 0) {
		GETDNS_FREE(*mfs, res->data);
		GETDNS_FREE(*mfs, res);
		goto failed;
	}
	mbedtls_ssl_session_free(&session);
	return res;

      failed:
	mbedtls_ssl_session_free(&session);
	return NULL;
}

const char *
_getdns_tls_connection_get_version(_getdns_tls_connection *conn)
{
	if (!conn)
		return NULL;

	return mbedtls_ssl_get_version(&conn->ssl);
}

getdns_return_t
_getdns_tls_connection_do_handshake(_getdns_tls_connection *conn)
{
	int r;

	if (!conn)
		return GETDNS_RETURN_INVALID_PARAMETER;

	r = mbedtls_ssl_handshake(&conn->ssl);
	if (r == 0)
		return GETDNS_RETURN_GOOD;

	if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) {
		char errbuf[128];
		mbedtls_strerror(r, errbuf, sizeof(errbuf));
		_getdns_log(conn->log, GETDNS_LOG_UPSTREAM_STATS,
		    GETDNS_LOG_ERR, "%s: %s %s\n", STUB_DEBUG_SETUP_TLS,
		    "Error in TLS handshake", errbuf);
	}
	return error_may_want_read_write(r);
}

_getdns_tls_x509 *
_getdns_tls_connection_get_peer_certificate(struct mem_funcs *mfs,
    _getdns_tls_connection *conn)
{
	const mbedtls_x509_crt *crt;
	_getdns_tls_x509 *res;

	if (!conn)
		return NULL;

	crt = mbedtls_ssl_get_peer_cert(&conn->ssl);
	if (!crt)
		return NULL;

	if (!(res = GETDNS_MALLOC(*mfs, struct _getdns_tls_x509)))
		                 return NULL;
	res->der = GETDNS_XMALLOC(*mfs, unsigned char, crt->raw.len);
	if (!res->der) {
		GETDNS_FREE(*mfs, res);
		return NULL;
	}
	memcpy(res->der, crt->raw.p, crt->raw.len);
	res->len = crt->raw.len;
	return res;
}

getdns_return_t
_getdns_tls_connection_is_session_reused(_getdns_tls_connection *conn)
{
	if (!conn)
		return GETDNS_RETURN_INVALID_PARAMETER;

	/* mbedTLS 4.x has no public API to query whether a handshake was
	 * resumed. Always reporting FRESH means stub.c never skips
	 * re-verifying a connection that wasn't actually checked. */
	return GETDNS_RETURN_TLS_CONNECTION_FRESH;
}

getdns_return_t
_getdns_tls_connection_setup_hostname_auth(_getdns_tls_connection *conn,
    const char *auth_name)
{
	if (!conn || !auth_name)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (mbedtls_ssl_set_hostname(&conn->ssl, auth_name) != 0)
		return GETDNS_RETURN_GENERIC_ERROR;

	mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_connection_set_host_pinset(_getdns_tls_connection *conn,
    const char *auth_name, const sha256_pin_t *pinset)
{
	size_t npins = 0;
	const sha256_pin_t *pin;
	size_t i;

	(void) auth_name;

	if (!conn)
		return GETDNS_RETURN_INVALID_PARAMETER;

	for (pin = pinset; pin; pin = pin->next)
		npins++;

	GETDNS_FREE(*conn->mfs, conn->pins);
	conn->pins = NULL;
	conn->npins = 0;
	if (npins == 0)
		return GETDNS_RETURN_GOOD;

	conn->pins = GETDNS_XMALLOC(*conn->mfs, _getdns_sha256_hash, npins);
	if (!conn->pins)
		return GETDNS_RETURN_GENERIC_ERROR;

	for (pin = pinset, i = 0; pin; pin = pin->next, i++)
		memcpy(conn->pins[i], pin->pin, SHA256_DIGEST_LENGTH);
	conn->npins = npins;

	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_connection_certificate_verify(_getdns_tls_connection *conn,
    long *errnum, const char **errmsg)
{
	const mbedtls_x509_crt *crt;

	if (!conn)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!conn->pins || conn->npins == 0)
		return GETDNS_RETURN_GOOD;

	crt = mbedtls_ssl_get_peer_cert(&conn->ssl);
	if (!crt) {
		*errnum = 1;
		*errmsg = "No peer certificate";
		return GETDNS_RETURN_GENERIC_ERROR;
	}

	/* mbedTLS has no DANE-alike pinning API; hash each chain cert's SPKI
	 * DER by hand and compare against the pinset. */
	for (; crt; crt = crt->next) {
		unsigned char der[2048];
		int len;
		unsigned char hash[SHA256_DIGEST_LENGTH];
		size_t hash_len;
		size_t i;

		len = mbedtls_pk_write_pubkey_der(&crt->pk, der, sizeof(der));
		if (len < 0)
			continue;

		/* writes at the end of the buffer */
		if (psa_hash_compute(PSA_ALG_SHA_256, der + sizeof(der) - len,
			(size_t) len, hash, sizeof(hash),
			&hash_len) != PSA_SUCCESS)
			continue;

		for (i = 0; i < conn->npins; i++) {
			if (memcmp(hash, conn->pins[i],
				SHA256_DIGEST_LENGTH) == 0)
				return GETDNS_RETURN_GOOD;
		}
	}

	*errnum = 3;
	*errmsg = "Pinset validation: Certificate differs";
	return GETDNS_RETURN_GENERIC_ERROR;
}

getdns_return_t
_getdns_tls_connection_read(_getdns_tls_connection *conn, uint8_t *buf,
    size_t to_read, size_t *read)
{
	int r;

	if (!conn || !read)
		return GETDNS_RETURN_INVALID_PARAMETER;

	/* TLS1.3 NewSessionTicket messages are consumed internally; retry. */
	do {
		r = mbedtls_ssl_read(&conn->ssl, buf, to_read);
	} while (r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET);
	if (r < 0)
		return error_may_want_read_write(r);

	*read = (size_t) r;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_connection_write(_getdns_tls_connection *conn, uint8_t *buf,
    size_t to_write, size_t *written)
{
	int r;

	if (!conn || !written)
		return GETDNS_RETURN_INVALID_PARAMETER;

	r = mbedtls_ssl_write(&conn->ssl, buf, to_write);
	if (r < 0)
		return error_may_want_read_write(r);

	*written = (size_t) r;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_session_free(struct mem_funcs *mfs, _getdns_tls_session *s)
{
	if (!s)
		return GETDNS_RETURN_INVALID_PARAMETER;
	GETDNS_FREE(*mfs, s->data);
	GETDNS_FREE(*mfs, s);
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
_getdns_tls_get_api_information(getdns_dict *dict)
{
	if (getdns_dict_set_int(dict, "mbedtls_build_version_number",
		(int) MBEDTLS_VERSION_NUMBER))
		return GETDNS_RETURN_GENERIC_ERROR;

#ifdef MBEDTLS_VERSION_C
	{
		unsigned int version_number = mbedtls_version_get_number();

		if (getdns_dict_set_int(dict, "mbedtls_runtime_version_number",
			(int) version_number))
			return GETDNS_RETURN_GENERIC_ERROR;

		if (getdns_dict_set_int(dict, "mbedtls_feature_tls1_3",
			mbedtls_version_check_feature
			("MBEDTLS_SSL_PROTO_TLS1_3") == 0))
			return GETDNS_RETURN_GENERIC_ERROR;
	}
#endif
	return GETDNS_RETURN_GOOD;
}

void
_getdns_tls_x509_free(struct mem_funcs *mfs, _getdns_tls_x509 *cert)
{
	if (cert) {
		GETDNS_FREE(*mfs, cert->der);
		GETDNS_FREE(*mfs, cert);
	}
}

int
_getdns_tls_x509_to_der(struct mem_funcs *mfs, _getdns_tls_x509 *cert,
    getdns_bindata *bindata)
{
	if (!cert)
		return 0;

	if (!bindata)
		return (int) cert->len;

	bindata->data = GETDNS_XMALLOC(*mfs, uint8_t, cert->len);
	if (!bindata->data)
		return 0;

	memcpy(bindata->data, cert->der, cert->len);
	bindata->size = cert->len;
	return (int) cert->len;
}

unsigned char *
_getdns_tls_hmac_hash(struct mem_funcs *mfs, int algorithm, const void *key,
    size_t key_size, const void *data, size_t data_size, size_t *output_size)
{
	psa_algorithm_t alg;
	psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	unsigned char *res;
	size_t mac_len = 0;

	switch (algorithm) {
	case GETDNS_HMAC_MD5:
		alg = PSA_ALG_HMAC(PSA_ALG_MD5);
		break;
	case GETDNS_HMAC_SHA1:
		alg = PSA_ALG_HMAC(PSA_ALG_SHA_1);
		break;
	case GETDNS_HMAC_SHA224:
		alg = PSA_ALG_HMAC(PSA_ALG_SHA_224);
		break;
	case GETDNS_HMAC_SHA256:
		alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);
		break;
	case GETDNS_HMAC_SHA384:
		alg = PSA_ALG_HMAC(PSA_ALG_SHA_384);
		break;
	case GETDNS_HMAC_SHA512:
		alg = PSA_ALG_HMAC(PSA_ALG_SHA_512);
		break;
	default:
		return NULL;
	}

	psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attrs, alg);
	psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);

	if (psa_import_key(&attrs, key, key_size, &key_id) != PSA_SUCCESS)
		return NULL;

	res =
	    (unsigned char *) GETDNS_XMALLOC(*mfs, unsigned char,
	    PSA_MAC_LENGTH(PSA_KEY_TYPE_HMAC, 0, alg));
	if (!res) {
		psa_destroy_key(key_id);
		return NULL;
	}

	if (psa_mac_compute(key_id, alg, data, data_size,
		res, PSA_MAC_LENGTH(PSA_KEY_TYPE_HMAC, 0, alg),
		&mac_len) != PSA_SUCCESS) {
		psa_destroy_key(key_id);
		GETDNS_FREE(*mfs, res);
		return NULL;
	}
	psa_destroy_key(key_id);

	if (output_size)
		*output_size = mac_len;
	return res;
}

void
_getdns_tls_sha1(const void *data, size_t data_size, unsigned char *buf)
{
	size_t hash_len;
	(void) psa_hash_compute(PSA_ALG_SHA_1, data, data_size, buf,
	    SHA_DIGEST_LENGTH, &hash_len);
}

void
_getdns_tls_cookie_sha256(uint32_t secret, void *addr, size_t addrlen,
    unsigned char *buf, size_t *buflen)
{
	psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
	size_t hash_len = 0;

	psa_hash_setup(&op, PSA_ALG_SHA_256);
	psa_hash_update(&op, (const uint8_t *) &secret, sizeof(secret));
	psa_hash_update(&op, (const uint8_t *) addr, addrlen);
	psa_hash_finish(&op, buf, SHA256_DIGEST_LENGTH, &hash_len);
	*buflen = hash_len;
}

/* tls.c */
