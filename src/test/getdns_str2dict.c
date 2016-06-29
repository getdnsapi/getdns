/*
 * Copyright (c) 2013, NLNet Labs, Verisign, Inc.
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

#include "config.h"
#include "const-info.h"
#include "jsmn/jsmn.h"
#include "getdns_str2dict.h"
#include "types-internal.h"	/* For getdns_item */
#include "list.h"		/* For _getdns_list_create_from_mf() */
#include "dict.h"		/* For _getdns_dict_create_from_mf() */
#include <stdlib.h>		/* For bsearch */

static struct mem_funcs _getdns_plain_mem_funcs = {
	MF_PLAIN, .mf.pln = { malloc, realloc, free }
};

/* TODO: Replace with gldns_b64_pton
 * once getdns_ipaddr_dict becomes  part of the library
 */
static int _gldns_b64_pton(char const *src, uint8_t *target, size_t targsize)
{
	const uint8_t pad64 = 64; /* is 64th in the b64 array */
	const char* s = src;
	uint8_t in[4];
	size_t o = 0, incount = 0;

	while(*s) {
		/* skip any character that is not base64 */
		/* conceptually we do:
		const char* b64 =      pad'=' is appended to array
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
		const char* d = strchr(b64, *s++);
		and use d-b64;
		*/
		char d = *s++;
		if(d <= 'Z' && d >= 'A')
			d -= 'A';
		else if(d <= 'z' && d >= 'a')
			d = d - 'a' + 26;
		else if(d <= '9' && d >= '0')
			d = d - '0' + 52;
		else if(d == '+')
			d = 62;
		else if(d == '/')
			d = 63;
		else if(d == '=')
			d = 64;
		else	continue;
		in[incount++] = (uint8_t)d;
		if(incount != 4)
			continue;
		/* process whole block of 4 characters into 3 output bytes */
		if(in[3] == pad64 && in[2] == pad64) { /* A B = = */
			if(o+1 > targsize)
				return -1;
			target[o] = (in[0]<<2) | ((in[1]&0x30)>>4);
			o += 1;
			break; /* we are done */
		} else if(in[3] == pad64) { /* A B C = */
			if(o+2 > targsize)
				return -1;
			target[o] = (in[0]<<2) | ((in[1]&0x30)>>4);
			target[o+1]= ((in[1]&0x0f)<<4) | ((in[2]&0x3c)>>2);
			o += 2;
			break; /* we are done */
		} else {
			if(o+3 > targsize)
				return -1;
			/* write xxxxxxyy yyyyzzzz zzwwwwww */
			target[o] = (in[0]<<2) | ((in[1]&0x30)>>4);
			target[o+1]= ((in[1]&0x0f)<<4) | ((in[2]&0x3c)>>2);
			target[o+2]= ((in[2]&0x03)<<6) | in[3];
			o += 3;
		}
		incount = 0;
	}
	return (int)o;
}

static getdns_dict *
_getdns_ipaddr_dict_mf(struct mem_funcs *mf, char *ipstr)
{
	getdns_dict *r = _getdns_dict_create_with_mf(mf);
	char *s = strchr(ipstr, '%'), *scope_id_str = "";
	char *p = strchr(ipstr, '@'), *portstr = "";
	char *t = strchr(ipstr, '#'), *tls_portstr = "";
	char *n = strchr(ipstr, '~'), *tls_namestr = "";
	/* ^[alg:]name:key */
	char *T = strchr(ipstr, '^'), *tsig_name_str = ""
	                            , *tsig_secret_str = ""
	                            , *tsig_algorithm_str = "";
	char *br, *c;
	int            tsig_secret_size;
	uint8_t        tsig_secret_buf[256]; /* 4 times SHA512 */
	getdns_bindata tsig_secret;
	uint8_t buf[sizeof(struct in6_addr)];
	getdns_bindata addr;

	addr.data = buf;

	if (!r) return NULL;

	if (*ipstr == '[') {
		char *br = strchr(ipstr, ']');
		if (br) {
			ipstr += 1;
			*br = 0;
			if ((c = strchr(br + 1, ':'))) {
				p = c;
			}
		}
	} else if ((br = strchr(ipstr, '.')) && (c = strchr(br + 1, ':'))
	    && (T == NULL || c < T))
		p = c;

	else if ((*ipstr == '*') && (c = strchr(ipstr+1, ':')))
		p = c;

	if (s) {
		*s = 0;
		scope_id_str = s + 1;
	}
	if (p) {
		*p = 0;
		portstr = p + 1;
	}
	if (t) {
		*t = 0;
		tls_portstr = t + 1;
	}
	if (n) {
		*n = 0;
		tls_namestr = n + 1;
	}
	if (T) {
		*T = 0;
		tsig_name_str = T + 1;
		if ((T = strchr(tsig_name_str, ':'))) {
			*T = 0;
			tsig_secret_str = T + 1;
			if ((T = strchr(tsig_secret_str, ':'))) {
				*T = 0;
				tsig_algorithm_str  = tsig_name_str;
				tsig_name_str = tsig_secret_str;
				tsig_secret_str  = T + 1;
			}
		} else {
			tsig_name_str = "";
		}
	}
	if (*ipstr == '*') {
		getdns_dict_util_set_string(r, "address_type", "IPv6");
		addr.size = 16;
		(void) memset(buf, 0, 16);
	} else if (strchr(ipstr, ':')) {
		getdns_dict_util_set_string(r, "address_type", "IPv6");
		addr.size = 16;
		if (inet_pton(AF_INET6, ipstr, buf) <= 0) {
			getdns_dict_destroy(r);
			return NULL;
		}
	} else {
		getdns_dict_util_set_string(r, "address_type", "IPv4");
		addr.size = 4;
		if (inet_pton(AF_INET, ipstr, buf) <= 0) {
			getdns_dict_destroy(r);
			return NULL;
		}
	}
	getdns_dict_set_bindata(r, "address_data", &addr);
	if (*portstr)
		getdns_dict_set_int(r, "port", (int32_t)atoi(portstr));
	if (*tls_portstr)
		getdns_dict_set_int(r, "tls_port", (int32_t)atoi(tls_portstr));
	if (*tls_namestr) {
		getdns_dict_util_set_string(r, "tls_auth_name", tls_namestr);
	}
	if (*scope_id_str)
		getdns_dict_util_set_string(r, "scope_id", scope_id_str);
	if (*tsig_name_str)
		getdns_dict_util_set_string(r, "tsig_name", tsig_name_str);
	if (*tsig_algorithm_str)
		getdns_dict_util_set_string(r, "tsig_algorithm", tsig_algorithm_str);
	if (*tsig_secret_str) {
		tsig_secret_size = _gldns_b64_pton(
		    tsig_secret_str, tsig_secret_buf, sizeof(tsig_secret_buf));
		if (tsig_secret_size > 0) {
			tsig_secret.size = tsig_secret_size;
			tsig_secret.data = tsig_secret_buf;
			getdns_dict_set_bindata(r, "tsig_secret", &tsig_secret);
		}
	}
	return r;
}

static int _jsmn_get_ipdict(struct mem_funcs *mf, const char *js, jsmntok_t *t,
    getdns_dict **value)
{
	char value_str[3072];
	int size = t->end - t->start;

	if (size <= 0 || size >= sizeof(value_str))
		return 0;

	(void) memcpy(value_str, js + t->start, size);
	value_str[size] = '\0';

	*value = _getdns_ipaddr_dict_mf(mf, value_str);
	return *value != NULL;
}

getdns_dict *
_getdns_ipaddr_dict(const char *ipstr)
{
	char value_str[3072];
	size_t size = strlen(ipstr);

	if (size >= sizeof(value_str))
		return NULL;

	(void) memcpy(value_str, ipstr, size);
	value_str[size] = '\0';

	return _getdns_ipaddr_dict_mf(&_getdns_plain_mem_funcs, value_str);
}

static int _jsmn_get_data(struct mem_funcs *mf, const char *js, jsmntok_t *t,
    getdns_bindata **value)
{
	size_t i, j;
	uint8_t h, l;

	if ((t->end - t->start) < 4 || (t->end - t->start) % 2 == 1 ||
	    js[t->start] != '0' || js[t->start + 1] != 'x')
		return 0;

	for (i = t->start + 2; i < t->end; i++)
		if (!((js[i] >= '0' && js[i] <= '9')
		    ||(js[i] >= 'a' && js[i] <= 'f')
		    ||(js[i] >= 'A' && js[i] <= 'F')))
			return 0;

	if (!(*value = GETDNS_MALLOC(*mf, getdns_bindata)))
		return 0;

	else if (!((*value)->data = GETDNS_XMALLOC(
	    *mf, uint8_t, (t->end - t->start) / 2 - 1))) {
		GETDNS_FREE(*mf, *value);
		return 0;
	}
	for (i = t->start + 2, j = 0; i < t->end; i++, j++) {
		h = js[i] >= '0' && js[i] <= '9' ? js[i] - '0'
		  : js[i] >= 'A' && js[i] <= 'F' ? js[i] + 10 - 'A'
		                                 : js[i] + 10 - 'a';
		h <<= 4;
		i++;
		l = js[i] >= '0' && js[i] <= '9' ? js[i] - '0'
		  : js[i] >= 'A' && js[i] <= 'F' ? js[i] + 10 - 'A'
		                                 : js[i] + 10 - 'a';
		(*value)->data[j] = h | l;
	}
	(*value)->size = j;
	return 1;
}

static int _jsmn_get_dname(struct mem_funcs *mf, const char *js, jsmntok_t *t,
    getdns_bindata **value)
{
	char value_str[1025];
	int size = t->end - t->start;

	if (size <= 0 || size >= sizeof(value_str) || js[t->end - 1] != '.')
		return 0;

	(void) memcpy(value_str, js + t->start, size);
	value_str[size] = '\0';

	return !getdns_convert_fqdn_to_dns_name(value_str, value);
}

static int _jsmn_get_ipv4(struct mem_funcs *mf, const char *js, jsmntok_t *t,
    getdns_bindata **value)
{
	char value_str[16];
	int size = t->end - t->start;
	uint8_t buf[4];

	if (size <= 0 || size >= sizeof(value_str))
		return 0;

	(void) memcpy(value_str, js + t->start, size);
	value_str[size] = '\0';

	if (inet_pton(AF_INET, value_str, buf) <= 0)
		; /* pass */

	else if (!(*value = GETDNS_MALLOC(*mf, getdns_bindata)))
		; /* pass */

	else if (!((*value)->data = GETDNS_XMALLOC(*mf, uint8_t, 4)))
		GETDNS_FREE(*mf, *value);

	else {
		(*value)->size = 4;
		(void) memcpy((*value)->data, buf, 4);
		return 1;
	}
	return 0;
}

static int _jsmn_get_ipv6(struct mem_funcs *mf, const char *js, jsmntok_t *t,
    getdns_bindata **value)
{
	char value_str[40];
	int size = t->end - t->start;
	uint8_t buf[16];

	if (size <= 0 || size >= sizeof(value_str))
		return 0;

	(void) memcpy(value_str, js + t->start, size);
	value_str[size] = '\0';

	if (inet_pton(AF_INET6, value_str, buf) <= 0)
		; /* pass */

	else if (!(*value = GETDNS_MALLOC(*mf, getdns_bindata)))
		; /* pass */

	else if (!((*value)->data = GETDNS_XMALLOC(*mf, uint8_t, 16)))
		GETDNS_FREE(*mf, *value);

	else {
		(*value)->size = 16;
		(void) memcpy((*value)->data, buf, 16);
		return 1;
	}
	return 0;
}

static int _jsmn_get_int(struct mem_funcs *mf, const char *js, jsmntok_t *t,
    uint32_t *value)
{
	char value_str[11];
	int size = t->end - t->start;
	char *endptr;

	if (size <= 0 || size >= sizeof(value_str))
		return 0;

	(void) memcpy(value_str, js + t->start, size);
	value_str[size] = '\0';

	*value = (uint32_t)strtoul(value_str, &endptr, 10);
	return *value_str != '\0' && *endptr == '\0';
}

static int _getdns_get_const_name_info(const char *name, uint32_t *code);

static int _jsmn_get_const(struct mem_funcs *mf, const char *js, jsmntok_t *t,
    uint32_t *value)
{
	char value_str[80];
	int size = t->end - t->start;

	if (size <= 0 || size >= sizeof(value_str))
		return 0;

	(void) memcpy(value_str, js + t->start, size);
	value_str[size] = '\0';

	return _getdns_get_const_name_info(value_str, value);
}

static void
_getdns_destroy_item_data(struct mem_funcs *mf, getdns_item *item)
{
	switch (item->dtype) {
	case t_dict:
		getdns_dict_destroy(item->data.dict);
		break;

	case t_list:
		getdns_list_destroy(item->data.list);
		break;

	case t_bindata:
		GETDNS_FREE(*mf, item->data.bindata->data);
		GETDNS_FREE(*mf, item->data.bindata);
	default:
		break;
	}
}
static int _jsmn_get_item(struct mem_funcs *mf, const char *js, jsmntok_t *t,
    size_t count, getdns_item *item, getdns_return_t *r);

static int _jsmn_get_dict(struct mem_funcs *mf, const char *js, jsmntok_t *t,
    size_t count, getdns_dict *dict, getdns_return_t *r)
{
	size_t i, j = 1;
	char key_spc[1024], *key = NULL;
	getdns_item child_item;

	for (i = 0; i < t->size; i++) {
		if (t[j].type != JSMN_STRING &&
		    t[j].type != JSMN_PRIMITIVE) {

			/* Key must be string or primitive */
			*r = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
			break;
		}
		if (t[j].end <= t[j].start) {
			/* Key must be at least 1 character */
			*r = GETDNS_RETURN_GENERIC_ERROR; /* range error */
			break;
		}
		if (t[j].end - t[j].start < sizeof(key_spc))
			key = key_spc;

		else if (!(key = GETDNS_XMALLOC(
		    *mf, char, t[j].end - t[j].start + 1))) {

			*r = GETDNS_RETURN_MEMORY_ERROR;
			break;
		}
		(void) memcpy(key, js + t[j].start, t[j].end - t[j].start);
		key[t[j].end - t[j].start] = '\0';
		j += 1;

		j += _jsmn_get_item(mf, js, t + j, count - j, &child_item, r);
		if (*r) break;

		switch (child_item.dtype) {
		case t_int:
			*r = getdns_dict_set_int(dict, key,
			    child_item.data.n);
			break;
		case t_bindata:
			*r = getdns_dict_set_bindata(dict, key,
			    child_item.data.bindata);
			break;
		case t_list:
			*r = getdns_dict_set_list(dict, key,
			    child_item.data.list);
			break;
		case t_dict:
			*r = getdns_dict_set_dict(dict, key,
			    child_item.data.dict);
			break;
		default:
			*r = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
			break;

		}
		_getdns_destroy_item_data(mf, &child_item);
		if (*r) break;
		if (key && key != key_spc) {
			GETDNS_FREE(*mf, key);
			key = NULL;
		}
	}
	if (key && key != key_spc)
		GETDNS_FREE(*mf, key);

	if (*r) {
		getdns_dict_destroy(dict);
		return 0;
	}
	return j;
}

static int _jsmn_get_list(struct mem_funcs *mf, const char *js, jsmntok_t *t,
    size_t count, getdns_list *list, getdns_return_t *r)
{
	size_t i, j = 1, index = 0;
	getdns_item child_item;

	for (i = 0; i < t->size; i++) {
		j += _jsmn_get_item(mf, js, t + j, count - j, &child_item, r);
		if (*r) break;

		switch (child_item.dtype) {
		case t_int:
			*r = getdns_list_set_int(list, index++,
			    child_item.data.n);
			break;
		case t_bindata:
			*r = getdns_list_set_bindata(list, index++,
			    child_item.data.bindata);
			break;
		case t_list:
			*r = getdns_list_set_list(list, index++,
			    child_item.data.list);
			break;
		case t_dict:
			*r = getdns_list_set_dict(list, index++,
			    child_item.data.dict);
			break;
		default:
			*r = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
			break;

		}
		_getdns_destroy_item_data(mf, &child_item);
		if (*r) break;
	}
	if (*r) {
		getdns_list_destroy(list);
		return 0;
	}
	return j;
}

static int _jsmn_get_item(struct mem_funcs *mf, const char *js, jsmntok_t *t,
    size_t count, getdns_item *item, getdns_return_t *r)
{
	assert(item);

	switch (t->type) {
	case JSMN_STRING:
		if (t->end < t->start)
			*r = GETDNS_RETURN_GENERIC_ERROR;

		else if (!(item->data.bindata =
		    GETDNS_MALLOC(*mf, getdns_bindata)))
			*r = GETDNS_RETURN_MEMORY_ERROR;

		else if (!(item->data.bindata->data = GETDNS_XMALLOC(
		    *mf, uint8_t, t->end - t->start + 1))) {
			GETDNS_FREE(*mf, item->data.bindata);
			*r = GETDNS_RETURN_MEMORY_ERROR;
		} else {
			item->dtype = t_bindata;
			if (t->end - t->start) {
				(void) memcpy(item->data.bindata->data,
				    js + t->start, t->end - t->start);
			}
			item->data.bindata->data[t->end - t->start] = '\0';
			item->data.bindata->size = t->end - t->start;
			*r = GETDNS_RETURN_GOOD;
			return 1;
		}
		break;

	case JSMN_PRIMITIVE:
		/* There is no such thing as an empty primitive */
		if (t->end <= t->start) {
			*r = GETDNS_RETURN_GENERIC_ERROR;
			break;

		} else if (_jsmn_get_int(mf, js, t, &item->data.n)
		    || _jsmn_get_const(mf, js, t, &item->data.n)) {

			item->dtype = t_int;
		}
		else if (_jsmn_get_data(mf, js, t, &item->data.bindata)
		    || _jsmn_get_dname(mf, js, t,  &item->data.bindata)
		    || _jsmn_get_ipv4(mf, js, t,  &item->data.bindata)
		    || _jsmn_get_ipv6(mf, js, t,  &item->data.bindata))

			item->dtype = t_bindata;

		else if (_jsmn_get_ipdict(mf, js, t, &item->data.dict))

			item->dtype = t_dict;
		else {
			*r = GETDNS_RETURN_GENERIC_ERROR;
			break;
		}
		*r = GETDNS_RETURN_GOOD;
		return 1;

	case JSMN_OBJECT:
		if (!(item->data.dict = _getdns_dict_create_with_mf(mf))) {
			*r = GETDNS_RETURN_MEMORY_ERROR;
			break;
		}
		item->dtype = t_dict;
		return _jsmn_get_dict(mf, js, t, count, item->data.dict, r);

	case JSMN_ARRAY:
		if (!(item->data.list = _getdns_list_create_with_mf(mf))) {
			*r = GETDNS_RETURN_MEMORY_ERROR;
			break;
		}
		item->dtype = t_list;
		return _jsmn_get_list(mf, js, t, count, item->data.list, r);

	default:
		*r = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
		break;
	}
	return 0;
}

static getdns_return_t
_getdns_str2item_mf(struct mem_funcs *mf, const char *str, getdns_item *item)
{
	jsmn_parser p;
	jsmntok_t *tok = NULL, *new_tok;
	size_t tokcount = 100;
	int r;
	getdns_return_t gr;

	jsmn_init(&p);
	tok = GETDNS_XMALLOC(*mf, jsmntok_t, tokcount);
	do {
		r = jsmn_parse(&p, str, strlen(str), tok, tokcount);
		if (r == JSMN_ERROR_NOMEM) {
			tokcount *= 2;
			if (!(new_tok = GETDNS_XREALLOC(
			    *mf, tok, jsmntok_t, tokcount))) {
				GETDNS_FREE(*mf, tok);
				return GETDNS_RETURN_MEMORY_ERROR;
			} 
			tok  = new_tok;
		}
	} while (r == JSMN_ERROR_NOMEM);
	if (r < 0) 
		gr = GETDNS_RETURN_GENERIC_ERROR;
	else
		(void) _jsmn_get_item(mf, str, tok, p.toknext, item, &gr);
	GETDNS_FREE(*mf, tok);
	return gr;
}

getdns_return_t
getdns_str2dict(const char *str, getdns_dict **dict)
{
	getdns_item item;
	getdns_return_t r;

	if ((r = _getdns_str2item_mf(&_getdns_plain_mem_funcs, str, &item)))
		return r;

	else if (item.dtype != t_dict) {
		_getdns_destroy_item_data(&_getdns_plain_mem_funcs, &item);
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
	}
	*dict = item.data.dict;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_str2list(const char *str, getdns_list **list)
{
	getdns_item item;
	getdns_return_t r;

	if ((r = _getdns_str2item_mf(&_getdns_plain_mem_funcs, str, &item)))
		return r;

	else if (item.dtype != t_list) {
		_getdns_destroy_item_data(&_getdns_plain_mem_funcs, &item);
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
	}
	*list = item.data.list;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_str2bindata(const char *str, getdns_bindata **bindata)
{
	getdns_item item;
	getdns_return_t r;

	if ((r = _getdns_str2item_mf(&_getdns_plain_mem_funcs, str, &item)))
		return r;

	else if (item.dtype != t_bindata) {
		_getdns_destroy_item_data(&_getdns_plain_mem_funcs, &item);
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
	}
	*bindata = item.data.bindata;
	return GETDNS_RETURN_GOOD;
}

getdns_return_t
getdns_str2int(const char *str, uint32_t *value)
{
	getdns_item item;
	getdns_return_t r;

	if ((r = _getdns_str2item_mf(&_getdns_plain_mem_funcs, str, &item)))
		return r;

	else if (item.dtype != t_int) {
		_getdns_destroy_item_data(&_getdns_plain_mem_funcs, &item);
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;
	}
	*value = item.data.n;
	return GETDNS_RETURN_GOOD;
}


struct const_name_info { const char *name; uint32_t code; };
static struct const_name_info consts_name_info[] = {
	{ "GETDNS_APPEND_NAME_ALWAYS", 550 },
	{ "GETDNS_APPEND_NAME_NEVER", 553 },
	{ "GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE", 552 },
	{ "GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE", 551 },
	{ "GETDNS_APPEND_NAME_TO_SINGLE_LABEL_FIRST", 554 },
	{ "GETDNS_AUTHENTICATION_NONE", 1300 },
	{ "GETDNS_AUTHENTICATION_REQUIRED", 1301 },
	{ "GETDNS_BAD_DNS_ALL_NUMERIC_LABEL", 1101 },
	{ "GETDNS_BAD_DNS_CNAME_IN_TARGET", 1100 },
	{ "GETDNS_BAD_DNS_CNAME_RETURNED_FOR_OTHER_TYPE", 1102 },
	{ "GETDNS_CALLBACK_CANCEL", 701 },
	{ "GETDNS_CALLBACK_COMPLETE", 700 },
	{ "GETDNS_CALLBACK_ERROR", 703 },
	{ "GETDNS_CALLBACK_TIMEOUT", 702 },
	{ "GETDNS_CONTEXT_CODE_APPEND_NAME", 607 },
	{ "GETDNS_CONTEXT_CODE_DNSSEC_ALLOWED_SKEW", 614 },
	{ "GETDNS_CONTEXT_CODE_DNSSEC_TRUST_ANCHORS", 609 },
	{ "GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS", 604 },
	{ "GETDNS_CONTEXT_CODE_DNS_TRANSPORT", 605 },
	{ "GETDNS_CONTEXT_CODE_EDNS_CLIENT_SUBNET_PRIVATE", 619 },
	{ "GETDNS_CONTEXT_CODE_EDNS_DO_BIT", 613 },
	{ "GETDNS_CONTEXT_CODE_EDNS_EXTENDED_RCODE", 611 },
	{ "GETDNS_CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE", 610 },
	{ "GETDNS_CONTEXT_CODE_EDNS_VERSION", 612 },
	{ "GETDNS_CONTEXT_CODE_FOLLOW_REDIRECTS", 602 },
	{ "GETDNS_CONTEXT_CODE_IDLE_TIMEOUT", 617 },
	{ "GETDNS_CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES", 606 },
	{ "GETDNS_CONTEXT_CODE_MEMORY_FUNCTIONS", 615 },
	{ "GETDNS_CONTEXT_CODE_NAMESPACES", 600 },
	{ "GETDNS_CONTEXT_CODE_PUBKEY_PINSET", 621 },
	{ "GETDNS_CONTEXT_CODE_RESOLUTION_TYPE", 601 },
	{ "GETDNS_CONTEXT_CODE_SUFFIX", 608 },
	{ "GETDNS_CONTEXT_CODE_TIMEOUT", 616 },
	{ "GETDNS_CONTEXT_CODE_TLS_AUTHENTICATION", 618 },
	{ "GETDNS_CONTEXT_CODE_TLS_QUERY_PADDING_BLOCKSIZE", 620 },
	{ "GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS", 603 },
	{ "GETDNS_DNSSEC_BOGUS", 401 },
	{ "GETDNS_DNSSEC_INDETERMINATE", 402 },
	{ "GETDNS_DNSSEC_INSECURE", 403 },
	{ "GETDNS_DNSSEC_NOT_PERFORMED", 404 },
	{ "GETDNS_DNSSEC_SECURE", 400 },
	{ "GETDNS_EXTENSION_FALSE", 1001 },
	{ "GETDNS_EXTENSION_TRUE", 1000 },
	{ "GETDNS_NAMESPACE_DNS", 500 },
	{ "GETDNS_NAMESPACE_LOCALNAMES", 501 },
	{ "GETDNS_NAMESPACE_MDNS", 503 },
	{ "GETDNS_NAMESPACE_NETBIOS", 502 },
	{ "GETDNS_NAMESPACE_NIS", 504 },
	{ "GETDNS_NAMETYPE_DNS", 800 },
	{ "GETDNS_NAMETYPE_WINS", 801 },
	{ "GETDNS_OPCODE_IQUERY", 1 },
	{ "GETDNS_OPCODE_NOTIFY", 4 },
	{ "GETDNS_OPCODE_QUERY", 0 },
	{ "GETDNS_OPCODE_STATUS", 2 },
	{ "GETDNS_OPCODE_UPDATE", 5 },
	{ "GETDNS_RCODE_BADALG", 21 },
	{ "GETDNS_RCODE_BADKEY", 17 },
	{ "GETDNS_RCODE_BADMODE", 19 },
	{ "GETDNS_RCODE_BADNAME", 20 },
	{ "GETDNS_RCODE_BADSIG", 16 },
	{ "GETDNS_RCODE_BADTIME", 18 },
	{ "GETDNS_RCODE_BADTRUNC", 22 },
	{ "GETDNS_RCODE_BADVERS", 16 },
	{ "GETDNS_RCODE_FORMERR", 1 },
	{ "GETDNS_RCODE_NOERROR", 0 },
	{ "GETDNS_RCODE_NOTAUTH", 9 },
	{ "GETDNS_RCODE_NOTIMP", 4 },
	{ "GETDNS_RCODE_NOTZONE", 10 },
	{ "GETDNS_RCODE_NXDOMAIN", 3 },
	{ "GETDNS_RCODE_NXRRSET", 8 },
	{ "GETDNS_RCODE_REFUSED", 5 },
	{ "GETDNS_RCODE_SERVFAIL", 2 },
	{ "GETDNS_RCODE_YXDOMAIN", 6 },
	{ "GETDNS_RCODE_YXRRSET", 7 },
	{ "GETDNS_REDIRECTS_DO_NOT_FOLLOW", 531 },
	{ "GETDNS_REDIRECTS_FOLLOW", 530 },
	{ "GETDNS_RESOLUTION_RECURSING", 521 },
	{ "GETDNS_RESOLUTION_STUB", 520 },
	{ "GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS", 904 },
	{ "GETDNS_RESPSTATUS_ALL_TIMEOUT", 902 },
	{ "GETDNS_RESPSTATUS_GOOD", 900 },
	{ "GETDNS_RESPSTATUS_NO_NAME", 901 },
	{ "GETDNS_RESPSTATUS_NO_SECURE_ANSWERS", 903 },
	{ "GETDNS_RETURN_BAD_CONTEXT", 301 },
	{ "GETDNS_RETURN_BAD_DOMAIN_NAME", 300 },
	{ "GETDNS_RETURN_CONTEXT_UPDATE_FAIL", 302 },
	{ "GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED", 309 },
	{ "GETDNS_RETURN_EXTENSION_MISFORMAT", 308 },
	{ "GETDNS_RETURN_GENERIC_ERROR", 1 },
	{ "GETDNS_RETURN_GOOD", 0 },
	{ "GETDNS_RETURN_INVALID_PARAMETER", 311 },
	{ "GETDNS_RETURN_MEMORY_ERROR", 310 },
	{ "GETDNS_RETURN_NEED_MORE_SPACE", 399 },
	{ "GETDNS_RETURN_NOT_IMPLEMENTED", 312 },
	{ "GETDNS_RETURN_NO_SUCH_DICT_NAME", 305 },
	{ "GETDNS_RETURN_NO_SUCH_EXTENSION", 307 },
	{ "GETDNS_RETURN_NO_SUCH_LIST_ITEM", 304 },
	{ "GETDNS_RETURN_UNKNOWN_TRANSACTION", 303 },
	{ "GETDNS_RETURN_WRONG_TYPE_REQUESTED", 306 },
	{ "GETDNS_RRCLASS_ANY", 255 },
	{ "GETDNS_RRCLASS_CH", 3 },
	{ "GETDNS_RRCLASS_HS", 4 },
	{ "GETDNS_RRCLASS_IN", 1 },
	{ "GETDNS_RRCLASS_NONE", 254 },
	{ "GETDNS_RRTYPE_A", 1 },
	{ "GETDNS_RRTYPE_AAAA", 28 },
	{ "GETDNS_RRTYPE_AFSDB", 18 },
	{ "GETDNS_RRTYPE_ANY", 255 },
	{ "GETDNS_RRTYPE_APL", 42 },
	{ "GETDNS_RRTYPE_ATMA", 34 },
	{ "GETDNS_RRTYPE_AXFR", 252 },
	{ "GETDNS_RRTYPE_CAA", 257 },
	{ "GETDNS_RRTYPE_CDNSKEY", 60 },
	{ "GETDNS_RRTYPE_CDS", 59 },
	{ "GETDNS_RRTYPE_CERT", 37 },
	{ "GETDNS_RRTYPE_CNAME", 5 },
	{ "GETDNS_RRTYPE_CSYNC", 62 },
	{ "GETDNS_RRTYPE_DHCID", 49 },
	{ "GETDNS_RRTYPE_DLV", 32769 },
	{ "GETDNS_RRTYPE_DNAME", 39 },
	{ "GETDNS_RRTYPE_DNSKEY", 48 },
	{ "GETDNS_RRTYPE_DS", 43 },
	{ "GETDNS_RRTYPE_EID", 31 },
	{ "GETDNS_RRTYPE_GID", 102 },
	{ "GETDNS_RRTYPE_GPOS", 27 },
	{ "GETDNS_RRTYPE_HINFO", 13 },
	{ "GETDNS_RRTYPE_HIP", 55 },
	{ "GETDNS_RRTYPE_IPSECKEY", 45 },
	{ "GETDNS_RRTYPE_ISDN", 20 },
	{ "GETDNS_RRTYPE_IXFR", 251 },
	{ "GETDNS_RRTYPE_KEY", 25 },
	{ "GETDNS_RRTYPE_KX", 36 },
	{ "GETDNS_RRTYPE_LOC", 29 },
	{ "GETDNS_RRTYPE_LP", 107 },
	{ "GETDNS_RRTYPE_MAILA", 254 },
	{ "GETDNS_RRTYPE_MAILB", 253 },
	{ "GETDNS_RRTYPE_MB", 7 },
	{ "GETDNS_RRTYPE_MD", 3 },
	{ "GETDNS_RRTYPE_MF", 4 },
	{ "GETDNS_RRTYPE_MG", 8 },
	{ "GETDNS_RRTYPE_MINFO", 14 },
	{ "GETDNS_RRTYPE_MR", 9 },
	{ "GETDNS_RRTYPE_MX", 15 },
	{ "GETDNS_RRTYPE_NAPTR", 35 },
	{ "GETDNS_RRTYPE_NID", 104 },
	{ "GETDNS_RRTYPE_NIMLOC", 32 },
	{ "GETDNS_RRTYPE_NINFO", 56 },
	{ "GETDNS_RRTYPE_NS", 2 },
	{ "GETDNS_RRTYPE_NSAP", 22 },
	{ "GETDNS_RRTYPE_NSEC", 47 },
	{ "GETDNS_RRTYPE_NULL", 10 },
	{ "GETDNS_RRTYPE_NXT", 30 },
	{ "GETDNS_RRTYPE_OPENPGPKEY", 61 },
	{ "GETDNS_RRTYPE_OPT", 41 },
	{ "GETDNS_RRTYPE_PTR", 12 },
	{ "GETDNS_RRTYPE_PX", 26 },
	{ "GETDNS_RRTYPE_RKEY", 57 },
	{ "GETDNS_RRTYPE_RP", 17 },
	{ "GETDNS_RRTYPE_RRSIG", 46 },
	{ "GETDNS_RRTYPE_RT", 21 },
	{ "GETDNS_RRTYPE_SIG", 24 },
	{ "GETDNS_RRTYPE_SINK", 40 },
	{ "GETDNS_RRTYPE_SOA", 6 },
	{ "GETDNS_RRTYPE_SPF", 99 },
	{ "GETDNS_RRTYPE_SRV", 33 },
	{ "GETDNS_RRTYPE_SSHFP", 44 },
	{ "GETDNS_RRTYPE_TA", 32768 },
	{ "GETDNS_RRTYPE_TALINK", 58 },
	{ "GETDNS_RRTYPE_TKEY", 249 },
	{ "GETDNS_RRTYPE_TLSA", 52 },
	{ "GETDNS_RRTYPE_TSIG", 250 },
	{ "GETDNS_RRTYPE_TXT", 16 },
	{ "GETDNS_RRTYPE_UID", 101 },
	{ "GETDNS_RRTYPE_UINFO", 100 },
	{ "GETDNS_RRTYPE_UNSPEC", 103 },
	{ "GETDNS_RRTYPE_URI", 256 },
	{ "GETDNS_RRTYPE_WKS", 11 },
	{ "GETDNS_TRANSPORT_TCP", 1201 },
	{ "GETDNS_TRANSPORT_TCP_ONLY", 542 },
	{ "GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN", 543 },
	{ "GETDNS_TRANSPORT_TLS", 1202 },
	{ "GETDNS_TRANSPORT_TLS_FIRST_AND_FALL_BACK_TO_TCP_KEEP_CONNECTIONS_OPEN", 545 },
	{ "GETDNS_TRANSPORT_TLS_ONLY_KEEP_CONNECTIONS_OPEN", 544 },
	{ "GETDNS_TRANSPORT_UDP", 1200 },
	{ "GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP", 540 },
	{ "GETDNS_TRANSPORT_UDP_ONLY", 541 },
};
static int const_name_info_cmp(const void *a, const void *b)
{
	return strcmp( ((struct const_name_info *) a)->name
	             , ((struct const_name_info *) b)->name );
}
static int
_getdns_get_const_name_info(const char *name, uint32_t *code)
{
	struct const_name_info key = { name, 0 };
	struct const_name_info *i = bsearch(&key, consts_name_info,
	    sizeof(consts_name_info) / sizeof(struct const_name_info),
	    sizeof(struct const_name_info), const_name_info_cmp);
	if (!i)
		return 0;
	if (code)
		*code = i->code;
	return 1;
}
