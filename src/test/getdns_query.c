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
#include "debug.h"
#include "const-info.h"
#include "jsmn/jsmn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#ifndef USE_WINSOCK
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#else
#include <winsock2.h>
#include <iphlpapi.h>
typedef unsigned short in_port_t;
#include <windows.h>
#include <wincrypt.h>
#endif


#define MAX_TIMEOUTS FD_SETSIZE

#define EXAMPLE_PIN "pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\""

/* Eventloop based on select */
typedef struct my_eventloop {
	getdns_eventloop        base;
	getdns_eventloop_event *fd_events[FD_SETSIZE];
	uint64_t                fd_timeout_times[FD_SETSIZE];
	getdns_eventloop_event *timeout_events[MAX_TIMEOUTS];
	uint64_t                timeout_times[MAX_TIMEOUTS];
} my_eventloop;

static uint64_t get_now_plus(uint64_t amount)
{
	struct timeval tv;
	uint64_t       now;
	
	if (gettimeofday(&tv, NULL)) {
		perror("gettimeofday() failed");
		exit(EXIT_FAILURE);
	}
	now = tv.tv_sec * 1000000 + tv.tv_usec;

	return (now + amount * 1000) >= now ? now + amount * 1000 : -1;
}

getdns_return_t
my_eventloop_schedule(getdns_eventloop *loop,
    int fd, uint64_t timeout, getdns_eventloop_event *event)
{
	my_eventloop *my_loop  = (my_eventloop *)loop;
	size_t        i;

	DEBUG_SCHED( "%s(loop: %p, fd: %d, timeout: %"PRIu64", event: %p, FD_SETSIZE: %d)\n"
	        , __FUNCTION__, loop, fd, timeout, event, FD_SETSIZE);

	assert(loop);
	assert(event);
	assert(fd < FD_SETSIZE);

	if (fd >= 0 && (event->read_cb || event->write_cb)) {
		assert(my_loop->fd_events[fd] == NULL);

		my_loop->fd_events[fd] = event;
		my_loop->fd_timeout_times[fd] = get_now_plus(timeout);
		event->ev = (void *) (intptr_t) fd + 1;

		DEBUG_SCHED( "scheduled read/write at %d\n", fd);
		return GETDNS_RETURN_GOOD;
	}

	assert(event->timeout_cb && !event->read_cb && !event->write_cb);

	for (i = 0; i < MAX_TIMEOUTS; i++) {
		if (my_loop->timeout_events[i] == NULL) {
			my_loop->timeout_events[i] = event;
			my_loop->timeout_times[i] = get_now_plus(timeout);
			event->ev = (void *) (intptr_t) i + 1;

			DEBUG_SCHED( "scheduled timeout at %d\n", (int)i);
			return GETDNS_RETURN_GOOD;
		}
	}
	return GETDNS_RETURN_GENERIC_ERROR;
}

getdns_return_t
my_eventloop_clear(getdns_eventloop *loop, getdns_eventloop_event *event)
{
	my_eventloop *my_loop = (my_eventloop *)loop;
	size_t i;

	assert(loop);
	assert(event);

	DEBUG_SCHED( "%s(loop: %p, event: %p)\n", __FUNCTION__, loop, event);

	i = (intptr_t)event->ev - 1;
	assert(i >= 0 && i < FD_SETSIZE);

	if (event->timeout_cb && !event->read_cb && !event->write_cb) {
		assert(my_loop->timeout_events[i] == event);
		my_loop->timeout_events[i] = NULL;
	} else {
		assert(my_loop->fd_events[i] == event);
		my_loop->fd_events[i] = NULL;
	}
	event->ev = NULL;
	return GETDNS_RETURN_GOOD;
}

void my_eventloop_cleanup(getdns_eventloop *loop)
{
}

void my_read_cb(int fd, getdns_eventloop_event *event)
{
	DEBUG_SCHED( "%s(fd: %d, event: %p)\n", __FUNCTION__, fd, event);
	event->read_cb(event->userarg);
}

void my_write_cb(int fd, getdns_eventloop_event *event)
{
	DEBUG_SCHED( "%s(fd: %d, event: %p)\n", __FUNCTION__, fd, event);
	event->write_cb(event->userarg);
}

void my_timeout_cb(int fd, getdns_eventloop_event *event)
{
	DEBUG_SCHED( "%s(fd: %d, event: %p)\n", __FUNCTION__, fd, event);
	event->timeout_cb(event->userarg);
}

void my_eventloop_run_once(getdns_eventloop *loop, int blocking)
{
	my_eventloop *my_loop = (my_eventloop *)loop;

	fd_set   readfds, writefds;
	int      fd, max_fd = -1;
	uint64_t now, timeout = (uint64_t)-1;
	size_t   i;
	struct timeval tv;

	assert(loop);

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	now = get_now_plus(0);

	for (i = 0; i < MAX_TIMEOUTS; i++) {
		if (!my_loop->timeout_events[i])
			continue;
		if (now > my_loop->timeout_times[i])
			my_timeout_cb(-1, my_loop->timeout_events[i]);
		else if (my_loop->timeout_times[i] < timeout)
			timeout = my_loop->timeout_times[i];
	}
	for (fd = 0; fd < FD_SETSIZE; fd++) {
		if (!my_loop->fd_events[fd])
			continue;
		if (my_loop->fd_events[fd]->read_cb)
			FD_SET(fd, &readfds);
		if (my_loop->fd_events[fd]->write_cb)
			FD_SET(fd, &writefds);
		if (fd > max_fd)
			max_fd = fd;
		if (my_loop->fd_timeout_times[fd] < timeout)
			timeout = my_loop->fd_timeout_times[fd];
	}
	if (max_fd == -1 && timeout == (uint64_t)-1)
		return;

	if (! blocking || now > timeout) {
		tv.tv_sec = 0;
		tv.tv_usec = 0;
	} else {
		tv.tv_sec  = (timeout - now) / 1000000;
		tv.tv_usec = (timeout - now) % 1000000;
	}
	if (select(max_fd + 1, &readfds, &writefds, NULL, &tv) < 0) {
		perror("select() failed");
		exit(EXIT_FAILURE);
	}
	now = get_now_plus(0);
	for (fd = 0; fd < FD_SETSIZE; fd++) {
		if (my_loop->fd_events[fd] &&
		    my_loop->fd_events[fd]->read_cb &&
		    FD_ISSET(fd, &readfds))
			my_read_cb(fd, my_loop->fd_events[fd]);

		if (my_loop->fd_events[fd] &&
		    my_loop->fd_events[fd]->write_cb &&
		    FD_ISSET(fd, &writefds))
			my_write_cb(fd, my_loop->fd_events[fd]);

		if (my_loop->fd_events[fd] &&
		    my_loop->fd_events[fd]->timeout_cb &&
		    now > my_loop->fd_timeout_times[fd])
			my_timeout_cb(fd, my_loop->fd_events[fd]);

		i = fd;
		if (my_loop->timeout_events[i] &&
		    my_loop->timeout_events[i]->timeout_cb &&
		    now > my_loop->timeout_times[i])
			my_timeout_cb(-1, my_loop->timeout_events[i]);
	}
}

void my_eventloop_run(getdns_eventloop *loop)
{
	my_eventloop *my_loop = (my_eventloop *)loop;
	size_t        i;

	assert(loop);

	i = 0;
	while (i < MAX_TIMEOUTS) {
		if (my_loop->fd_events[i] || my_loop->timeout_events[i]) {
			my_eventloop_run_once(loop, 1);
			i = 0;
		} else {
			i++;
		}
	}
}

void my_eventloop_init(my_eventloop *loop)
{
	static getdns_eventloop_vmt my_eventloop_vmt = {
		my_eventloop_cleanup,
		my_eventloop_schedule,
		my_eventloop_clear,
		my_eventloop_run,
		my_eventloop_run_once
	};

	(void) memset(loop, 0, sizeof(my_eventloop));
	loop->base.vmt = &my_eventloop_vmt;
}

static int quiet = 0;
static int batch_mode = 0;
static char *query_file = NULL;
static int json = 0;
static char *the_root = ".";
static char *name;
static getdns_context *context;
static getdns_dict *extensions;
static getdns_list *pubkey_pinset = NULL;
static getdns_list *listen_list = NULL;
static size_t pincount = 0;
static size_t listen_count = 0;
static uint16_t request_type = GETDNS_RRTYPE_NS;
static int timeout, edns0_size, padding_blocksize;
static int async = 0, interactive = 0;
static enum { GENERAL, ADDRESS, HOSTNAME, SERVICE } calltype = GENERAL;

int get_rrtype(const char *t);

int gqldns_b64_pton(char const *src, uint8_t *target, size_t targsize)
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

getdns_dict *
ipaddr_dict(getdns_context *context, char *ipstr)
{
	getdns_dict *r = getdns_dict_create_with_context(context);
	char *s = strchr(ipstr, '%'), *scope_id_str = "";
	char *p = strchr(ipstr, '@'), *portstr = "";
	char *t = strchr(ipstr, '#'), *tls_portstr = "";
	char *n = strchr(ipstr, '~'), *tls_namestr = "";
	/* ^[alg:]name:key */
	char *T = strchr(ipstr, '^'), *tsig_name_str = ""
	                            , *tsig_secret_str = ""
	                            , *tsig_algorithm_str = "";
	int            tsig_secret_size;
	uint8_t        tsig_secret_buf[256]; /* 4 times SHA512 */
	getdns_bindata tsig_secret;
	uint8_t buf[sizeof(struct in6_addr)];
	getdns_bindata addr;

	addr.data = buf;

	if (!r) return NULL;
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
	if (strchr(ipstr, ':')) {
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
		tsig_secret_size = gqldns_b64_pton(
		    tsig_secret_str, tsig_secret_buf, sizeof(tsig_secret_buf));
		if (tsig_secret_size > 0) {
			tsig_secret.size = tsig_secret_size;
			tsig_secret.data = tsig_secret_buf;
			getdns_dict_set_bindata(r, "tsig_secret", &tsig_secret);
		}
	}
	return r;
}

static getdns_return_t
fill_transport_list(getdns_context *context, char *transport_list_str, 
                    getdns_transport_list_t *transports, size_t *transport_count)
{
	size_t max_transports = *transport_count;
	*transport_count = 0;
	for ( size_t i = 0
	    ; i < max_transports && i < strlen(transport_list_str)
	    ; i++, (*transport_count)++) {
		switch(*(transport_list_str + i)) {
			case 'U': 
				transports[i] = GETDNS_TRANSPORT_UDP;
				break;
			case 'T': 
				transports[i] = GETDNS_TRANSPORT_TCP;
				break;
			case 'L': 
				transports[i] = GETDNS_TRANSPORT_TLS;
				break;
			default:
				fprintf(stderr, "Unrecognised transport '%c' in string %s\n", 
				       *(transport_list_str + i), transport_list_str);
				return GETDNS_RETURN_GENERIC_ERROR;
		}
	}
	return GETDNS_RETURN_GOOD;
}

void
print_usage(FILE *out, const char *progname)
{
	fprintf(out, "usage: %s [<option> ...] \\\n"
	    "\t\t[@<upstream> ...] [+<extension> ...] [<name>] [<type>]\n", progname);
	fprintf(out, "\ndefault mode: "
#ifdef HAVE_LIBUNBOUND
	    "recursive"
#else
	    "stub"
#endif
	    ", synchronous resolution of NS record using UDP with TCP fallback\n");
	fprintf(out, "\nupstreams: @<ip>[%%<scope_id>][@<port>][#<tls port>][~<tls name>][^<tsig spec>]\n");
	fprintf(out, "\ntsig spec: [<algorithm>:]<name>:<secret in Base64>\n");
	fprintf(out, "\nextensions:\n");
	fprintf(out, "\t+add_warning_for_bad_dns\n");
	fprintf(out, "\t+dnssec_return_status\n");
	fprintf(out, "\t+dnssec_return_only_secure\n");
	fprintf(out, "\t+dnssec_return_all_statuses\n");
	fprintf(out, "\t+dnssec_return_validation_chain\n");
	fprintf(out, "\t+dnssec_return_full_validation_chain\n");
#ifdef DNSSEC_ROADBLOCK_AVOIDANCE
	fprintf(out, "\t+dnssec_roadblock_avoidance\n");
#endif
#ifdef EDNS_COOKIES
	fprintf(out, "\t+edns_cookies\n");
#endif
	fprintf(out, "\t+return_both_v4_and_v6\n");
	fprintf(out, "\t+return_call_reporting\n");
	fprintf(out, "\t+sit=<cookie>\t\tSend along cookie OPT with value <cookie>\n");
	fprintf(out, "\t+specify_class=<class>\n");
	fprintf(out, "\t+0\t\t\tClear all extensions\n");
	fprintf(out, "\noptions:\n");
	fprintf(out, "\t-a\tPerform asynchronous resolution "
	    "(default = synchronous)\n");
	fprintf(out, "\t-A\taddress lookup (<type> is ignored)\n");
	fprintf(out, "\t-B\tBatch mode. Schedule all messages before processing responses.\n");
	fprintf(out, "\t-b <bufsize>\tSet edns0 max_udp_payload size\n");
	fprintf(out, "\t-c\tSend Client Subnet privacy request\n");
	fprintf(out, "\t-D\tSet edns0 do bit\n");
	fprintf(out, "\t-d\tclear edns0 do bit\n");
	fprintf(out, "\t-e <idle_timeout>\tSet idle timeout in miliseconds\n");
	fprintf(out, "\t-F <filename>\tread the queries from the specified file\n");
	fprintf(out, "\t-f <filename>\tRead DNSSEC trust anchors from <filename>\n");
	fprintf(out, "\t-G\tgeneral lookup\n");
	fprintf(out, "\t-H\thostname lookup. (<name> must be an IP address; <type> is ignored)\n");
	fprintf(out, "\t-h\tPrint this help\n");
	fprintf(out, "\t-i\tPrint api information\n");
	fprintf(out, "\t-I\tInteractive mode (> 1 queries on same context)\n");
	fprintf(out, "\t-j\tOutput json response dict\n");
	fprintf(out, "\t-J\tPretty print json response dict\n");
	fprintf(out, "\t-k\tPrint root trust anchors\n");
	fprintf(out, "\t-K <pin>\tPin a public key for TLS connections (can repeat)\n");
	fprintf(out, "\t\t(should look like '" EXAMPLE_PIN "')\n");
	fprintf(out, "\t-n\tSet TLS authentication mode to NONE (default)\n");
	fprintf(out, "\t-m\tSet TLS authentication mode to REQUIRED\n");
	fprintf(out, "\t-p\tPretty print response dict\n");
	fprintf(out, "\t-P <blocksize>\tPad TLS queries to a multiple of blocksize\n");
	fprintf(out, "\t-q\tQuiet mode - don't print response\n");
	fprintf(out, "\t-r\tSet recursing resolution type\n");
	fprintf(out, "\t-R <filename>\tRead root hints from <filename>\n");
	fprintf(out, "\t-s\tSet stub resolution type (default = recursing)\n");
	fprintf(out, "\t-S\tservice lookup (<type> is ignored)\n");
	fprintf(out, "\t-t <timeout>\tSet timeout in miliseconds\n");
	fprintf(out, "\t-x\tDo not follow redirects\n");
	fprintf(out, "\t-X\tFollow redirects (default)\n");

	fprintf(out, "\t-0\tAppend suffix to single label first (default)\n");
	fprintf(out, "\t-W\tAppend suffix always\n");
	fprintf(out, "\t-1\tAppend suffix only to single label after failure\n");
	fprintf(out, "\t-M\tAppend suffix only to multi label name after failure\n");
	fprintf(out, "\t-N\tNever append a suffix\n");
	fprintf(out, "\t-Z <suffixes>\tSet suffixes with the given comma separed list\n");

	fprintf(out, "\t-T\tSet transport to TCP only\n");
	fprintf(out, "\t-O\tSet transport to TCP only keep connections open\n");
	fprintf(out, "\t-L\tSet transport to TLS only keep connections open\n");
	fprintf(out, "\t-E\tSet transport to TLS with TCP fallback only keep connections open\n");
	fprintf(out, "\t-u\tSet transport to UDP with TCP fallback (default)\n");
	fprintf(out, "\t-U\tSet transport to UDP only\n");
	fprintf(out, "\t-l <transports>\tSet transport list. List can contain 1 of each of the characters\n");
	fprintf(out, "\t\t\t U T L S for UDP, TCP or TLS e.g 'UT' or 'LTU' \n");

}

static getdns_return_t validate_chain(getdns_dict *response)
{
	getdns_return_t r;
	getdns_list *validation_chain;
	getdns_list *replies_tree;
	getdns_dict *reply;
	getdns_list *to_validate;
	getdns_list *trust_anchor;
	size_t i;
	int s;
	
	if (!(to_validate = getdns_list_create()))
		return GETDNS_RETURN_MEMORY_ERROR;

	if (getdns_context_get_dnssec_trust_anchors(context, &trust_anchor))
		trust_anchor = getdns_root_trust_anchor(NULL);

	if ((r = getdns_dict_get_list(
	    response, "validation_chain", &validation_chain)))
		goto error;

	if ((r = getdns_dict_get_list(
	    response, "replies_tree", &replies_tree)))
		goto error;

	fprintf(stdout, "replies_tree dnssec_status: ");
	switch ((s = getdns_validate_dnssec(
	    replies_tree, validation_chain, trust_anchor))) {

	case GETDNS_DNSSEC_SECURE:
		fprintf(stdout, "GETDNS_DNSSEC_SECURE\n");
		break;
	case GETDNS_DNSSEC_BOGUS:
		fprintf(stdout, "GETDNS_DNSSEC_BOGUS\n");
		break;
	case GETDNS_DNSSEC_INDETERMINATE:
		fprintf(stdout, "GETDNS_DNSSEC_INDETERMINATE\n");
		break;
	case GETDNS_DNSSEC_INSECURE:
		fprintf(stdout, "GETDNS_DNSSEC_INSECURE\n");
		break;
	case GETDNS_DNSSEC_NOT_PERFORMED:
		fprintf(stdout, "GETDNS_DNSSEC_NOT_PERFORMED\n");
		break;
	default:
		fprintf(stdout, "%d\n", (int)s);
	}

	i = 0;
	while (!(r = getdns_list_get_dict(replies_tree, i++, &reply))) {

		if ((r = getdns_list_set_dict(to_validate, 0, reply)))
			goto error;

		printf("reply "PRIsz", dnssec_status: ", i);
		switch ((s = getdns_validate_dnssec(
		    to_validate, validation_chain, trust_anchor))) {

		case GETDNS_DNSSEC_SECURE:
			fprintf(stdout, "GETDNS_DNSSEC_SECURE\n");
			break;
		case GETDNS_DNSSEC_BOGUS:
			fprintf(stdout, "GETDNS_DNSSEC_BOGUS\n");
			break;
		case GETDNS_DNSSEC_INDETERMINATE:
			fprintf(stdout, "GETDNS_DNSSEC_INDETERMINATE\n");
			break;
		case GETDNS_DNSSEC_INSECURE:
			fprintf(stdout, "GETDNS_DNSSEC_INSECURE\n");
			break;
		case GETDNS_DNSSEC_NOT_PERFORMED:
			fprintf(stdout, "GETDNS_DNSSEC_NOT_PERFORMED\n");
			break;
		default:
			fprintf(stdout, "%d\n", (int)s);
		}
	}
	if (r == GETDNS_RETURN_NO_SUCH_LIST_ITEM)
		r = GETDNS_RETURN_GOOD;
error:
	getdns_list_destroy(trust_anchor);
	getdns_list_destroy(to_validate);

	return GETDNS_RETURN_GOOD;
}

void callback(getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *response, void *userarg, getdns_transaction_t trans_id)
{
	char *response_str;

	/* This is a callback with data */;
	if (response && !quiet && (response_str = json ?
	    getdns_print_json_dict(response, json == 1)
	  : getdns_pretty_print_dict(response))) {

		fprintf(stdout, "ASYNC response:\n%s\n", response_str);
		validate_chain(response);
		free(response_str);
	}

	if (callback_type == GETDNS_CALLBACK_COMPLETE) {
		printf("Response code was: GOOD. Status was: Callback with ID %"PRIu64"  was successfull.\n",
			trans_id);

	} else if (callback_type == GETDNS_CALLBACK_CANCEL)
		fprintf(stderr,
			"An error occurred: The callback with ID %"PRIu64" was cancelled. Exiting.\n",
			trans_id);
	else {
		fprintf(stderr,
			"An error occurred: The callback got a callback_type of %d. Exiting.\n",
			(int)callback_type);
		fprintf(stderr,
			"Error :      '%s'\n",
			getdns_get_errorstr_by_id(callback_type));
	}
	getdns_dict_destroy(response);
	response = NULL;
}

#define CONTINUE ((getdns_return_t)-2)
#define CONTINUE_ERROR ((getdns_return_t)-3)

static getdns_return_t set_cookie(getdns_dict *exts, char *cookie)
{
	uint8_t data[40];
	size_t i;
	getdns_return_t r = GETDNS_RETURN_GENERIC_ERROR;
	getdns_bindata bindata;

	getdns_dict *opt_parameters = getdns_dict_create();
	getdns_list *options = getdns_list_create();
	getdns_dict *option = getdns_dict_create();

	if (*cookie == '=')
		cookie++;

	for (i = 0; i < 40 && *cookie; i++) {
		if (*cookie >= '0' && *cookie <= '9')
			data[i] = (uint8_t)(*cookie - '0') << 4;
		else if (*cookie >= 'a' && *cookie <= 'f')
			data[i] = (uint8_t)(*cookie - 'a' + 10) << 4;
		else if (*cookie >= 'A' && *cookie <= 'F')
			data[i] = (uint8_t)(*cookie - 'A' + 10) << 4;
		else
			goto done;
		cookie++;
		if (*cookie >= '0' && *cookie <= '9')
			data[i] |= (uint8_t)(*cookie - '0');
		else if (*cookie >= 'a' && *cookie <= 'f')
			data[i] |= (uint8_t)(*cookie - 'a' + 10);
		else if (*cookie >= 'A' && *cookie <= 'F')
			data[i] |= (uint8_t)(*cookie - 'A' + 10);
		else
			goto done;
		cookie++;;
	}
	bindata.data = data;
	bindata.size = i;
	if ((r = getdns_dict_set_int(option, "option_code", 10)))
		goto done;
	if ((r = getdns_dict_set_bindata(option, "option_data", &bindata)))
		goto done;
	if ((r = getdns_list_set_dict(options, 0, option)))
		goto done;
	if ((r = getdns_dict_set_list(opt_parameters, "options", options)))
		goto done;
	r = getdns_dict_set_dict(exts, "add_opt_parameters", opt_parameters);
done:
	getdns_dict_destroy(option);
	getdns_list_destroy(options);
	getdns_dict_destroy(opt_parameters);
	return r;
}

static int _jsmn_get_dname(char *js, jsmntok_t *t, getdns_bindata **value)
{
	char c = js[t->end];
	getdns_return_t r;

	if (t->end <= t->start || js[t->end - 1] != '.')
		return 0;

	js[t->end] = '\0';
	r = getdns_convert_fqdn_to_dns_name(js + t->start, value);
	js[t->end] = c;

	return r == GETDNS_RETURN_GOOD;
}

static int _jsmn_get_ipv4(char *js, jsmntok_t *t, getdns_bindata **value)
{
	char c = js[t->end];
	uint8_t buf[4];

	js[t->end] = '\0';
	if (inet_pton(AF_INET, js + t->start, buf) <= 0)
		; /* pass */

	else if (!(*value = malloc(sizeof(getdns_bindata))))
		; /* pass */

	else if (!((*value)->data = malloc(4)))
		free(*value);

	else {
		js[t->end] = c;
		(*value)->size = 4;
		(void) memcpy((*value)->data, buf, 4);
		return 1;
	}
	js[t->end] = c;
	return 0;
}

static int _jsmn_get_ipv6(char *js, jsmntok_t *t, getdns_bindata **value)
{
	char c = js[t->end];
	uint8_t buf[16];

	js[t->end] = '\0';
	if (inet_pton(AF_INET6, js + t->start, buf) <= 0)
		; /* pass */

	else if (!(*value = malloc(sizeof(getdns_bindata))))
		; /* pass */

	else if (!((*value)->data = malloc(16)))
		free(*value);

	else {
		js[t->end] = c;
		(*value)->size = 16;
		(void) memcpy((*value)->data, buf, 16);
		return 1;
	}
	js[t->end] = c;
	return 0;
}

static int _jsmn_get_integer(char *js, jsmntok_t *t, uint32_t *num)
{
	char c = js[t->end];
	;unsigned long int value;
	char *endptr;

	js[t->end] = '\0';
	value = strtoul(js + t->start, &endptr, 10);
	if (js[t->start] != '\0' && *endptr == '\0') {
		js[t->end] = c;
		*num = value;
		return 1;
	}
	js[t->end] = c;
	return 0;
}

static int _jsmn_get_constant(char *js, jsmntok_t *t, uint32_t *num)
{
	char c = js[t->end];
	int code;

	js[t->end] = '\0';
	if (_getdns_get_const_name_info(js + t->start, &code)) {
		js[t->end] = c;
		*num = code;
		return 1;
	}
	js[t->end] = c;
	return 0;
}

static int _jsmn_get_dict(char *js, jsmntok_t *t, size_t count,
    getdns_dict **dict, getdns_return_t *r);

static int _jsmn_get_list(char *js, jsmntok_t *t, size_t count,
    getdns_list **list, getdns_return_t *r)
{
	getdns_list *new_list, *child_list;
	getdns_dict *child_dict;
	size_t i, j;
	getdns_bindata bindata;
	size_t index = 0;
	uint32_t num;
	getdns_bindata *value;

	if (t->type != JSMN_ARRAY) {
		*r = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
		return 0;
	}
	new_list = getdns_list_create();
	j = 1;
	for (i = 0; i < t->size; i++) {
		switch (t[j].type) {
		case JSMN_OBJECT:
			j += _jsmn_get_dict(js, t+j, count-j, &child_dict, r);
			if (*r) {
				getdns_list_destroy(new_list);
				return 0;
			}
			*r = getdns_list_set_dict(new_list, index++, child_dict);
			getdns_dict_destroy(child_dict);
			if (*r) {
				getdns_list_destroy(new_list);
				return 0;
			}
			break;
		case JSMN_ARRAY:
			j += _jsmn_get_list(js, t+j, count-j, &child_list, r);
			if (*r) {
				getdns_list_destroy(new_list);
				return 0;
			}
			*r = getdns_list_set_list(new_list, index++, child_list);
			getdns_list_destroy(child_list);
			if (*r) {
				getdns_list_destroy(new_list);
				return 0;
			}
			break;
		case JSMN_STRING:
			bindata.size = t[j].end - t[j].start;
			bindata.data = (uint8_t *)js + t[j].start;
			*r = getdns_list_set_bindata(
			    new_list, index++, &bindata);
			if (*r) {
				getdns_list_destroy(new_list);
				return 0;
			}
			j += 1;
			break;
		case JSMN_PRIMITIVE:
			if (_jsmn_get_integer(js, t+j, &num) ||
			    _jsmn_get_constant(js, t+j, &num)) {
				*r = getdns_list_set_int(
				    new_list, index++, num);
			} else if (_jsmn_get_dname(js, t+j, &value) ||
			    _jsmn_get_ipv4(js, t+j, &value) ||
			    _jsmn_get_ipv6(js, t+j, &value)) {

				*r = getdns_list_set_bindata(
				    new_list, index++, value);

				free(value->data);
				free(value);
			} else {
				fprintf(stderr, "Could not convert primitive %.*s\n",
				    t[j].end  - t[j].start, js+t[j].start);
				*r = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
			}
			if (*r) {
				getdns_list_destroy(new_list);
				return 0;
			}
			j += 1;
			break;

		default:
			*r = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
			getdns_list_destroy(new_list);
			return 0;
		}
	}
	*list = new_list;
	*r = GETDNS_RETURN_GOOD;
	return j;
}

static int _jsmn_get_dict(char *js, jsmntok_t *t, size_t count,
    getdns_dict **dict, getdns_return_t *r)
{
	getdns_dict *new_dict, *child_dict;
	getdns_list *child_list;
	size_t i, j;
	getdns_bindata bindata;
	char *key;
	uint32_t num;
	getdns_bindata *value;

	if (t->type != JSMN_OBJECT) {
		*r = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
		return 0;
	}
	new_dict = getdns_dict_create();
	j = 1;
	for (i = 0; i < t->size; i++) {
		if (t[j].type != JSMN_STRING) {
			*r = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
			getdns_dict_destroy(new_dict);
			return 0;
		}
		key = js + t[j].start;
		js[t[j].end] = '\0';
		j += 1;
		switch (t[j].type) {
		case JSMN_OBJECT:
			j += _jsmn_get_dict(js, t+j, count-j, &child_dict, r);
			if (*r) {
				getdns_dict_destroy(new_dict);
				return 0;
			}
			*r = getdns_dict_set_dict(new_dict, key, child_dict);
			getdns_dict_destroy(child_dict);
			if (*r) {
				getdns_dict_destroy(new_dict);
				return 0;
			}
			break;
		case JSMN_ARRAY:
			j += _jsmn_get_list(js, t+j, count-j, &child_list, r);
			if (*r) {
				getdns_dict_destroy(new_dict);
				return 0;
			}
			*r = getdns_dict_set_list(new_dict, key, child_list);
			getdns_list_destroy(child_list);
			if (*r) {
				getdns_dict_destroy(new_dict);
				return 0;
			}
			break;
		case JSMN_STRING:
			bindata.size = t[j].end - t[j].start;
			bindata.data = (uint8_t *)js + t[j].start;
			*r = getdns_dict_set_bindata(
			    new_dict, key, &bindata);
			if (*r) {
				getdns_dict_destroy(new_dict);
				return 0;
			}
			j += 1;
			break;
		case JSMN_PRIMITIVE:
			if (_jsmn_get_integer(js, t+j, &num) ||
			    _jsmn_get_constant(js, t+j, &num)) {
				*r = getdns_dict_set_int(
				    new_dict, key, num);
			} else if (_jsmn_get_dname(js, t+j, &value) ||
			    _jsmn_get_ipv4(js, t+j, &value) ||
			    _jsmn_get_ipv6(js, t+j, &value)) {

				*r = getdns_dict_set_bindata(
				    new_dict, key, value);

				free(value->data);
				free(value);
			} else {
				*r = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
				fprintf(stderr, "Could not convert primitive %.*s\n",
				    t[j].end  - t[j].start, js+t[j].start);
			}
			if (*r) {
				getdns_dict_destroy(new_dict);
				return 0;
			}
			j += 1;
			break;

		default:
			*r = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
			getdns_dict_destroy(new_dict);
			return 0;
		}
	}
	*dict = new_dict;
	*r = GETDNS_RETURN_GOOD;
	return j;
}

void parse_config(char *config)
{
	jsmn_parser p;
	jsmntok_t *tok = NULL, *new_tok;
	size_t tokcount = 100;
	int r;
	getdns_return_t gr;
	getdns_dict *d;

	jsmn_init(&p);
	tok = malloc(sizeof(*tok) * tokcount);
	do {
		r = jsmn_parse(&p, config, strlen(config), tok, tokcount);
		if (r == JSMN_ERROR_NOMEM) {
			fprintf(stderr, "new tokcount: %d\n", (int)tokcount);
			tokcount *= 2;
			if (!(new_tok = realloc(tok, sizeof(*tok)*tokcount))){
				free(tok);
				fprintf(stderr,
				    "Memory error during config parsing\n");
				return;
			} 
			tok  = new_tok;
		}
	} while (r == JSMN_ERROR_NOMEM);
	if (r < 0) 
		fprintf(stderr, "Config parse error: %d\n", r);
	else {
		(void) _jsmn_get_dict(config, tok, p.toknext, &d, &gr);
		if (gr)
			fprintf(stderr, "Config parse error: %d\n", (int)gr);
		else
			fprintf(stderr, "config dict: %s\n",
			    getdns_pretty_print_dict(d));
	}
	free(tok);
}

getdns_return_t parse_args(int argc, char **argv)
{
	getdns_return_t r = GETDNS_RETURN_GOOD;
	size_t i, j;
	char *arg, *c, *endptr;
	int t, print_api_info = 0, print_trust_anchors = 0;
	getdns_list *upstream_list = NULL;
	getdns_list *tas = NULL, *hints = NULL;
	getdns_dict *pubkey_pin = NULL;
	getdns_list *suffixes;
	char *suffix;
	getdns_bindata bindata;
	size_t upstream_count = 0;
	FILE *fh;
	uint32_t klass;
	char *config_file = NULL;
	long config_file_sz;

	for (i = 1; i < argc; i++) {
		arg = argv[i];
		if ((t = get_rrtype(arg)) >= 0) {
			request_type = t;
			continue;

		} else if (arg[0] == '+') {
			if (arg[1] == 's' && arg[2] == 'i' && arg[3] == 't' &&
			   (arg[4] == '=' || arg[4] == '\0')) {
				if ((r = set_cookie(extensions, arg+4))) {
					fprintf(stderr, "Could not set cookie:"
					    " %d", (int)r);
					break;
				}
			} else if (strncmp(arg+1, "specify_class=", 14) == 0) {
				if (strncasecmp(arg+15, "IN", 3) == 0)
					r = getdns_dict_set_int(extensions,
					    "specify_class", GETDNS_RRCLASS_IN);
				else if (strncasecmp(arg+15, "CH", 3) == 0)
					r = getdns_dict_set_int(extensions,
					    "specify_class", GETDNS_RRCLASS_CH);
				else if (strncasecmp(arg+15, "HS", 3) == 0)
					r = getdns_dict_set_int(extensions,
					    "specify_class", GETDNS_RRCLASS_HS);
				else if (strncasecmp(arg+15, "NONE", 5) == 0)
					r = getdns_dict_set_int(extensions,
					    "specify_class", GETDNS_RRCLASS_NONE);
				else if (strncasecmp(arg+15, "ANY", 4) == 0)
					r = getdns_dict_set_int(extensions,
					    "specify_class", GETDNS_RRCLASS_ANY);
				else if (strncasecmp(arg+15, "CLASS", 5) == 0) {
					klass = strtol(arg + 20, &endptr, 10);
					if (*endptr || klass > 255)
						fprintf(stderr,
						    "Unknown class: %s\n",
						    arg+15);
					else
						r = getdns_dict_set_int(extensions,
						    "specify_class", klass);

				} else
					fprintf(stderr,
					    "Unknown class: %s\n", arg+15);
			} else if (arg[1] == '0') {
			    /* Unset all existing extensions*/
				getdns_dict_destroy(extensions);
				extensions = getdns_dict_create();
				break;
			} else if ((r = getdns_dict_set_int(extensions, arg+1,
			    GETDNS_EXTENSION_TRUE))) {
				fprintf(stderr, "Could not set extension "
				    "\"%s\": %d\n", argv[i], (int)r);
				break;
			}
			continue;

		} else if (arg[0] == '@') {
			getdns_dict *upstream = ipaddr_dict(context, arg + 1);
			if (upstream) {
				if (!upstream_list &&
				    !(upstream_list =
				    getdns_list_create_with_context(context))){
					fprintf(stderr, "Could not create upstream list\n");
					return GETDNS_RETURN_MEMORY_ERROR;
				}
				getdns_list_set_dict(upstream_list,
				    upstream_count++, upstream);
			}
			continue;
		} else if (arg[0] == '~') {
			getdns_dict *ipaddr = ipaddr_dict(context, arg + 1);
			if (ipaddr) {
				if (!listen_list &&
				    !(listen_list =
				    getdns_list_create_with_context(context))){
					fprintf(stderr, "Could not create upstream list\n");
					return GETDNS_RETURN_MEMORY_ERROR;
				}
				getdns_list_set_dict(listen_list,
				    listen_count++, ipaddr);
			}
			continue;
		} else if (arg[0] != '-') {
			name = arg;
			continue;
		}
		for (c = arg+1; *c; c++) {
			switch (*c) {
			case 'a':
				async = 1;
				break;
			case 'A':
				calltype = ADDRESS;
				break;
			case 'b':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "max_udp_payload_size "
					    "expected after -b\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				edns0_size = strtol(argv[i], &endptr, 10);
				if (*endptr || edns0_size < 0) {
					fprintf(stderr, "positive "
					    "numeric max_udp_payload_size "
					    "expected after -b\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_context_set_edns_maximum_udp_payload_size(
				    context, (uint16_t) edns0_size);
				goto next;
			case 'c':
				if (getdns_context_set_edns_client_subnet_private(context, 1))
					return GETDNS_RETURN_GENERIC_ERROR;
				break;
			case 'C':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "file name expected "
					    "after -C\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (!(fh = fopen(argv[i], "r"))) {
					fprintf(stderr, "Could not open \"%s\""
					    ": %s\n",argv[i], strerror(errno));
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (fseek(fh, 0,SEEK_END) == -1) {
					perror("fseek");
					fclose(fh);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				config_file_sz = ftell(fh);
				if (config_file_sz <= 0) {
					/* Empty config is no config */
					fclose(fh);
					break;
				}
				if (!(config_file=malloc(config_file_sz + 1))){
					fclose(fh);
					fprintf(stderr, "Could not allocate me"
					    "mory for \"%s\"\n", argv[i]);
					return GETDNS_RETURN_MEMORY_ERROR;
				}
				rewind(fh);
				if (fread(config_file, 1, config_file_sz, fh)
				    != config_file_sz) {
					fprintf(stderr, "An error occurred whil"
					    "e reading \"%s\": %s\n",argv[i],
					    strerror(errno));
					fclose(fh);
					return GETDNS_RETURN_MEMORY_ERROR;
				}
				config_file[config_file_sz] = 0;
				fclose(fh);
				parse_config(config_file);
				free(config_file);
				config_file = NULL;
				break;
			case 'D':
				(void) getdns_context_set_edns_do_bit(context, 1);
				break;
			case 'd':
				(void) getdns_context_set_edns_do_bit(context, 0);
				break;
			case 'f':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "file name expected "
					    "after -f\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (!(fh = fopen(argv[i], "r"))) {
					fprintf(stderr, "Could not open \"%s\""
					    ": %s\n",argv[i], strerror(errno));
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (getdns_fp2rr_list(fh, &tas, NULL, 3600)) {
					fprintf(stderr,"Could not parse "
					    "\"%s\"\n", argv[i]);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				fclose(fh);
				if (getdns_context_set_dnssec_trust_anchors(
				    context, tas)) {
					fprintf(stderr,"Could not set "
					    "trust anchors from \"%s\"\n",
					    argv[i]);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_list_destroy(tas);
				tas = NULL;
				break;
			case 'F':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "file name expected "
					    "after -F\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				query_file = argv[i];
				interactive = 1;
				break;
			case 'G':
				calltype = GENERAL;
				break;
			case 'H':
				calltype = HOSTNAME;
				break;
			case 'h':
				print_usage(stdout, argv[0]);
				return CONTINUE;
			case 'i':
				print_api_info = 1;
				break;
			case 'I':
				interactive = 1;
				break;
			case 'j':
				json = 2;
				break;
			case 'J':
				json = 1;
				break;
			case 'K':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "pin string of the form "
						EXAMPLE_PIN
						"expected after -K\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				pubkey_pin = getdns_pubkey_pin_create_from_string(context,
										 argv[i]);
				if (pubkey_pin == NULL) {
					fprintf(stderr, "could not convert '%s' into a "
						"public key pin.\n"
						"Good pins look like: " EXAMPLE_PIN "\n"
						"Please see RFC 7469 for details about "
						"the format\n", argv[i]);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (pubkey_pinset == NULL)
					pubkey_pinset = getdns_list_create_with_context(context);
				if (r = getdns_list_set_dict(pubkey_pinset, pincount++,
							     pubkey_pin), r) {
					fprintf(stderr, "Failed to add pin to pinset (error %d: %s)\n",
						(int)r, getdns_get_errorstr_by_id(r));
					getdns_dict_destroy(pubkey_pin);
					pubkey_pin = NULL;
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_dict_destroy(pubkey_pin);
				pubkey_pin = NULL;
				break;
			case 'k':
				print_trust_anchors = 1;
				break;
			case 'n':
				getdns_context_set_tls_authentication(context,
				                 GETDNS_AUTHENTICATION_NONE);
				break;
			case 'm':
				getdns_context_set_tls_authentication(context,
				                 GETDNS_AUTHENTICATION_REQUIRED);
				break;
			case 'P':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "tls_query_padding_blocksize "
					    "expected after -P\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				padding_blocksize = strtol(argv[i], &endptr, 10);
				if (*endptr || padding_blocksize < 0) {
					fprintf(stderr, "non-negative "
					    "numeric padding blocksize expected "
					    "after -P\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (getdns_context_set_tls_query_padding_blocksize(
					    context, padding_blocksize))
					return GETDNS_RETURN_GENERIC_ERROR;
				goto next;
			case 'p':
				json = 0;
			case 'q':
				quiet = 1;
				break;
			case 'r':
				getdns_context_set_resolution_type(
				    context,
				    GETDNS_RESOLUTION_RECURSING);
				break;
			case 'R':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "file name expected "
					    "after -f\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (!(fh = fopen(argv[i], "r"))) {
					fprintf(stderr, "Could not open \"%s\""
					    ": %s\n",argv[i], strerror(errno));
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (getdns_fp2rr_list(fh, &hints, NULL, 3600)) {
					fprintf(stderr,"Could not parse "
					    "\"%s\"\n", argv[i]);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				fclose(fh);
				if (getdns_context_set_dns_root_servers(
				    context, hints)) {
					fprintf(stderr,"Could not set "
					    "root servers from \"%s\"\n",
					    argv[i]);
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_list_destroy(hints);
				hints = NULL;
				break;
			case 's':
				getdns_context_set_resolution_type(
				    context, GETDNS_RESOLUTION_STUB);
				break;
			case 'S':
				calltype = SERVICE;
				break;
			case 't':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "timeout expected "
					    "after -t\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				timeout = strtol(argv[i], &endptr, 10);
				if (*endptr || timeout < 0) {
					fprintf(stderr, "positive "
					    "numeric timeout expected "
					    "after -t\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_context_set_timeout(
					context, timeout);
				goto next;
			case 'x': 
				getdns_context_set_follow_redirects(
				    context, GETDNS_REDIRECTS_DO_NOT_FOLLOW);
				break;
			case 'X': 
				getdns_context_set_follow_redirects(
				    context, GETDNS_REDIRECTS_FOLLOW);
				break;
			case 'e':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "idle timeout expected "
					    "after -t\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				timeout = strtol(argv[i], &endptr, 10);
				if (*endptr || timeout < 0) {
					fprintf(stderr, "positive "
					    "numeric idle timeout expected "
					    "after -t\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_context_set_idle_timeout(
					context, timeout);
				goto next;
			case 'W':
				(void) getdns_context_set_append_name(context,
				    GETDNS_APPEND_NAME_ALWAYS);
				break;
			case '1':
				(void) getdns_context_set_append_name(context,
			GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE);
				break;
			case '0':
				(void) getdns_context_set_append_name(context,
				    GETDNS_APPEND_NAME_TO_SINGLE_LABEL_FIRST);
				break;
			case 'M':
				(void) getdns_context_set_append_name(context,
		GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE);
				break;
			case 'N':
				(void) getdns_context_set_append_name(context,
				    GETDNS_APPEND_NAME_NEVER);
				break;
			case 'Z':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "suffixes expected"
					    "after -Z\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				if (!(suffixes = getdns_list_create()))
					return GETDNS_RETURN_MEMORY_ERROR;
				suffix = strtok(argv[i], ",");
				j = 0;
				while (suffix) {
					bindata.size = strlen(suffix);
					bindata.data = (void *)suffix;
					(void) getdns_list_set_bindata(
					    suffixes, j++, &bindata);
					suffix = strtok(NULL, ",");
				}
				(void) getdns_context_set_suffix(context,
				    suffixes);
				getdns_list_destroy(suffixes);
				goto next;
			case 'T':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_TCP_ONLY);
				break;
			case 'O':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN);
				break;
			case 'L':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_TLS_ONLY_KEEP_CONNECTIONS_OPEN);
				break;
			case 'E':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_TLS_FIRST_AND_FALL_BACK_TO_TCP_KEEP_CONNECTIONS_OPEN);
				break;
			case 'u':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP);
				break;
			case 'U':
				getdns_context_set_dns_transport(context,
				    GETDNS_TRANSPORT_UDP_ONLY);
				break;
			case 'l':
				if (c[1] != 0 || ++i >= argc || !*argv[i]) {
					fprintf(stderr, "transport list expected "
					    "after -l\n");
					return GETDNS_RETURN_GENERIC_ERROR;
				}
				getdns_transport_list_t transports[10];
				size_t transport_count = sizeof(transports);
				if ((r = fill_transport_list(context, argv[i], transports, &transport_count)) ||
				    (r = getdns_context_set_dns_transport_list(context, 
				                                               transport_count, transports))){
						fprintf(stderr, "Could not set transports\n");
						return r;
				}
				break;
			case 'B':
				batch_mode = 1;
				break;


			default:
				fprintf(stderr, "Unknown option "
				    "\"%c\"\n", *c);
				for (i = 0; i < argc; i++)
					fprintf(stderr, "%d: \"%s\"\n", (int)i, argv[i]);
				return GETDNS_RETURN_GENERIC_ERROR;
			}
		}
next:		;
	}
	if (r)
		return r;
	if (pubkey_pinset && upstream_count) {
		getdns_dict *upstream;
		/* apply the accumulated pubkey pinset to all upstreams: */
		for (i = 0; i < upstream_count; i++) {
			if (r = getdns_list_get_dict(upstream_list, i, &upstream), r) {
				fprintf(stderr, "Failed to get upstream "PRIsz" when adding pinset\n", i);
				return r;
			}
			if (r = getdns_dict_set_list(upstream, "tls_pubkey_pinset", pubkey_pinset), r) {
				fprintf(stderr, "Failed to set pubkey pinset on upstream "PRIsz"\n", i);
				return r;
			}
		}
	}
	if (upstream_count &&
	    (r = getdns_context_set_upstream_recursive_servers(
	    context, upstream_list))) {
		fprintf(stderr, "Error setting upstream recursive servers\n");
	}
	if (print_api_info) {
		fprintf(stdout, "%s\n", getdns_pretty_print_dict(
		    getdns_context_get_api_information(context)));
		return CONTINUE;
	}
	if (print_trust_anchors) {
		if (!getdns_context_get_dnssec_trust_anchors(context, &tas)) {
		/* if ((tas = getdns_root_trust_anchor(NULL))) { */
			fprintf(stdout, "%s\n", getdns_pretty_print_list(tas));
			return CONTINUE;
		} else
			return CONTINUE_ERROR;
	}
	return r;
}

getdns_return_t do_the_call(void)
{
	getdns_return_t r;
	getdns_dict *address = NULL;
	getdns_dict *response = NULL;
	char *response_str;
	uint32_t status;

	if (calltype == HOSTNAME &&
	    !(address = ipaddr_dict(context, name))) {
		fprintf(stderr, "Could not convert \"%s\" "
				"to an IP address", name);
		return GETDNS_RETURN_GOOD;
	}
	if (async) {
		switch (calltype) {
		case GENERAL:
			r = getdns_general(context, name, request_type,
			    extensions, &response, NULL, callback);
			break;
		case ADDRESS:
			r = getdns_address(context, name,
			    extensions, &response, NULL, callback);
			break;
		case HOSTNAME:
			r = getdns_hostname(context, address,
			    extensions, &response, NULL, callback);
			break;
		case SERVICE:
			r = getdns_service(context, name,
			    extensions, &response, NULL, callback);
			break;
		default:
			r = GETDNS_RETURN_GENERIC_ERROR;
			break;
		}
		if (r == GETDNS_RETURN_GOOD && !batch_mode) 
			getdns_context_run(context);
		if (r != GETDNS_RETURN_GOOD)
			fprintf(stderr, "An error occurred: %d '%s'\n", (int)r,
				 getdns_get_errorstr_by_id(r));
	} else {
		switch (calltype) {
		case GENERAL:
			r = getdns_general_sync(context, name,
			    request_type, extensions, &response);
			break;
		case ADDRESS:
			r = getdns_address_sync(context, name,
			    extensions, &response);
			break;
		case HOSTNAME:
			r = getdns_hostname_sync(context, address,
			    extensions, &response);
			break;
		case SERVICE:
			r = getdns_service_sync(context, name,
			    extensions, &response);
			break;
		default:
			r = GETDNS_RETURN_GENERIC_ERROR;
			break;
		}
		if (r != GETDNS_RETURN_GOOD) {
			fprintf(stderr, "An error occurred: %d '%s'\n", (int)r,
				 getdns_get_errorstr_by_id(r));
			getdns_dict_destroy(address);
			return r;
		}
		if (response && !quiet) {
			if ((response_str = json ?
			    getdns_print_json_dict(response, json == 1)
			  : getdns_pretty_print_dict(response))) {

				fprintf( stdout, "SYNC response:\n%s\n"
				       , response_str);
				validate_chain(response);
				free(response_str);
			} else {
				r = GETDNS_RETURN_MEMORY_ERROR;
				fprintf( stderr
				       , "Could not print response\n");
			}
		}
		getdns_dict_get_int(response, "status", &status);
		fprintf(stdout, "Response code was: GOOD. Status was: %s\n", 
			 getdns_get_errorstr_by_id(status));
		if (response)
			getdns_dict_destroy(response);
	}
	getdns_dict_destroy(address);
	return r;
}

my_eventloop my_loop;
FILE *fp;

void read_line_cb(void *userarg)
{
	getdns_eventloop_event *read_line_ev = userarg;
	getdns_return_t r;

	char line[1024], *token, *linev[256];
	int linec;

	if (!fgets(line, 1024, fp) || !*line) {
		if (query_file)
			fprintf(stdout,"End of file.");
		my_eventloop_clear(&my_loop.base, read_line_ev);
		return;
	}
	if (query_file)
		fprintf(stdout,"Found query: %s", line);

	linev[0] = __FILE__;
	linec = 1;
	if (!(token = strtok(line, " \t\f\n\r"))) {
		if (! query_file) {
			printf("> ");
			fflush(stdout);
		}
		return;
	}
	if (*token == '#') {
		fprintf(stdout,"Result:      Skipping comment\n");
		if (! query_file) {
			printf("> ");
			fflush(stdout);
		}
		return;
	}
	do linev[linec++] = token;
	while (linec < 256 && (token = strtok(NULL, " \t\f\n\r")));

	if (((r = parse_args(linec, linev)) || (r = do_the_call())) &&
	    (r != CONTINUE && r != CONTINUE_ERROR))
		my_eventloop_clear(&my_loop.base, read_line_ev);

	else if (! query_file) {
		printf("> ");
		fflush(stdout);
	}
}

typedef struct listen_data {
	socklen_t                addr_len;
	struct sockaddr_storage  addr;
	int                      fd;
	getdns_transport_list_t  transport;
	getdns_eventloop_event   event;
} listen_data;


listen_data *listening = NULL;

typedef struct dns_msg {
	listen_data         *ld;
	getdns_dict         *query;
	getdns_transaction_t transaction_id;
} dns_msg;

typedef struct udp_msg {
	dns_msg                 super;
	struct sockaddr_storage remote_in;
	socklen_t               addrlen;
} udp_msg;

typedef struct tcp_to_write tcp_to_write;
struct tcp_to_write {
	size_t        write_buf_len;
	size_t        written;
	tcp_to_write *next;
	uint8_t       write_buf[];
};

#define DOWNSTREAM_IDLE_TIMEOUT 5000
typedef struct downstream {
	listen_data            *ld;
	struct sockaddr_storage remote_in;
	socklen_t               addrlen;
	int                     fd;
	getdns_eventloop_event  event;

	uint8_t                *read_buf;
	size_t                  read_buf_len;
	uint8_t                *read_pos;
	size_t                  to_read;

	tcp_to_write           *to_write;
	size_t                  to_answer;
} downstream;

typedef struct tcp_msg {
	dns_msg     super;
	downstream *conn;
} tcp_msg;

void downstream_destroy(downstream *conn)
{
	tcp_to_write *cur, *next;

	if (conn->event.read_cb||conn->event.write_cb||conn->event.timeout_cb)
		my_eventloop_clear(&my_loop.base, &conn->event);
	if (conn->fd >= 0) {
		if (close(conn->fd) == -1)
			perror("close");
	}
	free(conn->read_buf);
	for (cur = conn->to_write; cur; cur = next) {
		next = cur->next;
		free(cur);
	}
	free(conn);
}

void tcp_write_cb(void *userarg)
{
	downstream *conn = (downstream *)userarg;
	tcp_to_write *to_write;
	ssize_t written;

	assert(userarg);

	/* Reset downstream idle timeout */
	my_eventloop_clear(&my_loop.base, &conn->event);
	
	if (!conn->to_write) {
		conn->event.write_cb = NULL;
		(void) my_eventloop_schedule(&my_loop.base, conn->fd,
		    DOWNSTREAM_IDLE_TIMEOUT, &conn->event);
		return;
	}
	to_write = conn->to_write;
	if ((written = write(conn->fd, &to_write->write_buf[to_write->written],
	    to_write->write_buf_len - to_write->written)) == -1) {

		perror("write");
		conn->event.read_cb = conn->event.write_cb =
		    conn->event.timeout_cb = NULL;
		downstream_destroy(conn);
		return;
	}
	to_write->written += written;
	if (to_write->written == to_write->write_buf_len) {
		conn->to_write = to_write->next;
		free(to_write);
	}
	if (!conn->to_write)
		conn->event.write_cb = NULL;
	(void) my_eventloop_schedule(&my_loop.base, conn->fd,
	    DOWNSTREAM_IDLE_TIMEOUT, &conn->event);
}

void request_cb(getdns_context *context, getdns_callback_type_t callback_type,
    getdns_dict *response, void *userarg, getdns_transaction_t transaction_id)
{
	dns_msg *msg = (dns_msg *)userarg;
	uint32_t qid;
	getdns_return_t r;
	uint8_t buf[65536];
	size_t len = sizeof(buf);

	if (callback_type != GETDNS_CALLBACK_COMPLETE) {
		if (response)
			getdns_dict_destroy(response);
		return;
	}
	if ((r = getdns_dict_get_int(msg->query, "/header/id", &qid)))
		fprintf(stderr, "Could not get qid: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if (!response)
		fprintf(stderr, "No response in request_cb\n");

	else if ((r = getdns_dict_set_int(response,
	    "/replies_tree/0/header/id", qid)))
		fprintf(stderr, "Could not set qid: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r = getdns_msg_dict2wire_buf(response, buf, &len)))
		fprintf(stderr, "Could not convert reply: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if (msg->ld->transport == GETDNS_TRANSPORT_UDP) {
		udp_msg *msg = (udp_msg *)userarg;

		if (sendto(msg->super.ld->fd, buf, len, 0,
		    (struct sockaddr *)&msg->remote_in, msg->addrlen) == -1)
			perror("sendto");

	} else if (msg->ld->transport == GETDNS_TRANSPORT_TCP) {
		tcp_msg *msg = (tcp_msg *)userarg;
		tcp_to_write **to_write_p;
		tcp_to_write *to_write = malloc(sizeof(tcp_to_write) + len + 2);

		if (!to_write) 
			fprintf(stderr, "Could not allocate memory for"
					"message to write on tcp stream\n");
		else {
			to_write->write_buf_len = len + 2;
			to_write->write_buf[0] = (len >> 8) & 0xFF;
			to_write->write_buf[1] = len & 0xFF;
			to_write->written = 0;
			to_write->next = NULL;
			(void) memcpy(to_write->write_buf + 2, buf, len);

			/* Appen to_write to conn->to_write list */
			for ( to_write_p = &msg->conn->to_write
			    ; *to_write_p
			    ; to_write_p = &(*to_write_p)->next)
				; /* pass */
			*to_write_p = to_write;

			my_eventloop_clear(&my_loop.base, &msg->conn->event);
			msg->conn->event.write_cb = tcp_write_cb;
			(void) my_eventloop_schedule(&my_loop.base,
			    msg->conn->fd, DOWNSTREAM_IDLE_TIMEOUT,
			    &msg->conn->event);
		}
	}
	if (msg) {
		getdns_dict_destroy(msg->query);
		free(msg);
	}
	if (response)
		getdns_dict_destroy(response);
}	

getdns_return_t schedule_request(dns_msg *msg)
{
	getdns_bindata *qname;
	char *qname_str = NULL;
	uint32_t qtype;
	getdns_return_t r;

	if ((r = getdns_dict_get_bindata(msg->query,"/question/qname",&qname)))
		fprintf(stderr, "Could not get qname from query: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r = getdns_convert_dns_name_to_fqdn(qname, &qname_str)))
		fprintf(stderr, "Could not convert qname: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r=getdns_dict_get_int(msg->query,"/question/qtype",&qtype)))
		fprintf(stderr, "Could get qtype from query: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r = getdns_general(context, qname_str, qtype,
	    extensions, msg, &msg->transaction_id, request_cb)))
		fprintf(stderr, "Could not schedule query: %s\n",
		    getdns_get_errorstr_by_id(r));

	return r;
}

void tcp_read_cb(void *userarg)
{
	downstream *conn = (downstream *)userarg;
	ssize_t bytes_read;
	tcp_msg *msg;
	getdns_return_t r;

	assert(userarg);

	/* Reset downstream idle timeout */
	my_eventloop_clear(&my_loop.base, &conn->event);
	(void) my_eventloop_schedule(&my_loop.base, conn->fd,
	    DOWNSTREAM_IDLE_TIMEOUT, &conn->event);

	if ((bytes_read = read(conn->fd, conn->read_pos, conn->to_read)) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		perror("read");
		downstream_destroy(conn);
		return;
	}
	if (bytes_read == 0) {
		/* fprintf(stderr, "Remote end closed connection\n"); */
		downstream_destroy(conn);
		return;
	}
	assert(bytes_read <= conn->to_read);

	conn->to_read  -= bytes_read;
	conn->read_pos += bytes_read;
	if (conn->to_read)
		return; /* More to read */

	if (conn->read_pos - conn->read_buf == 2) {
		/* read length of dns msg to read */
		conn->to_read = (conn->read_buf[0] << 8) | conn->read_buf[1];
		if (conn->to_read > conn->read_buf_len) {
			free(conn->read_buf);
			while (conn->to_read > conn->read_buf_len)
				conn->read_buf_len *= 2;
			if (!(conn->read_buf = malloc(conn->read_buf_len))) {
				fprintf(stderr, "Could not enlarge "
				                "downstream read buffer\n");
				downstream_destroy(conn);
				return;
			}
		}
		if (conn->to_read < 12) {
			fprintf(stderr, "Request smaller than DNS header\n");
			downstream_destroy(conn);
			return;
		}
		conn->read_pos = conn->read_buf;
		return;  /* Read DNS message */
	}
	if (!(msg = malloc(sizeof(tcp_msg)))) {
		fprintf(stderr, "Could not allocate tcp_msg\n");
		downstream_destroy(conn);
		return;
	}
	msg->super.ld = conn->ld;
	msg->conn = conn;
	if ((r = getdns_wire2msg_dict(conn->read_buf,
	    (conn->read_pos - conn->read_buf), &msg->super.query)))
		fprintf(stderr, "Error converting query dns msg: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r = schedule_request(&msg->super))) {
		fprintf(stderr, "Error scheduling query: %s\n",
		    getdns_get_errorstr_by_id(r));

		getdns_dict_destroy(msg->super.query);
	} else {
		conn->to_answer += 1;
		conn->read_pos = conn->read_buf;
		conn->to_read = 2;
		return; /* Read more requests */
	}
	free(msg);
	conn->read_pos = conn->read_buf;
	conn->to_read = 2;
	 /* Read more requests */
}

void tcp_timeout_cb(void *userarg)
{
	downstream *conn = (downstream *)userarg;

	assert(userarg);

	downstream_destroy(conn);
}

void tcp_accept_cb(void *userarg)
{
	listen_data *ld = (listen_data *)userarg;
	downstream *conn;

	assert(userarg);

	if (!(conn = malloc(sizeof(downstream))))
		return;

	(void) memset(conn, 0, sizeof(downstream));

	conn->ld = ld;
	conn->addrlen = sizeof(conn->remote_in);
	if ((conn->fd = accept(ld->fd,
	    (struct sockaddr *)&conn->remote_in, &conn->addrlen)) == -1) {
		perror("accept");
		free(conn);
	}
	if (!(conn->read_buf = malloc(4096))) {
		fprintf(stderr, "Could not allocate downstream read buffer.\n");
		free(conn);
	}
	conn->read_buf_len = 4096;
	conn->read_pos = conn->read_buf;
	conn->to_read = 2;
	conn->event.userarg = conn;
	conn->event.read_cb = tcp_read_cb;
	conn->event.timeout_cb = tcp_timeout_cb;
	(void) my_eventloop_schedule(&my_loop.base, conn->fd,
	    DOWNSTREAM_IDLE_TIMEOUT, &conn->event);
}

void udp_read_cb(void *userarg)
{
	listen_data *ld = (listen_data *)userarg;
	udp_msg *msg;
	uint8_t buf[65536];
	ssize_t len;
	getdns_return_t r;
	
	assert(userarg);

	if (!(msg = malloc(sizeof(udp_msg))))
		return;

	msg->super.ld = ld;
	msg->addrlen = sizeof(msg->remote_in);
	if ((len = recvfrom(ld->fd, buf, sizeof(buf), 0,
	    (struct sockaddr *)&msg->remote_in, &msg->addrlen)) == -1)
		perror("recvfrom");

	else if ((r = getdns_wire2msg_dict(buf, len, &msg->super.query)))
		fprintf(stderr, "Error converting query dns msg: %s\n",
		    getdns_get_errorstr_by_id(r));

	else if ((r = schedule_request(&msg->super))) {
		fprintf(stderr, "Error scheduling query: %s\n",
		    getdns_get_errorstr_by_id(r));

		getdns_dict_destroy(msg->super.query);
	} else
		return;
	free(msg);
}

getdns_return_t start_daemon()
{
	static const getdns_transport_list_t listen_transports[]
		= { GETDNS_TRANSPORT_UDP, GETDNS_TRANSPORT_TCP };
	static const uint32_t transport_ports[] = { 53, 53 };
	static const size_t n_transports = sizeof( listen_transports)
	                                 / sizeof(*listen_transports);

	size_t i;
	size_t t;
	struct addrinfo hints;
	getdns_return_t r = GETDNS_RETURN_GOOD;
	char addrstr[1024], portstr[1024], *eos;

	if (!listen_count)
		return GETDNS_RETURN_GOOD;

	if (!(listening = malloc(
	    sizeof(listen_data) * n_transports * listen_count)))
		return GETDNS_RETURN_MEMORY_ERROR;

	(void) memset(listening, 0,
	    sizeof(listen_data) * n_transports * listen_count);
	(void) memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_UNSPEC;
	hints.ai_flags     = AI_NUMERICHOST;

	for (i = 0; !r && i < listen_count; i++) {
		getdns_dict    *dict;
		getdns_bindata *address_data;
		struct sockaddr_storage  addr;
		getdns_bindata  *scope_id;

		if ((r = getdns_list_get_dict(listen_list, i, &dict)))
			break;
		if ((r = getdns_dict_get_bindata(
		    dict, "address_data", &address_data)))
			break;
		if (address_data->size == 4)
			addr.ss_family = AF_INET;
		else if (address_data->size == 16)
			addr.ss_family = AF_INET6;
		else {
			r = GETDNS_RETURN_INVALID_PARAMETER;
			break;
		}
		if (inet_ntop(addr.ss_family,
		    address_data->data, addrstr, 1024) == NULL) {
			r = GETDNS_RETURN_INVALID_PARAMETER;
			break;
		}
		if (dict && getdns_dict_get_bindata(dict,"scope_id",&scope_id)
		    == GETDNS_RETURN_GOOD) {
			if (strlen(addrstr) + scope_id->size > 1022) {
				r = GETDNS_RETURN_INVALID_PARAMETER;
				break;
			}
			eos = &addrstr[strlen(addrstr)];
			*eos++ = '%';
			(void) memcpy(eos, scope_id->data, scope_id->size);
			eos[scope_id->size] = 0;
		}
		for (t = 0; !r && t < n_transports; t++) {
			getdns_transport_list_t transport
			    = listen_transports[t];
			uint32_t port = transport_ports[t];
			struct addrinfo *ai;
			listen_data *ld = &listening[i * n_transports + t];

			ld->fd = -1;
			(void) getdns_dict_get_int(dict,
			    ( transport == GETDNS_TRANSPORT_TLS
			    ? "tls_port" : "port" ), &port);

			(void) snprintf(portstr, 1024, "%d", (int)port);

			if (getaddrinfo(addrstr, portstr, &hints, &ai)) {
				r = GETDNS_RETURN_INVALID_PARAMETER;
				break;
			}
			if (!ai)
				continue;

			ld->addr.ss_family = addr.ss_family;
			ld->addr_len = ai->ai_addrlen;
			(void) memcpy(&ld->addr, ai->ai_addr, ai->ai_addrlen);
			ld->transport = transport;
			freeaddrinfo(ai);
		}

	}
	if (r) {
		free(listening);
		listening = NULL;
	} else for (i = 0; !r && i < listen_count * n_transports; i++) {
		listen_data *ld = &listening[i];

		if (ld->transport != GETDNS_TRANSPORT_UDP &&
		    ld->transport != GETDNS_TRANSPORT_TCP)
			continue;

		if ((ld->fd = socket(ld->addr.ss_family,
		    ( ld->transport == GETDNS_TRANSPORT_UDP
		    ? SOCK_DGRAM : SOCK_STREAM), 0)) == -1)
			perror("socket");

		else if (bind(ld->fd, (struct sockaddr *)&ld->addr,
		    ld->addr_len) == -1)
			perror("bind");

		else if (ld->transport == GETDNS_TRANSPORT_UDP) {
			ld->event.userarg = ld;
			ld->event.read_cb = udp_read_cb;
			(void) my_eventloop_schedule(
			    &my_loop.base, ld->fd, -1, &ld->event);

		} else if (listen(ld->fd, 16) == -1)
			perror("listen");

		else {
			ld->event.userarg = ld;
			ld->event.read_cb = tcp_accept_cb;
			(void) my_eventloop_schedule(
			    &my_loop.base, ld->fd, -1, &ld->event);
		}
	}
	return r;
}

int
main(int argc, char **argv)
{
	getdns_return_t r;

	name = the_root;
	if ((r = getdns_context_create(&context, 1))) {
		fprintf(stderr, "Create context failed: %d\n", (int)r);
		return r;
	}
	my_eventloop_init(&my_loop);
	if ((r = getdns_context_set_use_threads(context, 1)))
		goto done_destroy_context;
	extensions = getdns_dict_create();
	if (! extensions) {
		fprintf(stderr, "Could not create extensions dict\n");
		r = GETDNS_RETURN_MEMORY_ERROR;
		goto done_destroy_context;
	}
	if ((r = parse_args(argc, argv)))
		goto done_destroy_context;

	if (query_file) {
		fp = fopen(query_file, "rt");
		if (fp == NULL) {
			fprintf(stderr, "Could not open query file: %s\n", query_file);
			goto done_destroy_context;
		}
	} else
		fp = stdin;

	if (listen_count || interactive) {
		if ((r = getdns_context_set_eventloop(context, &my_loop.base)))
			goto done_destroy_context;
	}
	start_daemon();
	/* Make the call */
	if (interactive) {

		getdns_eventloop_event read_line_ev = {
		    &read_line_ev, read_line_cb, NULL, NULL, NULL };
		(void) my_eventloop_schedule(
		    &my_loop.base, fileno(fp), -1, &read_line_ev);

		if (!query_file) {
			printf("> ");
			fflush(stdout);
		}
		my_eventloop_run(&my_loop.base);
	}
	else if (listen_count)
		my_eventloop_run(&my_loop.base);
	else
		r = do_the_call();

	if ((r == GETDNS_RETURN_GOOD && batch_mode))
		getdns_context_run(context);

	/* Clean up */
	getdns_dict_destroy(extensions);
done_destroy_context:
	getdns_context_destroy(context);

	if (fp)
		fclose(fp);

	if (r == CONTINUE)
		return 0;
	else if (r == CONTINUE_ERROR)
		return 1;
	fprintf(stdout, "\nAll done.\n");
	return r;
}

int get_rrtype(const char *t) {
	char *endptr;
	int r;

	switch (t[0]) {
	case 'A':
	case 'a': switch (t[1]) {
	          case '\0': return GETDNS_RRTYPE_A;
	          case '6': if (t[2] == '\0') return GETDNS_RRTYPE_A6;
                            return -1;
	          case 'A':
	          case 'a': /* before "AA", final "AA" (GETDNS_RRTYPE_AAAA) */
	                    if ((t[2]|0x20) == 'a' && (t[3]|0x20) == 'a' && t[4] == '\0')
	                              return GETDNS_RRTYPE_AAAA;
	                    return -1;
	          case 'F':
	          case 'f': /* before "AF", final "SDB" (GETDNS_RRTYPE_AFSDB) */
	                    if ((t[2]|0x20) == 's' && (t[3]|0x20) == 'd' && (t[4]|0x20) == 'b' && t[5] == '\0')
	                              return GETDNS_RRTYPE_AFSDB;
	                    return -1;
	          case 'P':
	          case 'p': /* before "AP", final "L" (GETDNS_RRTYPE_APL) */
	                    if ((t[2]|0x20) == 'l' && t[3] == '\0')
	                              return GETDNS_RRTYPE_APL;
	                    return -1;
	          case 'T':
	          case 't': /* before "AT", final "MA" (GETDNS_RRTYPE_ATMA) */
	                    if ((t[2]|0x20) == 'm' && (t[3]|0x20) == 'a' && t[4] == '\0')
	                              return GETDNS_RRTYPE_ATMA;
	                    return -1;
	          case 'X':
	          case 'x': /* before "AX", final "FR" (GETDNS_RRTYPE_AXFR) */
	                    if ((t[2]|0x20) == 'f' && (t[3]|0x20) == 'r' && t[4] == '\0')
	                              return GETDNS_RRTYPE_AXFR;
	                    return -1;
	          default : return -1;
	          };
	case 'C':
	case 'c': switch (t[1]) {
	          case 'A':
	          case 'a': /* before "CA", final "A" (GETDNS_RRTYPE_CAA) */
	                    if ((t[2]|0x20) == 'a' && t[3] == '\0')
	                              return GETDNS_RRTYPE_CAA;
	                    return -1;
	          case 'D':
	          case 'd': switch (t[2]) {
	                    case 'N':
	                    case 'n': /* before "CDN", final "SKEY" (GETDNS_RRTYPE_CDNSKEY) */
	                              if ((t[3]|0x20) == 's' && (t[4]|0x20) == 'k' && (t[5]|0x20) == 'e' && (t[6]|0x20) == 'y' && t[7] == '\0')
	                                        return GETDNS_RRTYPE_CDNSKEY;
	                              return -1;
	                    case 'S':
	                    case 's': if (t[3] == '\0') return GETDNS_RRTYPE_CDS;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'E':
	          case 'e': /* before "CE", final "RT" (GETDNS_RRTYPE_CERT) */
	                    if ((t[2]|0x20) == 'r' && (t[3]|0x20) == 't' && t[4] == '\0')
	                              return GETDNS_RRTYPE_CERT;
	                    return -1;
	          case 'N':
	          case 'n': /* before "CN", final "AME" (GETDNS_RRTYPE_CNAME) */
	                    if ((t[2]|0x20) == 'a' && (t[3]|0x20) == 'm' && (t[4]|0x20) == 'e' && t[5] == '\0')
	                              return GETDNS_RRTYPE_CNAME;
	                    return -1;
	          case 'S':
	          case 's': /* before "CS", final "YNC" (GETDNS_RRTYPE_CSYNC) */
	                    if ((t[2]|0x20) == 'y' && (t[3]|0x20) == 'n' && (t[4]|0x20) == 'c' && t[5] == '\0')
	                              return GETDNS_RRTYPE_CSYNC;
	                    return -1;

	          default : return -1;
	          };
	case 'D':
	case 'd': switch (t[1]) {
	          case 'H':
	          case 'h': /* before "DH", final "CID" (GETDNS_RRTYPE_DHCID) */
	                    if ((t[2]|0x20) == 'c' && (t[3]|0x20) == 'i' && (t[4]|0x20) == 'd' && t[5] == '\0')
	                              return GETDNS_RRTYPE_DHCID;
	                    return -1;
	          case 'L':
	          case 'l': /* before "DL", final "V" (GETDNS_RRTYPE_DLV) */
	                    if ((t[2]|0x20) == 'v' && t[3] == '\0')
	                              return GETDNS_RRTYPE_DLV;
	                    return -1;
	          case 'N':
	          case 'n': switch (t[2]) {
	                    case 'A':
	                    case 'a': /* before "DNA", final "ME" (GETDNS_RRTYPE_DNAME) */
	                              if ((t[3]|0x20) == 'm' && (t[4]|0x20) == 'e' && t[5] == '\0')
	                                        return GETDNS_RRTYPE_DNAME;
	                              return -1;
	                    case 'S':
	                    case 's': /* before "DNS", final "KEY" (GETDNS_RRTYPE_DNSKEY) */
	                              if ((t[3]|0x20) == 'k' && (t[4]|0x20) == 'e' && (t[5]|0x20) == 'y' && t[6] == '\0')
	                                        return GETDNS_RRTYPE_DNSKEY;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'S':
	          case 's': if (t[2] == '\0') return GETDNS_RRTYPE_DS;
	                    return -1;
	          default : return -1;
	          };
	case 'E':
	case 'e': switch (t[1]) {
	          case 'I':
	          case 'i': /* before "EI", final "D" (GETDNS_RRTYPE_EID) */
	                    if ((t[2]|0x20) == 'd' && t[3] == '\0')
	                              return GETDNS_RRTYPE_EID;
	                    return -1;
	          case 'U':
	          case 'u': /* before "EU", next "I" */
	                    if ((t[2]|0x20) != 'i')
	                              return -1;
	                    switch (t[3]) {
	                    case '4': /* before "EUI4", final "8" (GETDNS_RRTYPE_EUI48) */
	                              if (t[4] == '8' && t[5] == '\0')
	                                        return GETDNS_RRTYPE_EUI48;
	                              return -1;
	                    case '6': /* before "EUI6", final "4" (GETDNS_RRTYPE_EUI64) */
	                              if (t[4] == '4' && t[5] == '\0')
	                                        return GETDNS_RRTYPE_EUI64;
	                              return -1;
	                    default : return -1;
	                    };
	          default : return -1;
	          };
	case 'G':
	case 'g': switch (t[1]) {
	          case 'I':
	          case 'i': /* before "GI", final "D" (GETDNS_RRTYPE_GID) */
	                    if ((t[2]|0x20) == 'd' && t[3] == '\0')
	                              return GETDNS_RRTYPE_GID;
	                    return -1;
	          case 'P':
	          case 'p': /* before "GP", final "OS" (GETDNS_RRTYPE_GPOS) */
	                    if ((t[2]|0x20) == 'o' && (t[3]|0x20) == 's' && t[4] == '\0')
	                              return GETDNS_RRTYPE_GPOS;
	                    return -1;
	          default : return -1;
	          };
	case 'H':
	case 'h': /* before "H", next "I" */
	          if ((t[1]|0x20) != 'i')
	                    return -1;
	          switch (t[2]) {
	          case 'N':
	          case 'n': /* before "HIN", final "FO" (GETDNS_RRTYPE_HINFO) */
	                    if ((t[3]|0x20) == 'f' && (t[4]|0x20) == 'o' && t[5] == '\0')
	                              return GETDNS_RRTYPE_HINFO;
	                    return -1;
	          case 'P':
	          case 'p': if (t[3] == '\0') return GETDNS_RRTYPE_HIP;
	                    return -1;
	          default : return -1;
	          };
	case 'I':
	case 'i': switch (t[1]) {
	          case 'P':
	          case 'p': /* before "IP", final "SECKEY" (GETDNS_RRTYPE_IPSECKEY) */
	                    if ((t[2]|0x20) == 's' && (t[3]|0x20) == 'e' && (t[4]|0x20) == 'c' && (t[5]|0x20) == 'k' && (t[6]|0x20) == 'e' && (t[7]|0x20) == 'y' && t[8] == '\0')
	                              return GETDNS_RRTYPE_IPSECKEY;
	                    return -1;
	          case 'S':
	          case 's': /* before "IS", final "DN" (GETDNS_RRTYPE_ISDN) */
	                    if ((t[2]|0x20) == 'd' && (t[3]|0x20) == 'n' && t[4] == '\0')
	                              return GETDNS_RRTYPE_ISDN;
	                    return -1;
	          case 'X':
	          case 'x': /* before "IX", final "FR" (GETDNS_RRTYPE_IXFR) */
	                    if ((t[2]|0x20) == 'f' && (t[3]|0x20) == 'r' && t[4] == '\0')
	                              return GETDNS_RRTYPE_IXFR;
	                    return -1;
	          default : return -1;
	          };
	case 'K':
	case 'k': switch (t[1]) {
	          case 'E':
	          case 'e': /* before "KE", final "Y" (GETDNS_RRTYPE_KEY) */
	                    if ((t[2]|0x20) == 'y' && t[3] == '\0')
	                              return GETDNS_RRTYPE_KEY;
	                    return -1;
	          case 'X':
	          case 'x': if (t[2] == '\0') return GETDNS_RRTYPE_KX;
	                    return -1;
	          default : return -1;
	          };
	case 'L':
	case 'l': switch (t[1]) {
	          case '3': /* before "L3", final "2" (GETDNS_RRTYPE_L32) */
	                    if (t[2] == '2' && t[3] == '\0')
	                              return GETDNS_RRTYPE_L32;
	                    return -1;
	          case '6': /* before "L6", final "4" (GETDNS_RRTYPE_L64) */
	                    if (t[2] == '4' && t[3] == '\0')
	                              return GETDNS_RRTYPE_L64;
	                    return -1;
	          case 'O':
	          case 'o': /* before "LO", final "C" (GETDNS_RRTYPE_LOC) */
	                    if ((t[2]|0x20) == 'c' && t[3] == '\0')
	                              return GETDNS_RRTYPE_LOC;
	                    return -1;
	          case 'P':
	          case 'p': if (t[2] == '\0') return GETDNS_RRTYPE_LP;
	                    return -1;
	          default : return -1;
	          };
	case 'M':
	case 'm': switch (t[1]) {
	          case 'A':
	          case 'a': /* before "MA", next "IL" */
	                    if ((t[2]|0x20) != 'i' && (t[3]|0x20) != 'l')
	                              return -1;
	                    switch (t[4]) {
	                    case 'A':
	                    case 'a': if (t[5] == '\0') return GETDNS_RRTYPE_MAILA;
	                              return -1;
	                    case 'B':
	                    case 'b': if (t[5] == '\0') return GETDNS_RRTYPE_MAILB;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'B':
	          case 'b': if (t[2] == '\0') return GETDNS_RRTYPE_MB;
                            return -1;
	          case 'D':
	          case 'd': if (t[2] == '\0') return GETDNS_RRTYPE_MD;
                            return -1;
	          case 'F':
	          case 'f': if (t[2] == '\0') return GETDNS_RRTYPE_MF;
                            return -1;
	          case 'G':
	          case 'g': if (t[2] == '\0') return GETDNS_RRTYPE_MG;
                            return -1;
	          case 'I':
	          case 'i': /* before "MI", final "NFO" (GETDNS_RRTYPE_MINFO) */
	                    if ((t[2]|0x20) == 'n' && (t[3]|0x20) == 'f' && (t[4]|0x20) == 'o' && t[5] == '\0')
	                              return GETDNS_RRTYPE_MINFO;
	                    return -1;
	          case 'R':
	          case 'r': if (t[2] == '\0') return GETDNS_RRTYPE_MR;
	                    return -1;
	          case 'X':
	          case 'x': if (t[2] == '\0') return GETDNS_RRTYPE_MX;
	                    return -1;
	          default : return -1;
	          };
	case 'N':
	case 'n': switch (t[1]) {
	          case 'A':
	          case 'a': /* before "NA", final "PTR" (GETDNS_RRTYPE_NAPTR) */
	                    if ((t[2]|0x20) == 'p' && (t[3]|0x20) == 't' && (t[4]|0x20) == 'r' && t[5] == '\0')
	                              return GETDNS_RRTYPE_NAPTR;
	                    return -1;
	          case 'I':
	          case 'i': switch (t[2]) {
	                    case 'D':
	                    case 'd': if (t[3] == '\0') return GETDNS_RRTYPE_NID;
	                              return -1;
	                    case 'M':
	                    case 'm': /* before "NIM", final "LOC" (GETDNS_RRTYPE_NIMLOC) */
	                              if ((t[3]|0x20) == 'l' && (t[4]|0x20) == 'o' && (t[5]|0x20) == 'c' && t[6] == '\0')
	                                        return GETDNS_RRTYPE_NIMLOC;
	                              return -1;
	                    case 'N':
	                    case 'n': /* before "NIN", final "FO" (GETDNS_RRTYPE_NINFO) */
	                              if ((t[3]|0x20) == 'f' && (t[4]|0x20) == 'o' && t[5] == '\0')
	                                        return GETDNS_RRTYPE_NINFO;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'S':
	          case 's': switch (t[2]) {
	                    case '\0': return GETDNS_RRTYPE_NS;
	                    case 'A':
	                    case 'a': /* before "NSA", final "P" (GETDNS_RRTYPE_NSAP) */
	                              if ((t[3]|0x20) == 'p' && t[4] == '\0')
	                                        return GETDNS_RRTYPE_NSAP;
	                              return -1;
	                    case 'E':
	                    case 'e': /* before "NSE", final "C3PARAM" (GETDNS_RRTYPE_NSEC3PARAM) */
	                              if ((t[3]|0x20) == 'c' && t[4] == '3' && (t[5]|0x20) == 'p' && (t[6]|0x20) == 'a' && (t[7]|0x20) == 'r' && (t[8]|0x20) == 'a' && (t[9]|0x20) == 'm' && t[10] == '\0')
	                                        return GETDNS_RRTYPE_NSEC3PARAM;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'U':
	          case 'u': /* before "NU", final "LL" (GETDNS_RRTYPE_NULL) */
	                    if ((t[2]|0x20) == 'l' && (t[3]|0x20) == 'l' && t[4] == '\0')
	                              return GETDNS_RRTYPE_NULL;
	                    return -1;
	          case 'X':
	          case 'x': /* before "NX", final "T" (GETDNS_RRTYPE_NXT) */
	                    if ((t[2]|0x20) == 't' && t[3] == '\0')
	                              return GETDNS_RRTYPE_NXT;
	                    return -1;
	          default : return -1;
	          };
	case 'O':
	case 'o': /* before "O", next "P" */
	          if ((t[1]|0x20) != 'p')
	                    return -1;
	          switch (t[2]) {
	          case 'E':
	          case 'e': /* before "OPE", final "NPGPKEY" (GETDNS_RRTYPE_OPENPGPKEY) */
	                    if ((t[3]|0x20) == 'n' && (t[4]|0x20) == 'p' && (t[5]|0x20) == 'g' && (t[6]|0x20) == 'p' && (t[7]|0x20) == 'k' && (t[8]|0x20) == 'e' && (t[9]|0x20) == 'y' && t[10] == '\0')
	                              return GETDNS_RRTYPE_OPENPGPKEY;
	                    return -1;
	          case 'T':
	          case 't': if (t[3] == '\0') return GETDNS_RRTYPE_OPT;
	                    return -1;
	          default : return -1;
	          };
	case 'P':
	case 'p': switch (t[1]) {
	          case 'T':
	          case 't': /* before "PT", final "R" (GETDNS_RRTYPE_PTR) */
	                    if ((t[2]|0x20) == 'r' && t[3] == '\0')
	                              return GETDNS_RRTYPE_PTR;
	                    return -1;
	          case 'X':
	          case 'x': if (t[2] == '\0') return GETDNS_RRTYPE_PX;
	                    return -1;
	          default : return -1;
	          };
	case 'R':
	case 'r': switch (t[1]) {
	          case 'K':
	          case 'k': /* before "RK", final "EY" (GETDNS_RRTYPE_RKEY) */
	                    if ((t[2]|0x20) == 'e' && (t[3]|0x20) == 'y' && t[4] == '\0')
	                              return GETDNS_RRTYPE_RKEY;
	                    return -1;
	          case 'P':
	          case 'p': if (t[2] == '\0') return GETDNS_RRTYPE_RP;
	                    return -1;
	          case 'R':
	          case 'r': /* before "RR", final "SIG" (GETDNS_RRTYPE_RRSIG) */
	                    if ((t[2]|0x20) == 's' && (t[3]|0x20) == 'i' && (t[4]|0x20) == 'g' && t[5] == '\0')
	                              return GETDNS_RRTYPE_RRSIG;
	                    return -1;
	          case 'T':
	          case 't': if (t[2] == '\0') return GETDNS_RRTYPE_RT;
	                    return -1;
	          default : return -1;
	          };
	case 'S':
	case 's': switch (t[1]) {
	          case 'I':
	          case 'i': switch (t[2]) {
	                    case 'G':
	                    case 'g': if (t[3] == '\0') return GETDNS_RRTYPE_SIG;
	                              return -1;
	                    case 'N':
	                    case 'n': /* before "SIN", final "K" (GETDNS_RRTYPE_SINK) */
	                              if ((t[3]|0x20) == 'k' && t[4] == '\0')
	                                        return GETDNS_RRTYPE_SINK;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'O':
	          case 'o': /* before "SO", final "A" (GETDNS_RRTYPE_SOA) */
	                    if ((t[2]|0x20) == 'a' && t[3] == '\0')
	                              return GETDNS_RRTYPE_SOA;
	                    return -1;
	          case 'P':
	          case 'p': /* before "SP", final "F" (GETDNS_RRTYPE_SPF) */
	                    if ((t[2]|0x20) == 'f' && t[3] == '\0')
	                              return GETDNS_RRTYPE_SPF;
	                    return -1;
	          case 'R':
	          case 'r': /* before "SR", final "V" (GETDNS_RRTYPE_SRV) */
	                    if ((t[2]|0x20) == 'v' && t[3] == '\0')
	                              return GETDNS_RRTYPE_SRV;
	                    return -1;
	          case 'S':
	          case 's': /* before "SS", final "HFP" (GETDNS_RRTYPE_SSHFP) */
	                    if ((t[2]|0x20) == 'h' && (t[3]|0x20) == 'f' && (t[4]|0x20) == 'p' && t[5] == '\0')
	                              return GETDNS_RRTYPE_SSHFP;
	                    return -1;
	          default : return -1;
	          };
	case 'T':
	case 't': switch (t[1]) {
	          case 'A':
	          case 'a': /* before "TA", final "LINK" (GETDNS_RRTYPE_TALINK) */
	                    if ((t[2]|0x20) == 'l' && (t[3]|0x20) == 'i' && (t[4]|0x20) == 'n' && (t[5]|0x20) == 'k' && t[6] == '\0')
	                              return GETDNS_RRTYPE_TALINK;
	                    return -1;
	          case 'K':
	          case 'k': /* before "TK", final "EY" (GETDNS_RRTYPE_TKEY) */
	                    if ((t[2]|0x20) == 'e' && (t[3]|0x20) == 'y' && t[4] == '\0')
	                              return GETDNS_RRTYPE_TKEY;
	                    return -1;
	          case 'L':
	          case 'l': /* before "TL", final "SA" (GETDNS_RRTYPE_TLSA) */
	                    if ((t[2]|0x20) == 's' && (t[3]|0x20) == 'a' && t[4] == '\0')
	                              return GETDNS_RRTYPE_TLSA;
	                    return -1;
	          case 'S':
	          case 's': /* before "TS", final "IG" (GETDNS_RRTYPE_TSIG) */
	                    if ((t[2]|0x20) == 'i' && (t[3]|0x20) == 'g' && t[4] == '\0')
	                              return GETDNS_RRTYPE_TSIG;
	                    return -1;
	          case 'X':
	          case 'x': /* before "TX", final "T" (GETDNS_RRTYPE_TXT) */
	                    if ((t[2]|0x20) == 't' && t[3] == '\0')
	                              return GETDNS_RRTYPE_TXT;
	                    return -1;
	          case 'Y':
		  case 'y': /* before "TY", then "PE" followed by a number */
	                    if ((t[2]|0x20) == 'p' && (t[3]|0x20) == 'e' && t[4] != '\0') {
	                            r = (int) strtol(t + 4, &endptr, 10);
	                            if (*endptr == '\0') return r;
	                    }
	                    return -1;
	          default : return -1;
	          };
	case 'U':
	case 'u': switch (t[1]) {
	          case 'I':
	          case 'i': switch (t[2]) {
	                    case 'D':
	                    case 'd': if (t[3] == '\0') return GETDNS_RRTYPE_UID;
	                              return -1;
	                    case 'N':
	                    case 'n': /* before "UIN", final "FO" (GETDNS_RRTYPE_UINFO) */
	                              if ((t[3]|0x20) == 'f' && (t[4]|0x20) == 'o' && t[5] == '\0')
	                                        return GETDNS_RRTYPE_UINFO;
	                              return -1;
	                    default : return -1;
	                    };
	          case 'N':
	          case 'n': /* before "UN", final "SPEC" (GETDNS_RRTYPE_UNSPEC) */
	                    if ((t[2]|0x20) == 's' && (t[3]|0x20) == 'p' && (t[4]|0x20) == 'e' && (t[5]|0x20) == 'c' && t[6] == '\0')
	                              return GETDNS_RRTYPE_UNSPEC;
	                    return -1;
	          case 'R':
	          case 'r': /* before "UR", final "I" (GETDNS_RRTYPE_URI) */
	                    if ((t[2]|0x20) == 'i' && t[3] == '\0')
	                              return GETDNS_RRTYPE_URI;
	                    return -1;
	          default : return -1;
	          };
	case 'W':
	case 'w': /* before "W", final "KS" (GETDNS_RRTYPE_WKS) */
	          if ((t[1]|0x20) == 'k' && (t[2]|0x20) == 's' && t[3] == '\0')
	                    return GETDNS_RRTYPE_WKS;
	          return -1;
	case 'X':
	case 'x': /* before "X", final "25" (GETDNS_RRTYPE_X25) */
	          if (t[1] == '2' && t[2] == '5' && t[3] == '\0')
	                    return GETDNS_RRTYPE_X25;
	          return -1;
	default : return -1;
	};
}

