/**
 *
 * /brief A timed synchronous unbound resolve function
 *
 */
/*
 * Copyright (c) 2014, NLnet Labs, Verisign, Inc.
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

#include <sys/select.h>
#include <sys/time.h>
#include <assert.h>
#include "ub_timed_resolve.h"

static struct ub_result error_result;

static void cb_timed_resolve(void *my_arg, int err, struct ub_result *result)
{
	struct ub_result **to_return = (struct ub_result **)my_arg;
	*to_return = err ? &error_result : result;
}

int ub_timed_resolve(struct ub_ctx* ctx, char* name,
    int rrtype, int rrclass, struct ub_result** result, uint64_t *timeout)
{
	fd_set rfds;
	struct timeval tv, now, prev;
	int r;
	int ubfd;
	int async_id;
	uint64_t elapsed;

	assert(ctx != NULL);
	assert(name != NULL);
	assert(result != NULL);
	assert(timeout != NULL);

	*result = NULL;
	if (ub_resolve_async(ctx, name, rrtype, rrclass,
	    result, cb_timed_resolve, &async_id))
		return GETDNS_RETURN_GENERIC_ERROR;

	if (*result == &error_result) {
		*result = NULL;
		return GETDNS_RETURN_GENERIC_ERROR;

	} else if (*result)
		return GETDNS_RETURN_GOOD; /* result came from cache */

	ubfd = ub_fd(ctx);

	FD_ZERO(&rfds);
	FD_SET(ubfd, &rfds);

	if (gettimeofday(&now, NULL) < 0) {
		ub_cancel(ctx, async_id);
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	for (;;) {
		/* timeout is in miliseconds, so map to seconds and microseconds */
		tv.tv_sec  =  *timeout / 1000;
		tv.tv_usec = (*timeout % 1000) * 1000;

		r = select(ubfd + 1, &rfds, NULL, NULL, &tv);
		if (r <= 0)
			ub_cancel(ctx, async_id);
		if (r < 0)
			return GETDNS_RETURN_GENERIC_ERROR;
		else if (r == 0)
			return GETDNS_RESPSTATUS_ALL_TIMEOUT;

		prev = now;
		if (gettimeofday(&now, NULL) < 0) {
			ub_cancel(ctx, async_id);
			return GETDNS_RETURN_GENERIC_ERROR;
		}
		elapsed  =  now.tv_sec * 1000 +  now.tv_usec / 1000;
		elapsed -= prev.tv_sec * 1000 + prev.tv_usec / 1000;
		if (elapsed > *timeout) {
			*timeout = 0;
			ub_cancel(ctx, async_id);
			return GETDNS_RESPSTATUS_ALL_TIMEOUT;
		}
		*timeout -= elapsed;

		/* We have readiness */
		if (! ub_poll(ctx))
			continue;
		if (ub_process(ctx)) {
			ub_cancel(ctx, async_id);
			return GETDNS_RETURN_GENERIC_ERROR;
		}
		if (*result == &error_result) {
			*result = NULL;
			return GETDNS_RETURN_GENERIC_ERROR;

		} else if (*result)
			return GETDNS_RETURN_GOOD; /* result came from cache */
	}
}

/* ub_timed_resolve.c */
