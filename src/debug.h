/**
 *
 * \file debug.h
 * /brief Macro's for debugging
 *
 */

/*
 * Copyright (c) 2015, NLnet Labs, Verisign, Inc.
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

#ifndef DEBUG_H
#define DEBUG_H

#include "config.h"

#define STUB_DEBUG_ENTRY     "-> ENTRY:       "
#define STUB_DEBUG_SETUP     "--- SETUP:      "
#define STUB_DEBUG_SETUP_TLS "--- SETUP(TLS): "
#define STUB_DEBUG_TSIG      "--- TSIG:       "
#define STUB_DEBUG_SCHEDULE  "----- SCHEDULE: "
#define STUB_DEBUG_READ      "------- READ:   "
#define STUB_DEBUG_WRITE     "------- WRITE:  "
#define STUB_DEBUG_CLEANUP   "--- CLEANUP:    "

#define DEBUG_ON(...) do { \
		struct timeval tv; \
		struct tm tm; \
		char buf[10]; \
		\
		gettimeofday(&tv, NULL); \
		gmtime_r(&tv.tv_sec, &tm); \
		strftime(buf, 10, "%H:%M:%S", &tm); \
		fprintf(stderr, "[%s.%.6d] ", buf, (int)tv.tv_usec); \
		fprintf(stderr, __VA_ARGS__); \
	} while (0)

#define DEBUG_NL(...) do { \
		struct timeval tv; \
		struct tm tm; \
		char buf[10]; \
		\
		gettimeofday(&tv, NULL); \
		gmtime_r(&tv.tv_sec, &tm); \
		strftime(buf, 10, "%H:%M:%S", &tm); \
		fprintf(stderr, "[%s.%.6d] ", buf, (int)tv.tv_usec); \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n"); \
	} while (0)


#define DEBUG_OFF(...) do {} while (0)

#if defined(SCHED_DEBUG) && SCHED_DEBUG
#include <time.h>
#define DEBUG_SCHED(...) DEBUG_ON(__VA_ARGS__)
#else
#define DEBUG_SCHED(...) DEBUG_OFF(__VA_ARGS__)
#endif

#if defined(STUB_DEBUG) && STUB_DEBUG
#include <time.h>
#define DEBUG_STUB(...) DEBUG_ON(__VA_ARGS__)
#else
#define DEBUG_STUB(...) DEBUG_OFF(__VA_ARGS__)
#endif

#if defined(SEC_DEBUG) && SEC_DEBUG
#include <time.h>
#define DEBUG_SEC(...) DEBUG_ON(__VA_ARGS__)
#else
#define DEBUG_SEC(...) DEBUG_OFF(__VA_ARGS__)
#endif

#endif
/* debug.h */
