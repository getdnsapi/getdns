/**
 *
 * \file util-internal.h
 * /brief getdns contect management functions
 *
 * This is the meat of the API
 * Originally taken from the getdns API description pseudo implementation.
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

#ifndef UTIL_INTERNAL_H
#define UTIL_INTERNAL_H

#include <ldns/ldns.h>
#include "context.h"
#include "rr-iter.h"

#define SCHED_DEBUG 0
#define WIRE_DEBUG 1

#ifdef S_SPLINT_S
#  define INLINE 
#else
#  ifdef SWIG
#    define INLINE static
#  else
#    define INLINE static inline
#  endif
#endif

struct ub_result;
struct getdns_network_req;
getdns_return_t getdns_apply_network_result(getdns_network_req* netreq, struct ub_result* result);

#define GETDNS_MAX_DNAME_LEN 255
#define GETDNS_MAX_LABEL_LEN 63

/**
 * add an item to the tail of a list - note that this was not in the getdns API
 * description but the list_set functions seem to be designed to modify an existing
 * item in the list.  The newly added item has no data type.
 * @param list list containing the item to which child_list is to be added
 * @param *index assigned to the index of the newly added item on success
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_GENERAL_ERROR if out of memory
 */
getdns_return_t getdns_list_add_item(struct getdns_list *list, size_t * index);
getdns_return_t getdns_list_append_dict(getdns_list *list,
    const getdns_dict *child_dict);
getdns_return_t getdns_list_append_list(getdns_list *list,
    const getdns_list *child_list);
getdns_return_t getdns_list_append_bindata(getdns_list *list,
    const getdns_bindata *child_bindata);
getdns_return_t getdns_list_append_int(getdns_list *list,
    uint32_t child_uint32);

/**
  * private function (API users should not be calling this), this uses library
  * routines to make a copy of the list - would be faster to make the copy directly
  * caller must ensure that dstlist points to unallocated storage - the address will
  * be overwritten by a new list via a call to getdns_list_create(context)
  * @param srclist pointer to list to copy
  * @param dstlist pointer to pointer to list to receive the copy (will be allocated)
  * @return GETDNS_RETURN_GOOD on success
  * @return GETDNS_RETURN_NO_SUCH_LIST_ITEM if list is invalid
  * @return GETDNS_RETURN_GENERIC_ERROR if out of memory
  */
getdns_return_t getdns_list_copy(const struct getdns_list *srclist,
    struct getdns_list **dstlist);

/**
 * private function used to make a copy of a dict structure, the caller is responsible
 * for freeing storage allocated to returned value
 * NOTE: not thread safe - this needs to be fixed to be thread safe
 * @param srcdict the dictionary structure to copy
 * @param dstdict pointer to the location to write pointer to new dictionary
 * @return GETDNS_RETURN_GOOD on success
 */
getdns_return_t
getdns_dict_copy(const struct getdns_dict *srcdict,
    struct getdns_dict **dstdict);

/**
 * convert an ip address (v4/v6) dict to a sock storage
 * expects dict to contain keys GETDNS_STR_PORT, GETDNS_STR_ADDRESS_TYPE
 * GETDNS_STR_ADDRESS_DATA
 * @param ns pointer to dictionary containing keys listed above
 * @param output previously allocated storage used to return numeric address
 * @return GETDNS_RETURN_GOOD on success
 * @return GETDNS_RETURN_GENERIC_ERROR if keys missing from dictionary
 */
getdns_return_t dict_to_sockaddr(struct getdns_dict * ns,
    struct sockaddr_storage *output);
getdns_return_t sockaddr_to_dict(struct getdns_context *context,
    struct sockaddr_storage *sockaddr, struct getdns_dict ** output);

getdns_dict *
priv_getdns_rr_iter2rr_dict(getdns_context *context, priv_getdns_rr_iter *i);

struct getdns_dns_req;
struct getdns_dict *create_getdns_response(struct getdns_dns_req *completed_request);

getdns_return_t validate_dname(const char* dname);

/**
 * detect unrecognized extension strings or invalid extension formats
 * TODO: this could be optimized by searching a sorted list
 * @param extensions dictionary of valid extension strings and values
 * @return GETDNS_RETURN_GOOD if each extension string is valid and the format matches the API specification
 * @return GETDNS_RETURN_NO_SUCH_EXTENSION A name in the extensions dict is not a valid extension.
 * @return GETDNS_RETURN_EXTENSION_MISFORMAT One or more of the extensions has a bad format.
 */
getdns_return_t validate_extensions(struct getdns_dict * extensions);

/**
 * helper to convert an rr_list to getdns_list
 * @param context initialized getdns_context
 * @param rr_list ldns rr list to be converted
 * @return a list of objects where each object is a result from create_dict_from_rr
 */
struct getdns_list *
create_list_from_rr_list(struct getdns_context *context, ldns_rr_list * rr_list);


#define DEBUG_ON(...) do { \
		struct timeval tv; \
		struct tm tm; \
		char buf[10]; \
		\
		gettimeofday(&tv, NULL); \
		gmtime_r(&tv.tv_sec, &tm); \
		strftime(buf, 10, "%T", &tm); \
		fprintf(stderr, "[%s.%.6d] ", buf, (int)tv.tv_usec); \
		fprintf(stderr, __VA_ARGS__); \
	} while (0)

#define DEBUG_OFF(...) do {} while (0)

#if defined(SCHED_DEBUG) && SCHED_DEBUG
#include <time.h>
#define DEBUG_SCHED(...) DEBUG_ON(__VA_ARGS__)
#else
#define DEBUG_SCHED(...) DEBUG_OFF(__VA_ARGS__)
#endif

INLINE getdns_eventloop_event *getdns_eventloop_event_init(
    getdns_eventloop_event *ev,void *userarg, getdns_eventloop_callback read_cb,
    getdns_eventloop_callback write_cb, getdns_eventloop_callback timeout_cb)
{ ev->userarg = userarg; ev->read_cb = read_cb; ev->write_cb = write_cb;
  ev->timeout_cb = timeout_cb; ev->ev = NULL; return ev; }

#define GETDNS_CLEAR_EVENT(loop, event) \
	do { if ((event)->ev) (loop)->vmt->clear((loop), (event)); } while(0)
#define GETDNS_SCHEDULE_EVENT(loop, fd, timeout, event) \
	do { (loop)->vmt->schedule((loop),(fd),(timeout),(event)); } while(0)

#endif
/* util-internal.h */
