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
 * Copyright (c) 2013, Versign, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the name of the <organization> nor the
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
#include "types-internal.h"
*/

#include <ldns/ldns.h>
#include "context.h"

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

struct getdns_dns_req;
struct getdns_dict *create_getdns_response(struct getdns_dns_req *completed_request);

/* dict util */
/* set a string as bindata */
getdns_return_t getdns_dict_util_set_string(struct getdns_dict * dict, char *name,
    const char *value);

/* get a string from a dict.  result is valid as long as dict is valid */
getdns_return_t getdns_dict_util_get_string(struct getdns_dict * dict, char *name,
    char **result);
char *reverse_address(struct getdns_bindata *address_data);

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

/* util-internal.h */
