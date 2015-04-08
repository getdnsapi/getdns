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

#ifndef _GETDNS_EXTRA_H_
#define _GETDNS_EXTRA_H_

#include <getdns/getdns.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Enable the return_dnssec_status extension on every request.
   value is either GETDNS_EXTENSION_TRUE or GETDNS_EXTENSION_FALSE
   returns GETDNS_RETURN_GOOD on success or GETDNS_RETURN_INVALID_PARAMETER
   if context or value is invalid */
getdns_return_t getdns_context_set_return_dnssec_status(
    getdns_context *context, int enabled);

/* dict util */
/* set a string as bindata */
getdns_return_t getdns_dict_util_set_string(struct getdns_dict * dict,
    char *name, const char *value);

/* get a string from a dict.  the result must be freed if valid */
getdns_return_t getdns_dict_util_get_string(struct getdns_dict * dict,
    char *name, char **result);

/* tells underlying unbound to use background threads or fork */
getdns_return_t getdns_context_set_use_threads(getdns_context* context,
    int use_threads);

/* Async support */
uint32_t getdns_context_get_num_pending_requests(getdns_context* context,
    struct timeval* next_timeout);

/* process async reqs */
getdns_return_t getdns_context_process_async(getdns_context* context);

/*****************    functions for eventloop extensions    ******************/

typedef void (*getdns_eventloop_callback)(void *userarg);

/* context extension event data */
typedef struct getdns_eventloop_event {
	void *userarg;
	getdns_eventloop_callback read_cb;
	getdns_eventloop_callback write_cb;
	getdns_eventloop_callback timeout_cb;

	/* Pointer to the underlying event
	 * that the eventloop extension will create and free.
	 */
	void *ev;
} getdns_eventloop_event;

typedef struct getdns_eventloop_vmt getdns_eventloop_vmt;
typedef struct getdns_eventloop {
	getdns_eventloop_vmt *vmt;
} getdns_eventloop;

/* A prototype for a method having no arguments and not return value. */
typedef void (*getdns_eventloop_noargs)(getdns_eventloop *loop);

/* Call the extension to schedule an event
 *
 * The getdns_eventloop_event must be provided by the caller with the callbacks
 * and userarg therein already supplied (by the caller). This function will set
 * the ev pointer (in the getdns_eventloop_event) to refer to the underlying
 * (extension) event.
 */
typedef getdns_return_t (*getdns_eventloop_schedule)(getdns_eventloop *loop,
    int fd, uint64_t timeout, getdns_eventloop_event *ev);

/* Call the extension to clean a scheduled event */
typedef getdns_return_t (*getdns_eventloop_clear)
    (getdns_eventloop *loop, getdns_eventloop_event *ev);

typedef void (*getdns_eventloop_run_once)(getdns_eventloop *loop,int blocking);

 /* Virtual Method Table */
struct getdns_eventloop_vmt {
	getdns_eventloop_noargs     cleanup;
	getdns_eventloop_schedule   schedule;
	getdns_eventloop_clear      clear;
	getdns_eventloop_noargs     run;
	getdns_eventloop_run_once   run_once;
};

/* set an event loop extension on the context */
getdns_return_t
getdns_context_set_eventloop(getdns_context* context,
    getdns_eventloop *eventloop);

/* detach the eventloop from the context */
getdns_return_t
getdns_context_detach_eventloop(getdns_context *context);

/* Run the context's event loop until nothing more to do */
void
getdns_context_run(getdns_context *context);

/** begin getters **/
getdns_return_t
getdns_context_get_resolution_type(getdns_context *context,
    getdns_resolution_t* value);

/** users must call free on the resulting namespaces if not NULL */
getdns_return_t
getdns_context_get_namespaces(getdns_context *context,
    size_t* namespace_count, getdns_namespace_t **namespaces);

getdns_return_t
getdns_context_get_dns_transport(getdns_context *context,
    getdns_transport_t* value);

getdns_return_t
getdns_context_get_limit_outstanding_queries(getdns_context *context,
    uint16_t* limit);

getdns_return_t
getdns_context_get_timeout(getdns_context *context, uint64_t* timeout);

getdns_return_t
getdns_context_get_follow_redirects(getdns_context *context,
    getdns_redirects_t* value);

getdns_return_t
getdns_context_get_dns_root_servers(getdns_context *context,
    getdns_list **addresses);

getdns_return_t
getdns_context_get_append_name(getdns_context *context,
    getdns_append_name_t* value);

getdns_return_t
getdns_context_get_suffix(getdns_context *context, getdns_list **value);

getdns_return_t
getdns_context_get_dnssec_trust_anchors(getdns_context *context,
    getdns_list **value);

getdns_return_t
getdns_context_get_dnssec_allowed_skew(getdns_context *context,
    uint32_t* value);

getdns_return_t
getdns_context_get_upstream_recursive_servers(getdns_context *context,
    getdns_list **upstream_list);

getdns_return_t
getdns_context_get_edns_maximum_udp_payload_size(getdns_context *context,
    uint16_t* value);

getdns_return_t
getdns_context_get_edns_extended_rcode(getdns_context *context,
    uint8_t* value);

getdns_return_t
getdns_context_get_edns_version(getdns_context *context, uint8_t* value);

getdns_return_t
getdns_context_get_edns_do_bit(getdns_context *context, uint8_t* value);


/**
 * Pretty print the getdns_dict in a given buffer snprintf style.
 * @param str pointer to the buffer to print to
 * @param size size of the given buffer. No more than size bytes (including
 *             the terminating null byte) will be written to str.
 * @param dict getdns_dict to print
 * @return The number of characters written excluding the terminating null byte
 * or the number of characters which would have been written if enough space
 * had been available.
 */
int
getdns_pretty_snprint_dict(char *str, size_t size, const getdns_dict *dict);

/**
 * creates a string that describes the list in a human readable form.
 * @param some_list list to pretty print
 * @return character array (caller must free this) containing pretty string
 */
char *
getdns_pretty_print_list(const getdns_list *some_list);

/**
 * Pretty print the getdns_list in a given buffer snprintf style.
 * @param str pointer to the buffer to print to
 * @param size size of the given buffer. No more than size bytes (including
 *             the terminating null byte) will be written to str.
 * @param list getdns_list to print
 * @return The number of characters written excluding the terminating null byte
 * or the number of characters which would have been written if enough space
 * had been available.
 */
int
getdns_pretty_snprint_list(char *str, size_t size, const getdns_list *list);

/**
 * creates a string containing a json representation of some_dict.
 * bindatas are converted to strings when possible, including bindatas for 
 * addresses, dnames and other printable data.  All other bindatas are
 * converted to lists of byte values.
 * @param some_dict dict to represent as json data
 * @param pretty when non-zero returns formatted json
 * @return character array (caller must free this) containing pretty string
 */
char *
getdns_print_json_dict(const getdns_dict *some_dict, int pretty);

/**
 * Prints a json representation of dict in a given buffer snprintf style.
 * bindatas are converted to strings when possible, including bindatas for 
 * addresses, dnames and other printable data.  All other bindatas are
 * converted to lists of byte values.
 * @param str pointer to the buffer to print to
 * @param size size of the given buffer. No more than size bytes (including
 *             the terminating null byte) will be written to str.
 * @param dict dict to represent as json data
 * @param pretty when non-zero returns formatted json
 * @return The number of characters written excluding the terminating null byte
 * or the number of characters which would have been written if enough space
 * had been available.
 */
int
getdns_snprint_json_dict(
    char *str, size_t size, const getdns_dict *dict, int pretty);

/**
 * creates a string containing a json representation of some_list.
 * bindatas are converted to strings when possible, including bindatas for 
 * addresses, dnames and other printable data.  All other bindatas are
 * converted to lists of byte values.
 * @param some_list list to represent as json data
 * @param pretty when non-zero returns formatted json
 * @return character array (caller must free this) containing pretty string
 */
char *
getdns_print_json_list(const getdns_list *some_list, int pretty);

/**
 * Prints a json representation of list in a given buffer snprintf style.
 * bindatas are converted to strings when possible, including bindatas for 
 * addresses, dnames and other printable data.  All other bindatas are
 * converted to lists of byte values.
 * @param str pointer to the buffer to print to
 * @param size size of the given buffer. No more than size bytes (including
 *             the terminating null byte) will be written to str.
 * @param list list to represent as json data
 * @param pretty when non-zero returns formatted json
 * @return The number of characters written excluding the terminating null byte
 * or the number of characters which would have been written if enough space
 * had been available.
 */
int
getdns_snprint_json_list(
    char *str, size_t size, const getdns_list *list, int pretty);

/**
 * Register a callback function for context changes.
 * @param context The context to monitor for changes
 * @param userarg A user defined argument that will be passed to the callback
 *                function.
 * @param value   The callback function that will be called when a context
 *                value is changed.  The arguments to the callback function
 *                are the context for which the value changes, a code
 *                referencing the changed value and the userarg parameter
 *                supplied during callback registration.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_context_set_update_callback(getdns_context *context, void *userarg,
    void (*value) (getdns_context *, getdns_context_code_t, void *));

/**
 * Get the currently registered callback function and user defined argument
 * for context changes.
 * Combined with getdns_context_set_update_callback this can be used to
 * "chain" context update callbacks and in this way create a subscription
 * service catering multiple interested parties.
 * @param context The context to monitor for changes
 * @return userarg A user defined argument to be passed to the callback
 *                 function.
 * @return value   The callback function to be called on context value
 *                 changes.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_context_get_update_callback(getdns_context *context, void **userarg,
    void (**value) (getdns_context *, getdns_context_code_t, void *));

/**
 * Returns a text describing the getdns error code, or NULL when the error
 * code is unkown.
 * @param err The error code for which to return the describing text
 * @return The describing text for the error code.  The string is in library
 * space and the caller must *not* free this.
 */
const char *getdns_get_errorstr_by_id(uint16_t err);


/* WARNING! Function getdns_strerror is not in the API specification and
 * is likely to be removed from future versions of our implementation, to be
 * replaced by getdns_get_errorstr_by_id or something similar.
 * Please use getdns_get_errorstr_by_id instead of getdns_strerror.
 */
getdns_return_t getdns_strerror(getdns_return_t err, char *buf, size_t buflen);


#ifdef __cplusplus
}
#endif

#endif

