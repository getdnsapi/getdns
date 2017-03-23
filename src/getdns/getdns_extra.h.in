/**
 * \file
 * \brief Public interface to getdns that is ADDITIONAL to the official getdns API, include
 *        in your application to use additional functionality offered by
 *        this implementation.
 */

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
#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup UnofficialgetdnsAPI Additional API for getdns implementation
 *  @{
 */

/** \defgroup Uvaluesandtexts Additional values and texts
 *  @{
 */

/**
 * \defgroup Ureturnvaluesandtext Additional return values and texts
 *  @{
 */
#define GETDNS_RETURN_NO_UPSTREAM_AVAILABLE ((getdns_return_t) 398 )
#define GETDNS_RETURN_NO_UPSTREAM_AVAILABLE_TEXT "None of the configured upstreams could be used to send queries on the specified transports"
#define GETDNS_RETURN_NEED_MORE_SPACE ((getdns_return_t) 399 )
#define GETDNS_RETURN_NEED_MORE_SPACE_TEXT "The buffer was too small"
/** @}
  */


/**
 * \defgroup Ucontextcodes Additional context codes and texts
 *  @{
 */
#define GETDNS_CONTEXT_CODE_TLS_AUTHENTICATION 618
#define GETDNS_CONTEXT_CODE_TLS_AUTHENTICATION_TEXT "Change related to getdns_context_set_tls_authentication"
#define GETDNS_CONTEXT_CODE_EDNS_CLIENT_SUBNET_PRIVATE 619
#define GETDNS_CONTEXT_CODE_EDNS_CLIENT_SUBNET_PRIVATE_TEXT "Change related to getdns_context_set_edns_client_subnet_private"
#define GETDNS_CONTEXT_CODE_TLS_QUERY_PADDING_BLOCKSIZE 620
#define GETDNS_CONTEXT_CODE_TLS_QUERY_PADDING_BLOCKSIZE_TEXT "Change related to getdns_context_set_tls_query_padding_blocksize"
#define GETDNS_CONTEXT_CODE_PUBKEY_PINSET 621
#define GETDNS_CONTEXT_CODE_PUBKEY_PINSET_TEXT "Change related to getdns_context_set_pubkey_pinset"
#define GETDNS_CONTEXT_CODE_ROUND_ROBIN_UPSTREAMS 622
#define GETDNS_CONTEXT_CODE_ROUND_ROBIN_UPSTREAMS_TEXT "Change related to getdns_context_set_round_robin_upstreams"
#define GETDNS_CONTEXT_CODE_TLS_BACKOFF_TIME 623
#define GETDNS_CONTEXT_CODE_TLS_BACKOFF_TIME_TEXT "Change related to getdns_context_set_tls_backoff_time"
#define GETDNS_CONTEXT_CODE_TLS_CONNECTION_RETRIES 624
#define GETDNS_CONTEXT_CODE_TLS_CONNECTION_RETRIES_TEXT "Change related to getdns_context_set_tls_connection_retries"
/** @}
  */


/**
 * \defgroup versions Additional version values
 *  @{
 */
#define GETDNS_VERSION "@GETDNS_VERSION@"
#define GETDNS_NUMERIC_VERSION @GETDNS_NUMERIC_VERSION@
#define GETDNS_API_VERSION "@API_VERSION@"
#define GETDNS_API_NUMERIC_VERSION @API_NUMERIC_VERSION@
/** @}
  */


/* an alias for REQUIRED */
#define GETDNS_AUTHENTICATION_HOSTNAME GETDNS_AUTHENTICATION_REQUIRED

/**
  * \defgroup authvaulesandtext Additional authentication values and texts
  * @{
  */
/* Authentication options used when doing TLS */
typedef enum getdns_tls_authentication_t {
	GETDNS_AUTHENTICATION_NONE = 1300,
	GETDNS_AUTHENTICATION_REQUIRED = 1301
} getdns_tls_authentication_t;

#define GETDNS_AUTHENTICATION_NONE_TEXT "See getdns_context_set_tls_authentication()"
#define GETDNS_AUTHENTICATION_REQUIRED_TEXT "See getdns_context_set_tls_authentication()"
/** @}
  */


/**
 * \defgroup appendname Additional append name values and texts
 *  @{
 */
#define GETDNS_APPEND_NAME_TO_SINGLE_LABEL_FIRST ((getdns_append_name_t) 554 )
#define GETDNS_APPEND_NAME_TO_SINGLE_LABEL_FIRST_TEXT "See getdns_context_set_append_name()"
/** @}
  */

/**
 * \defgroup Uvaluesandtextsdepricated Additional transport values and texts (will be deprecated)
 *  @{
 */

/** WARNING! Do not use the constants below.  They will be removed from future
 * releases.  Please use the getdns_context_set_dns_transport_list with the
 * GETDNS_TRANSPORT_UDP, GETDNS_TRANSPORT_TCP and GETDNS_TRANSPORT_TLS
 * constants instead.
 */
#define GETDNS_TRANSPORT_TLS_ONLY_KEEP_CONNECTIONS_OPEN 544
#define GETDNS_TRANSPORT_TLS_ONLY_KEEP_CONNECTIONS_OPEN_TEXT "See getdns_context_set_dns_transport()"
#define GETDNS_TRANSPORT_TLS_FIRST_AND_FALL_BACK_TO_TCP_KEEP_CONNECTIONS_OPEN 545
#define GETDNS_TRANSPORT_TLS_FIRST_AND_FALL_BACK_TO_TCP_KEEP_CONNECTIONS_OPEN_TEXT "See getdns_context_set_dns_transport()"

/** @}
  */
/** @}
  */


/**
 * \defgroup Ufunctions Additional functions
 *  @{
 */

/**
 * \defgroup Ueventloops Additional event loop extension functions
 *  @{
 */

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

/* get the currently active (pluggable) eventloop from the context */
getdns_return_t
getdns_context_get_eventloop(getdns_context* context,
    getdns_eventloop **eventloop);

/* detach the eventloop from the context */
getdns_return_t
getdns_context_detach_eventloop(getdns_context *context);

/* Run the context's event loop until nothing more to do */
void
getdns_context_run(getdns_context *context);
/** @}
 */


/**
 * \defgroup Ucontextset Additional getdns_context_set functions
 *  @{
 */
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

/* Enable the return_dnssec_status extension on every request.
   value is either GETDNS_EXTENSION_TRUE or GETDNS_EXTENSION_FALSE
   returns GETDNS_RETURN_GOOD on success or GETDNS_RETURN_INVALID_PARAMETER
   if context or value is invalid */
getdns_return_t getdns_context_set_return_dnssec_status(
    getdns_context *context, int enabled);

/* tells underlying unbound to use background threads or fork */
getdns_return_t getdns_context_set_use_threads(getdns_context* context,
    int use_threads);

getdns_return_t
getdns_context_set_tls_authentication(
    getdns_context *context, getdns_tls_authentication_t value);

getdns_return_t
getdns_context_set_round_robin_upstreams(getdns_context *context, uint8_t value);

getdns_return_t
getdns_context_set_tls_backoff_time(getdns_context *context, uint16_t value);

getdns_return_t
getdns_context_set_tls_connection_retries(getdns_context *context, uint16_t value);

getdns_return_t
getdns_context_set_edns_client_subnet_private(getdns_context *context, uint8_t value);

getdns_return_t
getdns_context_set_tls_query_padding_blocksize(getdns_context *context, uint16_t value);
/** @}
 */

 /**
  * \defgroup Ucontextget Additional getdns_context_get functions
  *  @{
  */
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
getdns_context_get_dns_transport_list(getdns_context *context,
    size_t* transport_count, getdns_transport_list_t **transports);

getdns_return_t
getdns_context_get_limit_outstanding_queries(getdns_context *context,
    uint16_t* limit);

getdns_return_t
getdns_context_get_timeout(getdns_context *context, uint64_t* timeout);

getdns_return_t
getdns_context_get_idle_timeout(getdns_context *context, uint64_t* timeout);

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

getdns_return_t
getdns_context_get_edns_client_subnet_private(getdns_context *context, uint8_t* value);

getdns_return_t
getdns_context_get_tls_query_padding_blocksize(getdns_context *context, uint16_t* value);

getdns_return_t
getdns_context_get_tls_authentication(getdns_context *context,
    getdns_tls_authentication_t* value);

getdns_return_t
getdns_context_get_round_robin_upstreams(getdns_context *context,
    uint8_t* value);

getdns_return_t
getdns_context_get_tls_backoff_time(getdns_context *context,
    uint16_t* value);

getdns_return_t
getdns_context_get_tls_connection_retries(getdns_context *context,
    uint16_t* value);

/**
 * Get the currently registered callback function and user defined argument
 * for context changes.
 * Combined with getdns_context_set_update_callback this can be used to
 * "chain" context update callbacks and in this way create a subscription
 * service catering multiple interested parties.
 * @param context The context to monitor for changes
 * @param userarg A user defined argument to be passed to the callback
 *                 function.
 * @param value   The callback function to be called on context value
 *                 changes.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_context_get_update_callback(getdns_context *context, void **userarg,
    void (**value) (getdns_context *, getdns_context_code_t, void *));

/** @}
 */


/**
 * \defgroup Uutilityfunctions Additional utility functions
 *  @{
 */

const char *getdns_get_version(void);
uint32_t getdns_get_version_number(void);
const char *getdns_get_api_version(void);
uint32_t getdns_get_api_version_number(void);

/**
 * Returns a text describing the getdns error code, or NULL when the error
 * code is unkown.
 * @param err The error code for which to return the describing text
 * @return The describing text for the error code.  The string is in library
 * space and the caller must *not* free this.
 */
const char *getdns_get_errorstr_by_id(uint16_t err);

/* dict util */
/* set a string as bindata */
getdns_return_t getdns_dict_util_set_string(getdns_dict * dict,
    char *name, const char *value);

/* get a string from a dict.  the result must be freed if valid */
getdns_return_t getdns_dict_util_get_string(getdns_dict * dict,
    char *name, char **result);



/**
 * Validate replies or resource records.
 *
 * @param  to_validate     A list of RR-dicts with companion RRSIG-RR-dicts
 *                         which will be validated.  Or a list of reply-dicts
 *                         that will be validated.  The "replies_tree" list
 *                         of a response dict can be used directly here.
 * @param  support_records A list of DS's RR-dicts and DNSKEY RR-dicts with
 *                         companion RRSIG-RR-dicts that lead up from one of
 *                         the trust_anchors to the RR-dicts or replies to
 *                         validate.  The "validation_chain" list of a response
 *                         dict (with the dnssec_return_validation_chain
 *                         extension) can be used directly here.
 * @param  trust_anchors   The list of trusted DNSKEYs or DS'es RR-dicts.
 *                         The result of the getdns_root_trust_anchor() or the
 *                         getdns_context_get_dnssec_trust_anchors() function
 *                         can be used directly here.
 * @param  validation_time The point in time in seconds since 1 January 1970
 *                         00:00:00 UTC, ignoring leap seconds, wrapping using
 *                         "Serial number arithmetic", as defined in RFC1982.
 * @param  skew            The numer of seconds of skew that is allowed in 
 *                         either direction when checking an RRSIG's 
 *                         Expiration and Inception fields
 * @return The dnssec status of validated records or replies, 
 *         GETDNS_DNSSEC_SECURE, GETDNS_DNSSEC_INSECURE,
 *         GETDNS_DNSSEC_INDETERMINATE or GETDNS_DNSSEC_BOGUS, or an error
 *         return code.
 */
getdns_return_t
getdns_validate_dnssec2(getdns_list *to_validate,
    getdns_list *support_records,
    getdns_list *trust_anchors,
    time_t validation_time, uint32_t skew);

/**
 * Public Key Pinning functionality:
 * 
 * a public key pinset is a list of dicts.  each dict should have a
 * "digest" and a "value".
 * 
 * "digest": a string indicating the type of digest. at the moment, we
 *           only support a "digest" of "sha256".
 * 
 * "value": a binary representation of the digest provided.
 * 
 * given a such a pinset, we should be able to validate a chain
 * properly according to section 2.6 of RFC 7469.
 */

/**
 * convert an HPKP-style pin description to an appropriate getdns data
 * structure.  An example string is: (with the quotes, without any
 * leading or trailing whitespace):
 *
 *    pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="
 *
 * It is the caller's responsibility to call getdns_dict_destroy() on
 * the dict returned when it is no longer needed.
 *
 * @param context a context to use to create the dict, or NULL to create
 *            it generically
 * @param str the pinning string to parse
 * @return a dict created from ctx, or  NULL if the string did not match. 
 */
getdns_dict* getdns_pubkey_pin_create_from_string(
	getdns_context* context,
	const char* str);


/**
 * Test whether a given pinset is reasonable, including:
 *
 * is it well-formed?
 * are there at least two pins?
 * are the digests used sane?
 *
 * @param pinset the set of public key pins to check for sanity.  This
 *               should be a list of dicts.
 * @param errorlist if not NULL, a list of human-readable strings is 
 *                   appended to errorlist.
 * @return GETDNS_RETURN_GOOD if the pinset passes the sanity check.
 */ 
getdns_return_t getdns_pubkey_pinset_sanity_check(
	const getdns_list* pinset,
	getdns_list* errorlist);

/**
 * Configure a context with settings given in a getdns_dict.
 *
 * @param  context The context to be configured.
 * @param  config_dict The getdns_dict containing the settings.
 *                     The settings have the same name as returned by the
 *                     getdns_context_get_api_information() function, or as
 *                     used in the names of the getdns_context_get_*() and
 *                     getdns_context_set_*() functions.
 *                     - The dict returned by
 *                       getdns_context_get_api_information() can be used
 *                       as the config_dict directly, but context settings
 *                       do *not* have to be below a `"all_context"` key.
 *                     - It is possible to set default values for extensions
 *                       that could otherwise only be given on a per query
 *                       basis.  For example:
 *                       `{ dnssec_return_status: GETDNS_EXTENSION_TRUE }` is
 *                       equivalent to using the
 *                       getdns_context_set_return_dnssec_status() function
 *                       with that value, but default values for the other 
 *                       extensions can be set by this method now too.
 *                       For example
 *                       `{ return_call_reporting: GETDNS_EXTENSION_TRUE}`
 *                     - Trust anchor files and root hints content can also be
 *                       given by file, for example:
 *
 *                            { dns_root_servers : "named.root"
 *                            , dnssec_trust_anchors: "/etc/unbound/getdns-root.key"
 *                            }
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 * **Beware** that context might be partially configured on error.  For retry
 * strategies it is advised to recreate a new config.
 */
getdns_return_t
getdns_context_config(getdns_context *context, const getdns_dict *config_dict);



/** @}
 */

/**
 * \defgroup UXTRAPrettyPrinting Pretty printing of getdns dicts and lists
 *  @{
 */

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


/** @}
 */

/**
 * \defgroup UDNSDataConversionFunctions Functions for converting between getdns DNS dicts, DNS wire format and DNS presentation format
 *  @{
 */

/**
 * Convert rr_dict to wireformat representation of the resource record.
 *
 * @param  rr_dict The getdns dict representation of the resource record
 * @param wire    A newly allocated buffer which will contain the wireformat.
 * @param wire_sz The size of the allocated buffer and the wireformat.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_rr_dict2wire(
    const getdns_dict *rr_dict, uint8_t **wire, size_t *wire_sz);

/**
 * Convert rr_dict to wireformat representation of the resource record.
 *
 * @param  rr_dict The getdns dict representation of the resource record
 * @param  wire    The buffer in which the wireformat will be written
 * @param  wire_sz On input the size of the wire buffer,
 *                 On output the amount of wireformat needed for the
 *                 wireformat representation of the resource record;
 *                 even if it did not fit.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 * GETDNS_RETURN_NEED_MORE_SPACE will be returned when the buffer was too
 * small.  wire_sz will be set to the needed buffer space then.
 */
getdns_return_t
getdns_rr_dict2wire_buf(
    const getdns_dict *rr_dict, uint8_t *wire, size_t *wire_sz);

/**
 * Convert rr_dict to wireformat representation of the resource record.
 *
 * @param  rr_dict The getdns dict representation of the resource record
 * @param  wire    A pointer to the buffer pointer in which the wireformat 
 *                 will be written.
 *                 On output the buffer pointer will have moved along
 *                 the buffer and point right after the just written RR.
 * @param  wire_sz On input the size of the wire buffer,
 *                 On output the amount of wireformat needed for the
 *                 wireformat will have been substracted from wire_sz.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 * GETDNS_RETURN_NEED_MORE_SPACE will be returned when the buffer was too
 * small.  The function will pretend that it had written beyond the end
 * of the buffer, and wire will point past the buffer and wire_sz will
 * contain a negative value.
 */
getdns_return_t
getdns_rr_dict2wire_scan(
    const getdns_dict *rr_dict, uint8_t **wire, int *wire_sz);


/**
 * Convert wireformat resource record in a getdns rr_dict representation.
 *
 * @param  wire    Buffer containing the wireformat rr
 * @param  wire_sz Size of the wire buffer
 * @param rr_dict The returned rr_dict
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_wire2rr_dict(
    const uint8_t *wire, size_t wire_sz, getdns_dict **rr_dict);

/**
 * Convert wireformat resource record in a getdns rr_dict representation.
 *
 * @param  wire    Buffer containing the wireformat rr
 * @param  wire_sz On input the size of the wire buffer
 *                 On output the length of the wireformat rr.
 * @param rr_dict The returned rr_dict
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_wire2rr_dict_buf(
    const uint8_t *wire, size_t *wire_sz, getdns_dict **rr_dict);

/**
 * Convert wireformat resource record in a getdns rr_dict representation.
 *
 * @param  wire    A pointer to the pointer of the wireformat buffer.
 *                 On return this pointer is moved to after first read
 *                 in resource record.
 * @param  wire_sz On input the size of the wire buffer
 *                 On output the size is decreased with the length
 *                 of the wireformat resource record.
 * @param rr_dict The returned rr_dict
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_wire2rr_dict_scan(
    const uint8_t **wire, size_t *wire_sz, getdns_dict **rr_dict);


/**
 * Convert rr_dict to the string representation of the resource record.
 *
 * @param  rr_dict The getdns dict representation of the resource record
 * @param str     A newly allocated string representation of the rr
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_rr_dict2str(
    const getdns_dict *rr_dict, char **str);

/**
 * Convert rr_dict to the string representation of the resource record.
 *
 * @param  rr_dict The getdns dict representation of the resource record
 * @param  str     The buffer in which the string will be written
 * @param  str_len On input the size of the text buffer,
 *                 On output the amount of characters needed to write
 *                 the string representation of the rr.  Even if it does
 *                 not fit.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 * GETDNS_RETURN_NEED_MORE_SPACE will be returned when the buffer was too
 * small.  str_len will be set to the needed buffer space then.
 */
getdns_return_t
getdns_rr_dict2str_buf(
    const getdns_dict *rr_dict, char *str, size_t *str_len);

/**
 * Convert rr_dict to the string representation of the resource record.
 *
 * @param  rr_dict The getdns dict representation of the resource record
 * @param  str     A pointer to the buffer pointer in which the string 
 *                 will be written.
 *                 On output the buffer pointer will have moved along
 *                 the buffer and point right after the just written RR.
 * @param  str_len On input the size of the str buffer,
 *                 On output the number of characters needed for the
 *                 string will have been substracted from strlen.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 * GETDNS_RETURN_NEED_MORE_SPACE will be returned when the buffer was too
 * small.  The function will pretend that it had written beyond the end
 * of the buffer, and str will point past the buffer and str_len will
 * contain a negative value.
 */
getdns_return_t
getdns_rr_dict2str_scan(
    const getdns_dict *rr_dict, char **str, int *str_len);


/**
 * Convert the string representation of the resource record to rr_dict format.
 *
 * @param  str         String representation of the resource record.
 * @param  rr_dict     The result getdns dict representation of the resource record
 * @param  origin      Default suffix for not fully qualified domain names
 * @param  default_ttl Default ttl
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_str2rr_dict(
    const char *str, getdns_dict **rr_dict,
    const char *origin, uint32_t default_ttl);

/**
 * Read the zonefile and convert to a list of rr_dict's.
 *
 * @param  in          An opened FILE pointer on the zone file.
 * @param  rr_list     The result list of rr_dicts representing the zone file.
 * @param  origin      Default suffix for not fully qualified domain names
 * @param  default_ttl Default ttl
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_fp2rr_list(
    FILE *in, getdns_list **rr_list,
    const char *origin, uint32_t default_ttl);

/**
 * Convert DNS message dict to wireformat representation.
 *
 * @param  msg_dict The getdns dict representation of a DNS message
 * @param  wire     A newly allocated buffer which will contain the wireformat.
 * @param  wire_sz  The size of the allocated buffer and the wireformat.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_msg_dict2wire(
    const getdns_dict *msg_dict, uint8_t **wire, size_t *wire_sz);

/**
 * Convert DNS message dict to wireformat representation.
 *
 * @param  msg_dict The getdns dict representation of a DNS message 
 * @param  wire     The buffer in which the wireformat will be written
 * @param  wire_sz  On input the size of the wire buffer,
 *                  On output the amount of wireformat needed for the
 *                  wireformat representation of the DNS message;
 *                  even if it did not fit.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 * GETDNS_RETURN_NEED_MORE_SPACE will be returned when the buffer was too
 * small.  wire_sz will be set to the needed buffer space then.
 */
getdns_return_t
getdns_msg_dict2wire_buf(
    const getdns_dict *msg_dict, uint8_t *wire, size_t *wire_sz);

/**
 * Convert DNS message dict to wireformat representation.
 *
 * @param  msg_dict The getdns dict representation of the DNS message
 * @param  wire     A pointer to the buffer pointer in which the wireformat 
 *                  will be written.
 *                  On output the buffer pointer will have moved along
 *                  the buffer and point right after the just written RR.
 * @param  wire_sz  On input the size of the wire buffer,
 *                  On output the amount of wireformat needed for the
 *                  wireformat will have been substracted from wire_sz.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 * GETDNS_RETURN_NEED_MORE_SPACE will be returned when the buffer was too
 * small.  The function will pretend that it had written beyond the end
 * of the buffer, and wire will point past the buffer and wire_sz will
 * contain a negative value.
 */
getdns_return_t
getdns_msg_dict2wire_scan(
    const getdns_dict *msg_dict, uint8_t **wire, int *wire_sz);


/**
 * Convert wireformat DNS message in a getdns msg_dict representation.
 *
 * @param  wire     Buffer containing the wireformat rr
 * @param  wire_sz  Size of the wire buffer
 * @param  msg_dict The returned DNS message
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_wire2msg_dict(
    const uint8_t *wire, size_t wire_sz, getdns_dict **msg_dict);

/**
 * Convert wireformat DNS message in a getdns msg_dict representation.
 *
 * @param  wire     Buffer containing the wireformat rr
 * @param  wire_sz  On input the size of the wire buffer
 *                  On output the length of the wireformat rr.
 * @param  msg_dict The returned DNS message
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_wire2msg_dict_buf(
    const uint8_t *wire, size_t *wire_sz, getdns_dict **msg_dict);

/**
 * Convert wireformat DNS message in a getdns msg_dic representation.
 *
 * @param  wire     A pointer to the pointer of the wireformat buffer.
 *                  On return this pointer is moved to after first read
 *                  in resource record.
 * @param  wire_sz  On input the size of the wire buffer
 *                  On output the size is decreased with the length
 *                  of the wireformat DNS message.
 * @param  msg_dict The returned DNS message
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_wire2msg_dict_scan(
    const uint8_t **wire, size_t *wire_sz, getdns_dict **msg_dict);


/**
 * Convert msg_dict to the string representation of the DNS message.
 *
 * @param  msg_dict The getdns dict representation of the DNS message
 * @param  str      A newly allocated string representation of the rr
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_msg_dict2str(
    const getdns_dict *msg_dict, char **str);

/**
 * Convert msg_dict to the string representation of the DNS message.
 *
 * @param  msg_dict The getdns dict representation of the resource record
 * @param  str      The buffer in which the string will be written
 * @param  str_len  On input the size of the text buffer,
 *                  On output the amount of characters needed to write
 *                  the string representation of the rr.  Even if it does
 *                  not fit.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 * GETDNS_RETURN_NEED_MORE_SPACE will be returned when the buffer was too
 * small.  str_len will be set to the needed buffer space then.
 */
getdns_return_t
getdns_msg_dict2str_buf(
    const getdns_dict *msg_dict, char *str, size_t *str_len);

/**
 * Convert msg_dict to the string representation of the resource record.
 *
 * @param  msg_dict The getdns dict representation of the resource record
 * @param  str      A pointer to the buffer pointer in which the string 
 *                  will be written.
 *                  On output the buffer pointer will have moved along
 *                  the buffer and point right after the just written RR.
 * @param  str_len  On input the size of the str buffer,
 *                  On output the number of characters needed for the
 *                  string will have been substracted from strlen.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 * GETDNS_RETURN_NEED_MORE_SPACE will be returned when the buffer was too
 * small.  The function will pretend that it had written beyond the end
 * of the buffer, and str will point past the buffer and str_len will
 * contain a negative value.
 */
getdns_return_t
getdns_msg_dict2str_scan(
    const getdns_dict *msg_dict, char **str, int *str_len);

/** @}
 */

/**
 * \defgroup Ustring2getdns_data Functions for converting strings to getdns data structures
 *  @{
 */

/**
 * Convert string text to a getdns_dict.
 *
 * @param  str   A textual representation of a getdns_dict.
 *               The format is similar, but not precisely JSON.
 *               - dict keys may be given without quotes.
 *                 For example: `{ timeout: 2000 }` is the same as { "timeout": 2000 }
 *               - When str contains an IP or IPv6 address, it is converted
 *                 to an getdns dict representation of that address.  This may contain
 *                 a port, tls_port, tsig spec or tls authentication name in the same
 *                 way as may be given with the `getdns_query` tool.  For example:
 *                 `185.49.140.67:80#443` will result in the following getdns_dict:
 *
 *                      { address_type: "IPv4"
 *                      , address_data: "185.49.140.67"
 *                      , port: 80
 *                      , tls_port: 443
 *                      }
 *
 * @param  dict The returned getdns_dict.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_str2dict(const char *str, getdns_dict **dict);

/**
 * Convert string text to a getdns_list.
 *
 * @param  str   A textual representation of a getdns_list.
 *               The format is similar, but not precisely JSON.
 * @param  list The returned getdns_list.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_str2list(const char *str, getdns_list **list);

/**
 * Convert string text to a getdns_bindata.
 *
 * @param  str   A textual representation of a getdns_bindata
 *               The format is similar, but not precisely JSON.
 *               - Strings between double-quotes will be converted to bindata
 *                 containers, but *without the trailing null byte*.
 *                 For example: `{ suffix: [ "nlnetlabs.nl.", "nlnet.nl." ] }`
 *               - bindata representation of IP or IPv6 addresses may be
 *                 given in their presentation format.  For example:
 *                 `{ dns_root_servers: [ 2001:7fd::1, 193.0.14.129 ] }`
 *               - Arbitrary binary data may be given with a `0x` prefix,
 *                 or in base64 encoding.
 *                 For example:
 *
 *                      { add_opt_parameters:
 *                        { options: [ { option_code: 10
 *                                     , option_data: 0xA9E4EC50C03F5D65
 *                                     } ]
 *                        }
 *                      }
 *
 *               - Wireformat domain name bindatas can be given with a trailing dot.
 *                 For example:
 *
 *                      { upstream_recursive_servers:
 *                        [ { address_data  : 2a04:b900:0:100::37
 *                          , tsig_name     : hmac-md5.tsigs.getdnsapi.net.
 *                          , tsig_algorithm: hmac-md5.sig-alg.reg.int.
 *                          , tsig_secret : 16G69OTeXW6xSQ==
 *                          } ]
 *                      }
 *
 * @param  bindata The returned getdns_bindata.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_str2bindata(const char *str, getdns_bindata **bindata);

/**
 * Convert string text to a getdns 32 bits unsigned integer.
 *
 * @param  str   A textual representation of the integer.
 *               The format is similar, but not precisely JSON.
 *               - integer values may be given by the constant name.
 *                 For example: `{ resolution_type: GETDNS_RESOLUTION_STUB }`
 *                 or `{ specify_class: GETDNS_RRCLASS_CH }`
 * @param  value The returned integer.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 */
getdns_return_t
getdns_str2int(const char *str, uint32_t *value);

/** @}
 */

/**
 * \defgroup UServerFunctions Functions for creating simple DNS servers
 *  @{
 */

/**
 * The user defined request handler that will be called on incoming requests.
 */
typedef void (*getdns_request_handler_t)(
	getdns_context        *context,
	getdns_callback_type_t callback_type,
	getdns_dict           *request,
	void                  *userarg,
	getdns_transaction_t   request_id
);

/**
 * Create a name server by registering a list of addresses to listen on and
 * a user defined function that will handle the requests.
 *
 * @param context The context managing the eventloop that needs to be run to
 *                start serving.
 * @param listen_addresses  A list of address dicts or bindatas that will be
 *                          listened on for DNS requests.  Both UDP and TCP
 *                          transports will be used.
 * @param userarg A user defined argument that will be passed to the handler
 *                untouched.
 * @param handler The user defined request handler that will be called with the
 *                request received in reply dict format.  To reply to this request
 *                the function has to construct a response (or modify the request)
 *                and call getdns_reply() with the response and the with the request
 *                associated request_id.  The user is responsible of destroying
 *                both the replies and the response.  **Beware** that if requests are
 *                not answered by the function, by not calling getdns_reply() this
 *                will cause a memory leak.  The user most use getdns_reply()
 *                with NULL as the response to not answer/cancel a request.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 * On failure, the current set of listening addresses is left in place.
 * Also, if there is overlap in listening_addresses between the active set
 * and the newly given set, the ones in the active set will remain in their
 * current condition and will not be closed and reopened, also all assoicated
 * DNS transactions will remain.
 */
getdns_return_t
getdns_context_set_listen_addresses(
    getdns_context *context, const getdns_list *listen_addresses,
    void *userarg, getdns_request_handler_t handler);

/**
 * Answer the request associated with a request_id that is received by a
 * request handler
 *
 * @param context The context managing the eventloop that needs to be run to
 *                listen for and answer requests.
 * @param reply The answer in getdns reply dict or response dict format.
 *              When NULL is given as reply, the request is not answered
 *              but all associated state is deleted.
 * @param request_id The identifier that links this response with the
 *                   received request.
 * @return GETDNS_RETURN_GOOD on success or an error code on failure.
 * On fatal failure (no retry strategy possible) the user still needs to
 * cancel the request by recalling getdns_reply() but with NULL as response,
 * to clean up state.
 */
getdns_return_t
getdns_reply(getdns_context *context,
    getdns_dict *reply, getdns_transaction_t request_id);


/** @}
 */


/**
 * \defgroup Uutilityfunctionsdeprecated  Additional utility functions (will be deprecated)
 *  @{
 */
/* WARNING! Function getdns_strerror is not in the API specification and
 * is likely to be removed from future versions of our implementation, to be
 * replaced by getdns_get_errorstr_by_id or something similar.
 * Please use getdns_get_errorstr_by_id instead of getdns_strerror.
 */
getdns_return_t getdns_strerror(getdns_return_t err, char *buf, size_t buflen);

getdns_return_t getdns_context_process_async(getdns_context* context);

/* Async support */
uint32_t getdns_context_get_num_pending_requests(getdns_context* context,
    struct timeval* next_timeout);

/** @}
 */
/** @}
 */
/** @}
 */

#ifdef __cplusplus
}
#endif

#endif

