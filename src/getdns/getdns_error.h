/**
 * \file
 * \brief include this header in your application to use getdns API
 * This source was taken from the original pseudo-implementation by
 * Paul Hoffman.
 */
/* The MIT License (MIT)
 * Copyright (c) 2013 Verisign, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef GETDNS_ERROR_H
#define GETDNS_ERROR_H

#include <getdns/getdns.h>



struct getdns_struct_lookup_table { /* may or may not want to move this into */
    int id;                         /* getdns.h if it's more generally useful */
    const char *name;
};

typedef struct getdns_struct_lookup_table getdns_lookup_table;

/**
 * \defgroup error_table error number to string mapping
 * @{
 */

getdns_lookup_table getdns_error_str[] = {
    { GETDNS_RETURN_GOOD, "Good" },
    { GETDNS_RETURN_GENERIC_ERROR, "Generic error" },
    { GETDNS_RETURN_BAD_DOMAIN_NAME, "Badly-formed domain name" },
    { GETDNS_RETURN_BAD_CONTEXT, "Bad value for a context type" },
    { GETDNS_RETURN_CONTEXT_UPDATE_FAIL, "Did not update the context" },
    { GETDNS_RETURN_UNKNOWN_TRANSACTION, "An attempt was made to cancel a callback with a transaction_id that is not recognized" },
    { GETDNS_RETURN_NO_SUCH_LIST_ITEM, "A helper function for lists had an index argument that was too high" },
    { GETDNS_RETURN_NO_SUCH_DICT_NAME, "A helper function for dicts had a name argument that for a name that is not in the dict" },
    { GETDNS_RETURN_WRONG_TYPE_REQUESTED, "A helper function was supposed to return a certain type for an item, but the wrong type was given" },
    { GETDNS_RETURN_NO_SUCH_EXTENSION, "A name in the extensions dict is not a valid extension" },
    { GETDNS_RETURN_EXTENSION_MISFORMAT, "One or more of the extensions is has a bad format" },
    { GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED, "A query was made with a context that is using stub resolution and a DNSSEC extension specified" },
    { 0, "" }
};

typedef enum getdns_enum_status getdns_status;
const char *getdns_get_errorstr_by_id(uint16_t err);

/** @}
 */

#endif /* GETDNS_ERROR_H */
