/**
 * \file getdns_error.c
 * @brief getdns error code to string function
 *
 */

/* The MIT License (MIT)
 * Copyright (c) 2013 Verisign, Include.
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


#include <getdns/getdns.h>
#include <getdns/getdns_error.h>

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


/*---------------------------------------- getdns_get_errorstr_by_id() */
/**
 * return error string from getdns return
 * heavily modeled on ldns ldns_get_errorstr_by_id
 * @param err getdns_return_t
 * @return string containing error message
 */


const char *
getdns_get_errorstr_by_id(uint16_t err)
{
    getdns_lookup_table *lt;

    lt = getdns_error_str;
    while (lt->name != 0)  {
        if (lt->id == err)
            return lt->name;
        lt++;
    }
    return 0;
}
