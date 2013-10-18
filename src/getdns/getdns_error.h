/**
 * \file
 * \brief defines and data structure for getdns_error_str_by_id()
 *
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

extern getdns_lookup_table getdns_error_str[];

typedef enum getdns_enum_status getdns_status;
const char *getdns_get_errorstr_by_id(uint16_t err);

/** @}
 */

#endif /* GETDNS_ERROR_H */
