/**
 *
 * /brief getdns contect management functions
 *
 * This is the meat of the API
 * Originally taken from the getdns API description pseudo implementation.
 *
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

#include "types-internal.h"
#include "util-internal.h"

/* useful macros */
#define gd_malloc(sz) context->memory_allocator(sz)
#define gd_free(ptr) context->memory_deallocator(ptr)

getdns_nameserver* nameserver_new_from_ip_dict(getdns_context_t context,
                                               getdns_dict* ip_dict) {
    if (!context || !ip_dict) {
        return NULL;
    }
    struct sockaddr_storage sockdata;
    /* setup socket */
    if (dict_to_sockaddr(ip_dict, &sockdata) != GETDNS_RETURN_GOOD) {
        return NULL;
    }
    getdns_nameserver *result = gd_malloc(sizeof(getdns_nameserver));
    if (!result) {
        return NULL;
    }
    memset(result, 0, sizeof(getdns_nameserver));
    result->context = context;
    
    /* create socket */
    evutil_socket_t sock = socket(sockdata.ss_family, SOCK_DGRAM, 0);
    evutil_make_socket_closeonexec(sock);
    evutil_make_socket_nonblocking(sock);
    
    result->address = sockdata;
    result->socket = sock;
    
    int connected = -1;
    if (sockdata.ss_family == AF_INET) {
        connected = connect(sock, (struct sockaddr *) &sockdata, sizeof(struct sockaddr_in));
    } else if (sockdata.ss_family == AF_INET6) {
        connected = connect(sock, (struct sockaddr *) &sockdata, sizeof(struct sockaddr_in6));
    }
    if (connected != 0) {
        // sad
        nameserver_free(result);
        result= NULL;
    }

    
    return result;
}

void nameserver_free(getdns_nameserver* nameserver) {
    if (!nameserver) {
        return;
    }
    if (nameserver->event) {
        event_del(nameserver->event);
        event_free(nameserver->event);
    }
    getdns_context_t context = nameserver->context;
    evutil_closesocket(nameserver->socket);
    gd_free(nameserver);

}

/* TODO */
getdns_dict* nameserver_to_dict(getdns_nameserver* nameserver) {
    return NULL;
}

