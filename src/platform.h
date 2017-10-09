/**
 *
 * /brief general functions with platform-dependent implementations
 *
 */

/*
 * Copyright (c) 2017, NLnet Labs, Sinodun
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

#ifndef PLATFORM_H
#define PLATFORM_H

#include "config.h"

#ifdef USE_WINSOCK
typedef u_short sa_family_t;
#define _getdns_EAGAIN      (WSATRY_AGAIN)
#define _getdns_EWOULDBLOCK (WSAEWOULDBLOCK)
#define _getdns_EINPROGRESS (WSAEINPROGRESS)
#define _getdns_EMFILE      (WSAEMFILE)
#define _getdns_ECONNRESET  (WSAECONNRESET)

#define _getdns_closesocket(fd) closesocket(fd)
#define _getdns_poll(fdarray, nsockets, timer) WSAPoll(fdarray, nsockets, timer)
#define _getdns_socketerror() (WSAGetLastError())

#else /* USE_WINSOCK */

#ifdef HAVE_SYS_POLL_H
# include <sys/poll.h>
#else
# include <poll.h>
#endif

#define _getdns_EAGAIN      (EAGAIN)
#define _getdns_EWOULDBLOCK (EWOULDBLOCK)
#define _getdns_EINPROGRESS (EINPROGRESS)
#define _getdns_EMFILE      (EMFILE)
#define _getdns_ECONNRESET  (ECONNRESET)

#define SOCKADDR struct sockaddr
#define SOCKADDR_IN struct sockaddr_in
#define SOCKADDR_IN6 struct sockaddr_in6
#define SOCKADDR_STORAGE struct sockaddr_storage
#define SOCKET int

#define IP_MREQ struct ip_mreq
#define IPV6_MREQ struct ipv6_mreq
#define BOOL int
#define TRUE 1

#define _getdns_closesocket(fd) close(fd)
#define _getdns_poll(fdarray, nsockets, timer) poll(fdarray, nsockets, timer)
#define _getdns_socketerror() (errno)
#endif

#endif
