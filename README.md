[![Build Status](https://magnum.travis-ci.com/verisign/getdns.png?token=J2HZXstzJqePUsG523am&branch=develop)](https://magnum.travis-ci.com/verisign/getdns)

* auto-gen TOC:
{:toc}

getdns API  {#mainpage}
==========

* Date:    2014-02-14
* GitHub:  <https://github.com/verisign/getdns>

getdns is a [modern asynchronous DNS API](http://www.vpnc.org/getdns-api/) intended to make all types of DNS information easily available as described by Paul Hoffman.  This implementation is licensed under the New BSD License (BSD-new).

The [getdns-api mailing list](http://www.vpnc.org/mailman/listinfo/getdns-api) is a good place to engage in discussions regarding the design of the API.

If you are just getting started with the library take a look at the section below that
describes building and handling external dependencies for the library.  Once it is
built you should take a look at src/examples to see how the library is used.

This file captures the goals and direction of the project and the current state of the implementation.

The goals of this implementation of the getdns API are:

* Provide an open source implementation, in C, of the formally described getdns API by Paul Hoffman at <http://www.vpnc.org/getdns-api/>
* Initial support for FreeBSD, MS-Windows, OSX, Linux (CentOS/RHEL, Ubuntu) via functional "configure" script
* Initial support to include the Android platform
* Include examples and tests as part of the build
* Document code using doxygen
* Leverage github as much as possible for project coordination
* Coding style/standards follow the BSD coding style <ftp://ftp.netbsd.org/pub/NetBSD/NetBSD-current/src/share/misc/style>
* Follow the git flow branching model described at <http://nvie.com/posts/a-successful-git-branching-model/>
** the master branch is always in a production ready state
** the develop branch contains the latest development changes which are merged from develop into master once they are considered production ready
* Both synchronous and asynchronous entry points with an early focus on the asynchronous model

Non-goals (things we will not be doing at least initially) include:
* implementation of the traditional DNS related routines (gethostbyname, etc.)


Releases
========
Release numbering follows the [Semantic Versioning](http://semver.org/) approach.  We are currently in the early stages of building the API so the code should be considered incomplete.

The 0.1.0 release will be issued when the repository is opened to the public, our goal is to meet the following requirements prior to opening the repository:

* code compiles cleanly on at least the primary target platforms: RHEL/CentOS 6.3 Linux, FreeBSD 9.2
* examples must compile and be clean
* clearly document supported/unsupported elements of the API


Tickets/Bug Reports
===================
Tickets and bug reports from external contacts are received via a mailing list and managed in the git issues list.

TBD: mailing list address


#Building/External Dependencies
External dependencies are linked outside the getdns API build tree (we rely on configure to find them).  We would like to keep the dependency tree short.

* [libevent](http://libevent.org) version 2.0.21 stable
Sometimes called libevent2
* [libldns from NL](https://www.nlnetlabs.nl/projects/ldns/) version 1.6.17 (ldns requires openssl headers and libraries)
* [libunbound from NL](http://www.nlnetlabs.nl/projects/unbound/) svn revision 3069, configure must be run with the --with-libevent and the --enable-event-api option (recommended to also use --with-libunbound-only).
* [libexpat](http://expat.sourceforge.net/) for libunbound.
* [libidn from the FSF](http://www.gnu.org/software/libidn/) version 1.
* Doxygen is used to generate documentation, while this is not technically necessary for the build it makes things a lot more pleasant.

You have to install the library and also the library-devel (or -dev) for your
package management system to install the compile time files.  If you checked
out our git; the configure script is built with autoreconf --install.

Assuming that the getdns sources are in a diretory named getdns in your home directory, to build libunbound:
```
# mkdir unbound
# cd unbound
# svn export -r 3069 http://unbound.nlnetlabs.nl/svn/trunk
# cd trunk
# ./configure --with-libevent --with-libunbound-only --enable-event-api
### add --disable-gost --disable-ecdsa if elliptic curves are disabled for you.
# make
# make install
```

##Regression Tests

A suite of regression tests are included with the library, if you make changes or just
want to sanity check things on your system take a look at src/test.  You will need
to install [libcheck](http://check.sourceforge.net/).  Check is also available from
many of the package repositories for the more popular operating systems.

#Unsupported Features

The following API calls are documented in getDNS but *not supported* by the implementation at this time:

* Support for OPT Records in `getdns_general` and variants via the `extensions` parameter.
* `getdns_convert_dns_name_to_fqdn` and `getdns_convert_fqdn_to_dns_name`
* EDNS options
  * `getdns_context_set_edns_do_bit`
  * `getdns_context_set_edns_version`
  * `getdns_context_set_edns_extended_rcode`
* `GETDNS_CONTEXT_TCP_ONLY_KEEP_CONNECTIONS_OPEN` with `getdns_context_set_dns_transport`
* DNS Search suffixes / local file support
  * `getdns_context_set_append_name`
  * `getdns_context_set_suffix`
* Setting root servers via `getdns_context_set_dns_root_servers`
* DNSSEC
  * `getdns_context_set_dnssec_trust_anchors`
  * `getdns_validate_dnssec`
* Detecting changes to resolv.conf and hosts
* MDNS and NetBIOS namespaces (only DNS and LOCALFILES are supported)

Some platform specific features are not implemented in the first public release of getdns, however they are on the radar.  These include:

* Respecting settings in /etc/nsswitch.conf (linux and some other OSes), for the first release we simply check local files (/etc/hosts) before checking the DNS.
* Search suffixes specified in /etc/resolv.conf

#Known Issues

There are a few known issues which we have summarized below - the most recent
and helpful list is being maintained in the git issues list in the repository.

* (#113) Changing the resolution type between stub and recursive after a query has been issued with a context will not work - the previous resolution type will continue to be used.  If you want to change the resolution type you will need to create a new context and set the resolution type for that context.

#Spec Differences

This implementation makes a few modifications to the spec by adding the following methods to the public API:

* `getdns_context_set_memory_functions` replaces `getdns_context_set_memory_allocator`, `getdns_context_set_memory_deallocator`, and `getdns_context_set_memory_reallocator`
* `getdns_list_create_with_context`, `getdns_list_create_with_memory_functions`, `getdns_dict_create_with_context`, and `getdns_dict_create_with_memory_functions` to create lists and dictionaries with context or user supplied memory management functions.

#Supported Platforms

The primary platforms targeted are Linux and FreeBSD, other platform are supported as we get time.  The names listed here are intended to help ensure that we catch platform specific breakage, not to limit the work that folks are doing.

Where at all possible we need to make sure that both 32 and 64 bit implementations work.

* Debian 7.0, 7.3
* FreeBSD 8.4, 9.2, 10.0
* RHEL/CentOS 6.4, 6.5
* OSX 10.8, 10.9
* Ubuntu 12.04, 13.10

The NLNet folks offered to build on a number of legacy platforms as well to help ensure that the code is clean.  These include some big endian hardware and a few more obscure operating systems which will not be publicly supported but might work if someone wants to try them.

We intend to add MS-Windows, Android and other platforms to the releases as we have time to port it.


##Build Reports


TBD

Contributors
============
* Neel Goyal, Verisign, Inc.
* Allison Mankin, Verisign, Inc.
* Melinda Shore, No Mountain Software LLC
* Willem Toorop, NLNet Labs
* Glen Wiley, Verisign, Inc.
* Wouter Wijngaards, NLNet Labs
* Craig Despeaux, Verisign, Inc.

--
end README
