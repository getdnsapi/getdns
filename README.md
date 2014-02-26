getdns API
==========

* Date:    2014-02-26
* GitHub:  <https://github.com/getdnsapi/getdns>

getdns is a [modern asynchronous DNS API](http://www.vpnc.org/getdns-api/) intended to make all types of DNS information easily available as described by Paul Hoffman.  This implementation is licensed under the New BSD License (BSD-new).

The [getdns-api mailing list](http://www.vpnc.org/mailman/listinfo/getdns-api) is a good place to engage in discussions regarding the design of the API.

If you are just getting started with the library take a look at the section below that
describes building and handling external dependencies for the library.  Once it is
built you should take a look at src/examples to see how the library is used.

This file captures the goals and direction of the project and the current state of the implementation.

The goals of this implementation of the getdns API are:

* Provide an open source implementation, in C, of the formally described getdns API by Paul Hoffman at <http://www.vpnc.org/getdns-api/>
* Initial support for FreeBSD, OSX, Linux (CentOS/RHEL, Ubuntu) via functional "configure" script
* Initial support to include the Android platform
* Include examples and tests as part of the build
* Document code using doxygen
* Leverage github as much as possible for project coordination
* Coding style/standards follow the BSD coding style <ftp://ftp.netbsd.org/pub/NetBSD/NetBSD-current/src/share/misc/style>

Non-goals (things we will not be doing at least initially) include:
* implementation of the traditional DNS related routines (gethostbyname, etc.)

## Language Bindings

In parallel, the team is actively developing bindings for various languages.  For more information, visit the [wiki](https://github.com/getdnsapi/getdns/wiki/Language-Bindings).

Motivation for providing the API
================================

The developers are of the opinion that DNSSEC offers a unique global infrastructure for establishing and enhancing cryptographic trust relations. With the development of this API we intend to offer application developers a modern and flexible way that enables end-to-end trust in the DNS architecture and will inspire application developers towards innovative security solutions in their applications.


Releases
========
Release numbering follows the [Semantic Versioning](http://semver.org/) approach.  The code is currently under active development.

The following requirements were met as conditions for the present release:

* code compiles cleanly on at least the primary target platforms: RHEL/CentOS 6.3 Linux, FreeBSD 9.2
* examples must compile and be clean
* clearly document supported/unsupported elements of the API


Tickets/Bug Reports
===================
Tickets and bug reports should be reported via the [GitHub issues list](https://github.com/getdnsapi/getdns/issues).

Additionally, we have a mailing list at users@getdns.net.


Building/External Dependencies
==============================

External dependencies are linked outside the getdns API build tree (we rely on configure to find them).  We would like to keep the dependency tree short.

* [libldns from NLnet Labs](https://www.nlnetlabs.nl/projects/ldns/) version 1.6.11 or later (ldns requires openssl headers and libraries)
* [libunbound from NLnet Labs](http://www.nlnetlabs.nl/projects/unbound/) version 1.4.16 or later
* [libexpat](http://expat.sourceforge.net/) for libunbound.
* [libidn from the FSF](http://www.gnu.org/software/libidn/) version 1.
* Doxygen is used to generate documentation, while this is not technically necessary for the build it makes things a lot more pleasant.

You have to install the library and also the library-devel (or -dev) for your
package management system to install the compile time files.  If you checked
out our git; the configure script is built with autoreconf --install.

## Extensions / Event loop dependencies

The implementation works with a variety of event loops, each built as a separate shared library.  See [the wiki](https://github.com/getdnsapi/getdns/wiki/Asynchronous-Support#wiki-included-event-loop-integrations) for more details.

* [libevent](http://libevent.org).  Note: the examples *require* this and should work with either libevent 1.x or 2.x.  2.x is preferred.
* [libuv](https://github.com/joyent/libuv)
* [libev](http://software.schmorp.de/pkg/libev.html)

##Regression Tests

A suite of regression tests are included with the library, if you make changes or just
want to sanity check things on your system take a look at src/test.  You will need
to install [libcheck](http://check.sourceforge.net/).  Check is also available from
many of the package repositories for the more popular operating systems.

## DNSSEC

For the library to be DNSSEC capable, it needs to know the root trust anchor.
The library will try to load the root trust anchor from
`/etc/unbound/getdns-root.key` by default.  This file is expected to have one
or more `DS` or `DNSKEY` resource records in presentation (i.e. zone file)
format.  Note that this is different than the format of BIND.keys.

The best way to setup or update the root trust anchor is by using
[`unbound-anchor`](http://www.unbound.net/documentation/unbound-anchor.html).
To setup the library with the root trust anchor at the default location,
execute the following steps as root:

    # mkdir -p /etc/unbound
    # unbound-anchor -a /etc/unbound/getdns-root.key

#Unsupported Features

The following API calls are documented in getDNS but *not supported* by the implementation at this time:

* Support for OPT Records in `getdns_general` and variants via the `extensions` parameter.
* EDNS options
  * `getdns_context_set_edns_do_bit`
  * `getdns_context_set_edns_version`
  * `getdns_context_set_edns_extended_rcode`
* `GETDNS_CONTEXT_TCP_ONLY_KEEP_CONNECTIONS_OPEN` with `getdns_context_set_dns_transport`
* DNS Search suffixes / local file support
  * `getdns_context_set_append_name`
  * `getdns_context_set_suffix`
* Setting root servers via `getdns_context_set_dns_root_servers`
* `getdns_context_set_dnssec_trust_anchors`
* Detecting changes to resolv.conf and hosts
* MDNS and NetBIOS namespaces (only DNS and LOCALFILES are supported)

Some platform specific features are not implemented in the first public release of getdns, however they are on the radar.  These include:

* Respecting settings in /etc/nsswitch.conf (linux and some other OSes), for the first release we simply check local files (/etc/hosts) before checking the DNS.
* Search suffixes specified in /etc/resolv.conf

#Known Issues

There are a few known issues which we have summarized below - the most recent
and helpful list is being maintained in the git issues list in the repository.

* (#113) Changing the resolution type between stub and recursive after a query has been issued with a context will not work - the previous resolution type will continue to be used.  If you want to change the resolution type you will need to create a new context and set the resolution type for that context.

#Supported Platforms

The primary platforms targeted are Linux and FreeBSD, other platform are supported as we get time.  The names listed here are intended to help ensure that we catch platform specific breakage, not to limit the work that folks are doing.

* Debian 7.0, 7.3
* FreeBSD 8.4, 9.2, 10.0
* RHEL/CentOS 6.4, 6.5
* OSX 10.8, 10.9
* Ubuntu 12.04, 13.10

For most platforms where we have provided a binary distribution as a compressed tar you
can simply untar the file and run "make install".  Bear in mind that any dependencies
will need to be resolved before you can get the library to do it's work.

In some cases we have provided binaries that use the native packaging for the platform,
where possible dependencies are identified using the method specific to the platform.

We intend to add MS-Windows, Android and other platforms to the releases as we have time to port it.


##Build Reports

[![Build Status](https://travis-ci.org/getdnsapi/getdns.png?branch=master)](https://travis-ci.org/getdnsapi/getdns)

###CentOS/RHEL 6.5

We rely on the most excellent package manager fpm to build the linux packages which
means that the packaging platform requires ruby 2.1.0.  There are other ways to
build the packages, this is simplythe one we chose to use.

    # cat /etc/redhat-release
    CentOS release 6.5 (Final)
    # uname -a
    Linux host-10-1-1-6 2.6.32-358.el6.x86_64 #1 SMP Fri Feb 22 00:31:26 UTC 2013 x86_64 x86_64 x86_64 GNU/Linux
    # cd getdns-0.1.0
    # ./configure --prefix=/home/deploy/build
    # make; make install
    # cd /home/deploy/build
    # mv lib lib64
    # . /usr/local/rvm/config/alias
    # fpm -x "*.la" -a native -s dir -t rpm -n getdns -v 0.1.0 -d "unbound" -d "ldns" -d "libevent" -d "libidn" --prefix /usr --vendor "Verisign Inc., NLnet Labs" --license "BSD New" --url "http://www.getdnsapi.net" --description "Modern asynchronous API to the DNS" .

###OSX

    # sw_vers
    ProductName:	Mac OS X
    ProductVersion:	10.8.5
    BuildVersion:	12F45
    
    Built using PackageMaker.

Contributors
============
* Craig Despeaux, Verisign, Inc.
* Neel Goyal, Verisign, Inc.
* Allison Mankin, Verisign, Inc. - Verisign Labs.
* Melinda Shore, No Mountain Software LLC
* Willem Toorop, NLnet Labs
* Wouter Wijngaards, NLnet Labs
* Glen Wiley, Verisign, Inc.

Acknowledgements
================
The development team explicitly acknowledges Paul Hoffman for his initiative and efforts to develop a consensus based DNS API. We would like to thank the participants of the [mailing list](http://www.vpnc.org/mailman/listinfo/getdns-api) for their contributions.
