getdns API
==========

* Date:    2015-10-22
* GitHub:  <https://github.com/getdnsapi/getdns>

getdns is an implementation of a modern asynchronous DNS API specification
originally edited by Paul Hoffman.  It is intended to make all types of DNS
information easily available to application developers and non-DNS experts.
The project home page at [getdnsapi.net](https://getdnsapi.net) provides
documentation, binary downloads and new regarding the getdns API
implementation.  This implementation is licensed under the New BSD License
(BSD-new).

Download the sources from our [github repo](https://github.com/getdnsapi/getdns) 
or from [getdnsapi.net](https://getdnsapi.net) and verify the download using
the checksums (SHA1 or MD5) or using gpg to verify the signature.  Our keys are
available from the [pgp keyservers](http://keyserver.pgp.com)

* willem@nlnetlabs.nl, key id E5F8F8212F77A498
* gwiley@verisign.com, key id 9DC3D572A6B73532

The [getdns-api mailing list](http://www.vpnc.org/mailman/listinfo/getdns-api)
is a good place to engage in discussions regarding the design of the API.

If you are just getting started with the library take a look at the section
below that describes building and handling external dependencies for the
library.  Once it is built you should take a look at src/examples to see how
the library is used.

This file captures the goals and direction of the project and the current state
of the implementation.

The goals of this implementation of the getdns API are:

* Provide an open source implementation, in C, of the formally described getdns API by getdns API team at <https://getdnsapi.net/spec.html>
* Initial support for FreeBSD, OSX, Linux (CentOS/RHEL, Ubuntu) via functional "configure" script
* Initial support to include the Android platform
* Include examples and tests as part of the build
* Document code using doxygen
* Leverage github as much as possible for project coordination
* Coding style/standards follow the BSD coding style <ftp://ftp.netbsd.org/pub/NetBSD/NetBSD-current/src/share/misc/style>

Non-goals (things we will not be doing at least initially) include:
* implementation of the traditional DNS related routines (gethostbyname, etc.)

## Language Bindings

In parallel, the team is actively developing bindings for various languages.
For more information, visit the
[wiki](https://github.com/getdnsapi/getdns/wiki/Language-Bindings).

Motivation for providing the API
================================

The developers are of the opinion that DNSSEC offers a unique global
infrastructure for establishing and enhancing cryptographic trust relations.
With the development of this API we intend to offer application developers a
modern and flexible way that enables end-to-end trust in the DNS architecture
and will inspire application developers towards innovative security solutions
in their applications.


Releases
========
Release numbering follows the [Semantic Versioning](http://semver.org/)
approach.  The code is currently under active development.

The following requirements were met as conditions for the present release:

* code compiles cleanly on at least the primary target platforms: OSX, RHEL/CentOS Linux, FreeBSD
* examples must compile and run clean
* clearly document supported/unsupported elements of the API


Tickets/Bug Reports
===================
Tickets and bug reports should be reported via the [GitHub issues list](https://github.com/getdnsapi/getdns/issues).

Additionally, we have a mailing list at users@getdns.net.


Building/External Dependencies
==============================

External dependencies are linked outside the getdns API build tree (we rely on configure to find them).  We would like to keep the dependency tree short.

* [libunbound from NLnet Labs](https://unbound.net/) version 1.4.16 or later.
* [libidn from the FSF](https://www.gnu.org/software/libidn/) version 1.
* [libssl and libcrypto from the OpenSSL Project](https://www.openssl.org/) version 0.9.7 or later. (Note: version 1.0.1 or later is required for TLS support, version 1.0.2 or later is required for TLS hostname authentication)
* Doxygen is used to generate documentation, while this is not technically necessary for the build it makes things a lot more pleasant.

You have to install the library and also the library-devel (or -dev) for your
package management system to install the compile time files.  If you checked
out our git you need to copy the libtool helper scripts and rebuild configure
with:

    # libtoolize -ci
    # autoreconf -fi

## Minimal dependencies

* getdns can be configured for stub resolution mode only with the `--enable-stub-only` option to configure.  This removed the dependency on `libunbound`.
* Currently getdns only offers two helper functions to deal with IDN: `getdns_convert_ulabel_to_alabel` and `getdns_convert_alabel_to_ulabel`.  If you do not need these functions, getdns can be configured to compile without them with the `--without-libidn` option to configure.
* When both `--enable-stub-only` and `--with-libidn` options are used, getdns has only one dependency left, which is OpenSSL.

## Extensions / Event loop dependencies

The implementation works with a variety of event loops, each built as a separate shared library.  See [the wiki](https://github.com/getdnsapi/getdns/wiki/Asynchronous-Support#wiki-included-event-loop-integrations) for more details.

* [libevent](http://libevent.org).  Note: the examples *require* this and should work with either libevent 1.x or 2.x.  2.x is preferred.
* [libuv](https://github.com/joyent/libuv)
* [libev](http://software.schmorp.de/pkg/libev.html)

## Regression Tests

A suite of regression tests are included with the library, if you make changes or just
want to sanity check things on your system take a look at src/test.  You will need
to install [libcheck](http://check.sourceforge.net/) and [libldns from NLnet Labs](https://nlnetlabs.nl/projects/ldns/) version 1.6.17 or later.  Both libraries are also available from
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

* DNS Search suffixes
  * `getdns_context_set_append_name`
  * `getdns_context_set_suffix`
* Setting root servers via `getdns_context_set_dns_root_servers`
* Detecting changes to resolv.conf and hosts
* MDNS and NetBIOS namespaces (only DNS and LOCALFILES are supported)

Some platform specific features are not implemented in the first public release of getdns, however they are on the radar.  These include:

* Respecting settings in /etc/nsswitch.conf (linux and some other OSes), for the first release we simply check local files (/etc/hosts) before checking the DNS.
* Search suffixes specified in /etc/resolv.conf

#Known Issues

There are a few known issues which we have summarized below - the most recent
and helpful list is being maintained in the git issues list in the repository.
Other known issues are being managed in the git repository issue list.

* When doing a synchronous lookup with a context that has outstanding asynchronous lookups, the callbacks for the asynchronous lookups might get called as a side effect of the synchronous lookup.


#Supported Platforms

The primary platforms targeted are Linux and FreeBSD, other platform are supported as we get time.  The names listed here are intended to help ensure that we catch platform specific breakage, not to limit the work that folks are doing.

* RHEL/CentOS 6.4
* OSX 10.8
* Ubuntu 14.04

We intend to add MS-Windows, Android and other platforms to the releases as we have time to port it.


##Platform Specific Build Reports

[![Build Status](https://travis-ci.org/getdnsapi/getdns.png?branch=master)](https://travis-ci.org/getdnsapi/getdns)

###FreeBSD

If you're using [FreeBSD](http://www.freebsd.org/), you may install getdns via the [ports tree](http://www.freshports.org/dns/getdns/) by running: `cd /usr/ports/dns/getdns && make install clean`

If you are using FreeBSD 10 getdns can be intalled via 'pkg install getdns'.

###CentOS/RHEL 6.5

We rely on the most excellent package manager fpm to build the linux packages which
means that the packaging platform requires ruby 2.1.0.  There are other ways to
build the packages, this is simplythe one we chose to use.

    # cat /etc/redhat-release
    CentOS release 6.5 (Final)
    # uname -a
    Linux host-10-1-1-6 2.6.32-358.el6.x86_64 #1 SMP Fri Feb 22 00:31:26 UTC 2013 x86_64 x86_64 x86_64 GNU/Linux
    # cd getdns-0.2.0rc1
    # ./configure --prefix=/home/deploy/build
    # make; make install
    # cd /home/deploy/build
    # mv lib lib64
    # . /usr/local/rvm/config/alias
    # fpm -x "*.la" -a native -s dir -t rpm -n getdns -v 0.2.0rc1 -d "unbound" -d "ldns" -d "libevent" -d "libidn" --prefix /usr --vendor "Verisign Inc., NLnet Labs" --license "BSD New" --url "https://getdnsapi.net" --description "Modern asynchronous API to the DNS" .

###OSX

    # sw_vers
    ProductName:	Mac OS X
    ProductVersion:	10.8.5
    BuildVersion:	12F45

    Built using PackageMaker, libevent2.

    # ./configure --with-libevent --prefix=$HOME/getdnsosx/export
    # make
    # make install

    edit/fix hardcoded paths in lib/*.la to reference /usr/local

    update getdns.pmdoc to match release info

    build package using PackageMaker

    create dmg

    A self-compiled version of OpenSSL or the version installed via Homebrew is required.
    Note: If using a self-compiled version manual configuration of certificates into /usr/local/etc/openssl/certs is required for TLS authentication to work.

#### Homebrew

If you're using [Homebrew](http://brew.sh/), you may run `brew install getdns`.  By default, this will only build the core library without any 3rd party event loop support.

To install the [event loop integration libraries](https://github.com/getdnsapi/getdns/wiki/Asynchronous-Support) that enable support for libevent, libuv, and libev, run: `brew install getdns --with-libevent --with-libuv --with-libev`.  All switches are optional.

Note that in order to compile the examples, the `--with-libevent` switch is required.

As of the 0.2.0 release, when installing via Homebrew, the trust anchor is expected to be located at `$(brew --prefix)/etc/getdns-root.key`.  Additionally, the OpenSSL library installed by Homebrew is linked against. Note that the Homebrew OpenSSL installation clones the Keychain certificates to the default OpenSSL location so TLS certificate authentication should work out of the box.

Contributors
============
* Theogene Bucuti
* Andrew Cathrow, Verisign Labs
* Saúl Ibarra Corretgé
* Craig Despeaux, Verisign, Inc.
* John Dickinson, Sinodun
* Sara Dickinson, Sinodun
* Angelique Finan, Verisign, Inc.
* Daniel Kahn Gillmor
* Neel Goyal, Verisign, Inc.
* Bryan Graham, Verisign, Inc.
* Paul Hoffman
* Scott Hollenbeck, Verising, Inc.
* Shumon Huque, Verisign Labs
* Shane Kerr
* Anthony Kirby
* Olaf Kolkman, NLnet Labs
* Sanjay Mahurpawar, Verisign, Inc.
* Allison Mankin, Verisign, Inc. - Verisign Labs.
* Sai Mogali, Verisign, Inc.
* Benno Overeinder, NLnet Labs
* Joel Purra
* Prithvi Ranganath, Verisign, Inc.
* Rushi Shah, Verisign, Inc.
* Vinay Soni, Verisign, Inc.
* Melinda Shore, No Mountain Software LLC
* Bob Steagall, Verisign, Inc.
* Willem Toorop, NLnet Labs
* Gowri Visweswaran, Verisign Labs
* Wouter Wijngaards, NLnet Labs
* Glen Wiley, Verisign, Inc.
* Paul Wouters

Acknowledgements
================
The development team explicitly acknowledges Paul Hoffman for his initiative and efforts to develop a consensus based DNS API. We would like to thank the participants of the [mailing list](http://www.vpnc.org/mailman/listinfo/getdns-api) for their contributions.
