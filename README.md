getdns API
==========

* Date:    2013-06-27
* GitHub:  <https://github.com/verisign/getdns> 

getdns is a [modern asynchronous DNS API] intended to make all types of DNS information easily available as described by Paul Hoffman.  This implementation is licensed under the [MIT license](http://opensource.org/licenses/MIT).

This file captures the goals and direction of the project and the current state of the implementation.

The goals of this implemtation of the getdns API are:

* Provide an open source implementation, in C, of the formally described getdns API described by Paul Hoffman at <http://www.vpnc.org/getdns-api/>
* Initial support for FreeBSD x.y, MS-Windows Ver. X, OSX 10.x, Linux (CentOS/RHEL R6uX, Ubuntu Ver X) via functional "configure" script
* Initial support to include the Android platform
* Include examples and tests as part of the build
* Document code using doxygen
* Leverage github as much as possible for project coordination
* Coding style/standards follow the [BSD coding style](ftp://ftp.netbsd.org/pub/NetBSD/NetBSD-current/src/share/misc/style)
* Follow the git flow branching model described at <http://nvie.com/posts/a-successful-git-branching-model/>
* Both synchronous and asynchronous entry points with an early focus on the asynchronous model
 
Contributors
============
Neel Goyal, Verisign, Inc.
Allison Mankin, Verisign, Inc.
Melinda Shore, No Mountain Software LLC
Glen Wiley, Verisign, Inc.

External Dependencies
=====================
External dependencies are linked outside the getdns API build tree (we rely on configure to find them).

The project relies on [libldns from NL](https://www.nlnetlabs.nl/projects/ldns/) for parsing and constructing DNS packets.  Version 1.6.16 (note that building ldns may require openssl headers and libraries)

Although [libevent](http://libevent.org) is used initially to implement the asynchronous model, future work may include a move to other mechanisms (epoll based etc.).  Version 2.0.21 stable

Current State of the Implementation
===================================
We are currently in the early stages of building the API so the code should be considered incomplete.  The current target platforms and the personal primarily responsible for ensuring it builds and runs on that platform include:

* Android, Neel Goyal
* FreeBSD, Melinda Shore
* Linux RHEL/CentOS 6.x, Glen Wiley
* MS-Windows 8, Neel Goyal
* OSX 10.8, Glen Wiley

--
end README
