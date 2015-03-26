#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# known to work with autconf version: autoconf (GNU Autoconf) 2.69
#
# @configure_input@
#
# Copyright (c) 2013, Verisign, Inc., NLnet Labs
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
# * Neither the names of the copyright holders nor the
#   names of its contributors may be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Verisign, Inc. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

AC_PREREQ([2.56])

AC_INIT([getdns], [0.1.6], [stub-resolver@verisignlabs.com], [], [http://getdnsapi.net])

# Set current date from system if not set
AC_ARG_WITH([current-date],
  [AS_HELP_STRING([--with-current-date]
    [current date of the compilation, set to fixed date for reproducible builds @<:@default=system@:>@])],
  [CURRENT_DATE="$with_current_date"],
  [CURRENT_DATE="`date -u +%Y-%m-%dT%H:%M:%SZ`"])
GETDNS_COMPILATION_COMMENT="AC_PACKAGE_STRING configured on $CURRENT_DATE for the January 2015 version of the API"

# Library version
# ---------------
# current:revision:age
# (binary-api-number):(which-binary-api-version):(how-many-nrs-backwardscompat)
# if source code changes increment revision
# if any interfaces have been added/removed/changed since last update then
#   increment current and set revision to 0
# if any interfaces have been added since the last public release then increment age
# if any interfaces have been removed or changed since the last public release then
#   set age to 0
# if api unchanged: no changes
# if api broken: current++ ; revision = 0; age = 0
# if programs compiled against existing library work and link with new
#    version of library with new binary api:  revision++; age++
#
# getdns-0.1.4 had libversion 0:0:0
# getdns-0.1.5 had libversion 1:0:0
# getdns-0.1.6 has libversion 1:1:1
#
GETDNS_LIBVERSION=1:1:0

AC_SUBST(GETDNS_COMPILATION_COMMENT)
AC_SUBST(GETDNS_LIBVERSION)
AC_CONFIG_SRCDIR([src/getdns/getdns.h.in])
# AM_INIT_AUTOMAKE
# LT_INIT
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_CPP

# Checks for programs.
AC_CANONICAL_HOST

CFLAGS="$CFLAGS"
AC_PROG_CC_C99
AX_CHECK_COMPILE_FLAG([-xc99],[CFLAGS="$CFLAGS -xc99"],[],[])
AX_CHECK_COMPILE_FLAG([-Wall],[CFLAGS="$CFLAGS -Wall"],[],[])

case "$host_os" in
  linux* ) CFLAGS="$CFLAGS -D_BSD_SOURCE"
  ;;
  solaris* ) CFLAGS="$CFLAGS -D__EXTENSIONS__"  # for strdup() from <string.h>
  ;;
  darwin* ) CFLAGS="$CFLAGS -D_DARWIN_C_SOURCE"  # for strlcpy() from <string.h>
  ;;
esac

# always use ./libtool unless override from commandline (libtool=mylibtool)
if test -z "$libtool"; then
	libtool="`pwd`/libtool"
fi
AC_SUBST(libtool)
AC_PROG_LIBTOOL
AC_PROG_INSTALL

initial_LIBS="$LIBS"
initial_LDFLAGS="$LDFLAGS"

dnl Add option to disable the evil rpath. Check whether to use rpath or not.
dnl Adds the --disable-rpath option. Uses trick to edit the ./libtool.
AC_DEFUN([ACX_ARG_RPATH],
[
AC_ARG_ENABLE(rpath,
        [  --disable-rpath         disable hardcoded rpath (default=enabled)],
	enable_rpath="$enableval", enable_rpath=yes)
if test "x$enable_rpath" = xno; then
	dnl AC_MSG_RESULT([Fixing libtool for -rpath problems.])
	AC_CONFIG_COMMANDS([disable-rpath], [
	sed < libtool > libtool-2 \
	's/^hardcode_libdir_flag_spec.*$'/'hardcode_libdir_flag_spec=" -D__LIBTOOL_RPATH_SED__ "/'
	mv libtool-2 libtool
	chmod 755 libtool
	libtool="./libtool"
	])
fi
])
ACX_ARG_RPATH

AC_ARG_ENABLE(tcp-fastopen, AC_HELP_STRING([--enable-tcp-fastopen], [Enable TCP Fast Open]))
case "$enable_tcp_fastopen" in
	yes)
		AC_CHECK_DECL([MSG_FASTOPEN], [], [AC_MSG_ERROR([TCP Fast Open is not available: please rerun without --enable-tcp-fastopen])], [AC_INCLUDES_DEFAULT
#include <sys/socket.h>
		])
		AC_DEFINE_UNQUOTED([USE_TCP_FASTOPEN], [1], [Define this to enable TCP fast open.])
		;;
	no|*)
		;;
esac

AC_ARG_ENABLE(broken-native-stub-dnssec, AC_HELP_STRING([--enable-broken-native-stub-dnssec], [Enable very experimental and broken native stub DNSSEC support]))
case "$enable_broken_native_stub_dnssec" in
	yes)
		AC_DEFINE_UNQUOTED([STUB_NATIVE_DNSSEC], [1], [Define this to enable the very experimental and broken native stub DNSSEC support.])
		;;
	no|*)
		;;
esac

ACX_WITH_SSL_OPTIONAL


AC_ARG_ENABLE(draft-edns-cookies, AC_HELP_STRING([--enable-draft-edns-cookies], [Enable experimental edns cookies]))
case "$enable_draft_edns_cookies" in
	yes)
		if test "x_$HAVE_SSL" != "x_yes"; then
			AC_MSG_ERROR([edns cookies need openssl libcrypto which is not available, please rerun without --enable-draft-edns-cookies])
		fi
		AC_DEFINE_UNQUOTED([EDNS_COOKIES], [1], [Define this to enable the experimental draft edns cookies.])
		;;
	no|*)
		;;
esac
AC_DEFINE_UNQUOTED([EDNS_COOKIE_OPCODE], [65001], [The edns cookie option code.])
AC_DEFINE_UNQUOTED([EDNS_COOKIE_ROLLOVER_TIME], [(24 * 60 * 60)], [How often the edns client cookie is refreshed.])

# search to set include and library paths right
# find libidn
AC_ARG_WITH(libidn, AS_HELP_STRING([--with-libidn=pathname],
	[path to libidn (default: search /usr/local ..)]),
	[], [withval="yes"])
if test x_$withval = x_yes; then
	for dir in /usr/local /opt/local /usr/pkg /usr/sfw; do
		if test -f "$dir/include/idna.h"; then
			CFLAGS="$CFLAGS -I$dir/include"
			LDFLAGS="$LDFLAGS -L$dir/lib"
			AC_MSG_NOTICE([Found libidn in $dir])
			break
		fi
		if test -f "$dir/include/idn/idna.h"; then
			CFLAGS="$CFLAGS -I$dir/include/idn"
			LDFLAGS="$LDFLAGS -L$dir/lib"
			AC_MSG_NOTICE([Found libidn in $dir])
			break
		fi
	done
	if test -f "/usr/include/idn/idna.h"; then
		CFLAGS="$CFLAGS -I/usr/include/idn"
		#LDFLAGS="$LDFLAGS -L/usr/lib"
		AC_MSG_NOTICE([Found libidn in /usr])
	fi
else
	if test x_$withval != x_no; then
		CFLAGS="$CFLAGS -I$withval/include"
		LDFLAGS="$LDFLAGS -L$withval/lib"
	fi
fi

# find libldns
AC_ARG_WITH(libldns, AS_HELP_STRING([--with-libldns=pathname],
	[path to libldns (default: search /usr/local ..)]),
	[], [withval="yes"])
if test x_$withval = x_yes; then
	for dir in /usr/local /opt/local /usr/pkg /usr/sfw; do
		if test -f "$dir/include/ldns/ldns.h"; then
			CFLAGS="$CFLAGS -I$dir/include"
			LDFLAGS="$LDFLAGS -L$dir/lib"
			AC_MSG_NOTICE([Found libldns in $dir])
			break
		fi
	done
else
	if test x_$withval != x_no; then
		CFLAGS="$CFLAGS -I$withval/include"
		LDFLAGS="$LDFLAGS -L$withval/lib"
	fi
fi

# find libunbound
AC_ARG_WITH(libunbound, AS_HELP_STRING([--with-libunbound=pathname],
	[path to libunbound (default: search /usr/local ..)]),
	[], [withval="yes"])
if test x_$withval = x_yes; then
	for dir in /usr/local /opt/local /usr/pkg /usr/sfw; do
		if test -f "$dir/include/unbound.h"; then
			CFLAGS="$CFLAGS -I$dir/include"
			LDFLAGS="$LDFLAGS -L$dir/lib"
			AC_MSG_NOTICE([Found libunbound in $dir])
			break
		fi
	done
else
	if test x_$withval != x_no; then
		CFLAGS="$CFLAGS -I$withval/include"
		LDFLAGS="$LDFLAGS -L$withval/lib"
	fi
fi

# Checks for libraries.
found_all_libs=1
AC_MSG_NOTICE([Checking for dependency ldns])
AC_CHECK_LIB([ldns], [ldns_dname_new_frm_str], [], [found_all_libs=0])
AC_MSG_NOTICE([Checking for dependency libidn])
AC_CHECK_LIB([idn], [idna_to_ascii_8z], [], [found_all_libs=0])

AC_CHECK_MEMBER([struct ldns_struct_dnssec_zone.hashed_names],
[AC_DEFINE_UNQUOTED([LDNS_DNSSEC_ZONE_HASHED_NAMES], [1], [When defined ldns_dnssec_zone contained the hashed_names member.])], [], [[#include <ldns/ldns.h>]])

if test $found_all_libs == 0
then
    AC_MSG_ERROR([One more dependencies is missing])
fi

# break out libunbound from other libraries since we are currently using a
# patch to the sources
found_libunbound=1
AC_MSG_NOTICE([Checking for dependency libunbound])
AC_CHECK_LIB([unbound], [ub_fd], [], [found_libunbound=0])
if test $found_libunbound == 0
then
    AC_MSG_ERROR([libunbound is missing.])
fi

AC_PATH_PROG([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
    then AC_MSG_WARN([doxygen not found, continuing without])
fi

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h netinet/in.h stdint.h stdlib.h string.h],,, [AC_INCLUDES_DEFAULT])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPE([u_char])

AC_CHECK_FUNCS([fcntl])
# check ioctlsocket
AC_MSG_CHECKING(for ioctlsocket)
AC_LINK_IFELSE([AC_LANG_PROGRAM([
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
], [
	(void)ioctlsocket(0, 0, NULL);
])], [
AC_MSG_RESULT(yes)
AC_DEFINE(HAVE_IOCTLSOCKET, 1, [if the function 'ioctlsocket' is available])
],[AC_MSG_RESULT(no)])


# Check for libraries for other things than libgetdns after this point,
# so the getdns libraries can be reset with:
#
#	LIBS="$getdns_LIBS"
#	LDFLAGS="$getdns_LDFLAGS"
# 
# afterwards.
getdns_LIBS="$LIBS"
getdns_LDFLAGS="$LDFLAGS"

#-------------------- libraries needed for libcheck
LIBS="$initial_LIBS"

CHECK_GETDNS=""
CHECK_LIBS=""
CHECK_CFLAGS=""

PKG_CHECK_MODULES([CHECK],[check >= 0.9.6],[CHECK_GETDNS="check_getdns"],[
AC_SEARCH_LIBS([floor], [m])
AC_SEARCH_LIBS([timer_create], [rt])
AC_SEARCH_LIBS([pthread_create], [pthread])
AC_SEARCH_LIBS([srunner_create],[check check_pic],[
CHECK_GETDNS="check_getdns"
CHECK_LIBS="$LIBS"],[
AC_SUBST(NOLIBCHECK, [nolibcheck])
AC_MSG_WARN([libcheck not found or usable; unit tests will not be compiled and run])])])

LIBS="$getdns_LIBS"

AC_SUBST([CHECK_GETDNS])
AC_SUBST([CHECK_LIBS])
AC_SUBST([CHECK_CFLAGS])
# end libraries needed for libcheck

#-------------------- libevent extension
AC_ARG_WITH([libevent],
    [AS_HELP_STRING([--with-libevent], [path to libevent (default: search /usr/local ..)])],
    [with_libevent=search],
    [withval=no])

# libevent 1.x requires a u_char typedef which is not always available
# on some systems so our check is a little complicated
# we further need to ensure that this is included in the getdns headers
# that get installed later so some users may not be building in an
# environment that has the generated config.h SO we need to generate
# this one extra header in that case

have_libevent=0
EXTENSION_LIBEVENT_EXT_LIBS=""
EXTENSION_LIBEVENT_LIB=""
EXTENSION_LIBEVENT_LDFLAGS=""
CHECK_EVENT_PROG=""
AS_IF([test x_$withval = x_no],
    [],
    [AS_IF([test x_$withval = x_yes],
        [AC_SEARCH_LIBS([event_loop],
        	[event_core event],
            [AC_CHECK_FUNCS([event_base_new event_base_free])]
            [AC_CHECK_HEADERS([event2/event.h],
                [have_libevent=1]
                [AS_IF([test "x_$ac_cv_search_event_loop" = "x_none required"],[],[EXTENSION_LIBEVENT_EXT_LIBS="$ac_cv_search_event_loop"])],
                [AC_CHECK_HEADERS([event.h],
                    [have_libevent=1]
                    [AS_IF([test "x_$ac_cv_search_event_loop" = "x_none required"],[],[EXTENSION_LIBEVENT_EXT_LIBS="$ac_cv_search_event_loop"])],
                    [AC_MSG_ERROR([event2/event.h and event.h missing, try without libevent])]
                    [have_libevent=0],
                    [AC_INCLUDES_DEFAULT]
                    [#if HAVE_U_CHAR == 0
                     typedef unsigned char u_char;
                     #endif])],
                [AC_INCLUDES_DEFAULT])],
             [AC_MSG_ERROR([libevent missing, try without libevent])]
            )],
        [have_libevent=1]
        [AC_MSG_NOTICE([assuming libevent in $withval])]
        [CFLAGS="$CFLAGS -I$withval/include"]
		[EXTENSION_LIBEVENT_LDFLAGS="-L$withval/lib"]
        [EXTENSION_LIBEVENT_EXT_LIBS="-levent"])]
    )

AS_IF([test x_$have_libevent = x_1],
    [EXTENSION_LIBEVENT_LIB="libgetdns_ext_event.la"]
    [CHECK_EVENT_PROG=check_getdns_event]
# libunbound version 1.4.22 and older, not linked against libevent, on FreeBSD,
# =============================================================================
# cannot be linked against a program that also links libevent, because of
# symbol clash.  Libunbound has a libevent clone (called mini_event) build when
# not linked against libevent that uses the same symbols as libevent.

# First detect if the libevent symbols are visible when linking with libunbound
    [LIBS="$getdns_LIBS"]
    [LDFLAGS="$getdns_LDFLAGS"]
    [AC_MSG_CHECKING([if event_get_version symbol is leaking from libunbound])]
    [AC_LANG_PUSH(C)]
     AC_LINK_IFELSE(
	     [AC_LANG_PROGRAM(
		     [[const char *event_get_version(void);]],
		     [[const char *v = event_get_version();]])
	     ],[[AC_MSG_RESULT([yes])]
                [AC_MSG_CHECKING([if libunbound is linked against libevent])]
		 AC_RUN_IFELSE(
			[AC_LANG_PROGRAM(
				[[const char *event_get_version(void);]],
				[[const char *v = event_get_version();]
				 [return v@<:@0@:>@ == 'm' && v@<:@1@:>@ == 'i' &&
				         v@<:@2@:>@ == 'n' && v@<:@3@:>@ == 'i' ? 1 : 0;]])
			],[[AC_MSG_RESULT([yes])]
			],[[AC_MSG_RESULT([no])]
			   [AC_MSG_FAILURE([
***
*** On this system, when using libevent,  libunbound must
*** also have been compiled with libevent.  Please recompile
*** libunbound with libevent, or configure --without-libevent.
***])]
			]
		)
             ],[[AC_MSG_RESULT([no])]
	     ]
     )
    [AC_LANG_POP(C)])

AC_SUBST(have_libevent)
AC_SUBST(EXTENSION_LIBEVENT_LIB)
AC_SUBST(EXTENSION_LIBEVENT_EXT_LIBS)
AC_SUBST(EXTENSION_LIBEVENT_LDFLAGS)
AS_IF([test "x$have_libcheck" = x1], [AC_SUBST(CHECK_EVENT_PROG)])

LIBS="$getdns_LIBS"
LDFLAGS="$getdns_LDFLAGS"
# end libevent extension

#-------------------- libuv extension
# if user says nothing about libuv, or specifies --with-libuv=no or --without-libuv
# then we do not want libuv extensions built
# if user specifies --with-libuv then search for it
# if user specifies --with-libuv=/path then check the lib at that path
AC_ARG_WITH([libuv],
    [AS_HELP_STRING([--with-libuv], [path to libuv (default: search /usr/local ..)])],
    [with_libuv=search],
    [withval=no])

have_libuv=0
EXTENSION_LIBUV_EXT_LIBS=""
EXTENSION_LIBUV_LIB=""
EXTENSION_LIBUV_LDFLAGS=""
CHECK_UV_PROG=""
AS_IF([test x_$withval = x_no],
    [],
    [AS_IF([test x_$withval = x_yes],
        [AC_SEARCH_LIBS([uv_run],
        	[uv],
        	[AC_CHECK_HEADERS([uv.h],
                [have_libuv=1]
                [EXTENSION_LIBUV_EXT_LIBS="$ac_cv_search_uv_run"],
                [AC_MSG_ERROR([uv.h missing, try without libuv])]
                [have_libuv=0],
                [AC_INCLUDES_DEFAULT])],
                [AC_MSG_ERROR([libuv missing, try without libuv])]
            )],
        [have_libuv=1]
        [AC_MSG_NOTICE([assuming libuv in $withval])]
        [CFLAGS="$CFLAGS -I$withval/include"]
		[EXTENSION_LIBUV_LDFLAGS="-L$withval/lib"]
        [EXTENSION_LIBUV_EXT_LIBS="-luv"])]
    )

AS_IF([test x_$have_libuv = x_1],
    [EXTENSION_LIBUV_LIB="libgetdns_ext_uv.la"]
    [CHECK_UV_PROG=check_getdns_uv]
    [AC_MSG_CHECKING([for new signature of uv_timer_cb])
     AC_LANG_PUSH(C)
     AC_COMPILE_IFELSE(
	     [AC_LANG_PROGRAM(
		     [[#include <uv.h>]
		      [void test_cb(uv_timer_t *handle);]],
		     [[uv_timer_cb cb = test_cb;]
		      [(*cb)(0);]])
	     ],[AC_MSG_RESULT([yes])
		AC_DEFINE(HAVE_NEW_UV_TIMER_CB, [1], [Does libuv have the new uv_time_cb signature])
             ],[AC_MSG_RESULT([no])
	     ])
     AC_LANG_POP(C)] 
)

AC_SUBST(have_libuv)
AC_SUBST(EXTENSION_LIBUV_LIB)
AC_SUBST(EXTENSION_LIBUV_EXT_LIBS)
AC_SUBST(EXTENSION_LIBUV_LDFLAGS)
AS_IF([test "x$have_libcheck" = x1], [AC_SUBST(CHECK_UV_PROG)])

LIBS="$getdns_LIBS"
LDFLAGS="$getdns_LDFLAGS"
# end libuv extension

#-------------------- libev extension
AC_ARG_WITH([libev],
    [AS_HELP_STRING([--with-libev], [path to libev (default: search /usr/local ..)])],
    [with_libev=search],
    [withval=no])

have_libev=0
EXTENSION_LIBEV_EXT_LIBS=""
EXTENSION_LIBEV_LIB=""
EXTENSION_LIBEV_LDFLAGS=""
CHECK_EV_PROG=""
AS_IF([test x_$withval = x_no],
    [],
    [AS_IF([test x_$withval = x_yes],
        [AC_SEARCH_LIBS([ev_run],
        	[ev],
        	[AC_CHECK_HEADERS([ev.h],
			[have_libev=1]
			[EXTENSION_LIBEV_EXT_LIBS="$ac_cv_search_ev_run"],
			[AC_CHECK_HEADERS([libev/ev.h],
				[have_libev=1]
				[EXTENSION_LIBEV_EXT_LIBS="$ac_cv_search_ev_run"],
				[AC_MSG_ERROR([ev.h missing, try without libev])]
				[have_libev=0],
				[AC_INCLUDES_DEFAULT])
			],
			[AC_INCLUDES_DEFAULT])
		],
                [AC_MSG_ERROR([libev missing, try without libev])]
            )],
        [have_libev=1]
        [AC_MSG_NOTICE([assuming libev in $withval])]
        [CFLAGS="$CFLAGS -I$withval/include"]
		[EXTENSION_LIBEV_LDFLAGS="-L$withval/lib"]
        [EXTENSION_LIBEV_EXT_LIBS="-lev"])]
    )

AS_IF([test x_$have_libev = x_1],
    [EXTENSION_LIBEV_LIB="libgetdns_ext_ev.la"]
    [CHECK_EV_PROG=check_getdns_ev])

AC_SUBST(have_libev)
AC_SUBST(EXTENSION_LIBEV_LIB)
AC_SUBST(EXTENSION_LIBEV_EXT_LIBS)
AC_SUBST(EXTENSION_LIBEV_LDFLAGS)
AS_IF([test "x$have_libcheck" = x1], [AC_SUBST(CHECK_EV_PROG)])

LIBS="$getdns_LIBS"
LDFLAGS="$getdns_LDFLAGS"
# end libev extension

# --with-trust-anchor=
AC_DEFINE([SYSCONFDIR], [sysconfdir], [System configuration dir])
AC_ARG_WITH(trust-anchor, AS_HELP_STRING([--with-trust-anchor=KEYFILE], [Default location of the trust anchor file. [default=SYSCONFDIR/unbound/getdns-root.key]]), [
 TRUST_ANCHOR_FILE="$withval"
],[
 if test "x$TRUST_ANCHOR_FILE" = "x"; then
  if test "x$sysconfdir" = 'x${prefix}/etc' ; then
   if test "x$prefix" = 'xNONE' ; then
    TRUST_ANCHOR_FILE="/etc/unbound/getdns-root.key"
   else
    TRUST_ANCHOR_FILE="${prefix}/etc/unbound/getdns-root.key"
   fi
  else
    TRUST_ANCHOR_FILE="${sysconfdir}/unbound/getdns-root.key"
  fi
 fi
])
AC_DEFINE_UNQUOTED([TRUST_ANCHOR_FILE], ["$TRUST_ANCHOR_FILE"], [Default trust anchor file])
AC_SUBST(TRUST_ANCHOR_FILE)
AC_MSG_NOTICE([Default trust anchor: $TRUST_ANCHOR_FILE])

AC_CONFIG_FILES([Makefile src/Makefile src/getdns/getdns.h spec/example/Makefile src/test/Makefile doc/Makefile])
if [ test -n "$DOXYGEN" ]
    then AC_CONFIG_FILES([src/Doxyfile])
fi


dnl -----
dnl ----- Start of "Things needed for gldns" section
dnl -----
dnl ---------------------------------------------------------------------------

AC_CHECK_HEADERS([stdarg.h stdint.h netinet/in.h arpa/inet.h netdb.h sys/socket.h time.h sys/time.h bsd/string.h],,, [AC_INCLUDES_DEFAULT])

dnl Check the printf-format attribute (if any)
dnl result in HAVE_ATTR_FORMAT.  
dnl
AC_MSG_CHECKING(whether the C compiler (${CC-cc}) accepts the "format" attribute)
AC_CACHE_VAL(ac_cv_c_format_attribute,
[ac_cv_c_format_attribute=no
AC_TRY_COMPILE(
[#include <stdio.h>
void f (char *format, ...) __attribute__ ((format (printf, 1, 2)));
void (*pf) (char *format, ...) __attribute__ ((format (printf, 1, 2)));
], [
   f ("%s", "str");
],
[ac_cv_c_format_attribute="yes"],
[ac_cv_c_format_attribute="no"])
])
AC_MSG_RESULT($ac_cv_c_format_attribute)
if test $ac_cv_c_format_attribute = yes; then
  AC_DEFINE(HAVE_ATTR_FORMAT, 1, [Whether the C compiler accepts the "format" attribute])
fi

AC_MSG_CHECKING(whether the C compiler (${CC-cc}) accepts the "unused" attribute)
AC_CACHE_VAL(ac_cv_c_unused_attribute,
[ac_cv_c_unused_attribute=no
AC_TRY_COMPILE(
[#include <stdio.h>
void f (char *u __attribute__((unused)));
], [
   f ("x");
],
[ac_cv_c_unused_attribute="yes"],
[ac_cv_c_unused_attribute="no"])
])
AC_MSG_RESULT($ac_cv_c_unused_attribute)
if test $ac_cv_c_unused_attribute = yes; then
  AC_DEFINE(HAVE_ATTR_UNUSED, 1, [Whether the C compiler accepts the "unused" attribute])
fi
AC_CHECK_DECLS([strlcpy,arc4random,arc4random_uniform])
AC_REPLACE_FUNCS(strlcpy)
AC_REPLACE_FUNCS(arc4random)
AC_REPLACE_FUNCS(arc4random_uniform)
if test "$ac_cv_func_arc4random" = "no"; then
	AC_LIBOBJ(explicit_bzero)
	AC_LIBOBJ(arc4_lock)
	AC_CHECK_FUNCS([getentropy],,[
	    if test "$USE_WINSOCK" = 1; then
		AC_LIBOBJ(getentropy_win)
	    else
		case `uname` in
		Darwin)
			AC_LIBOBJ(getentropy_osx)
		;;
		SunOS)
			AC_LIBOBJ(getentropy_solaris)
			AC_CHECK_HEADERS([sys/sha2.h],, [
				AC_CHECK_FUNCS([SHA512_Update],,[
					AC_LIBOBJ(sha512)
				])
			], [AC_INCLUDES_DEFAULT])
			if test "$ac_cv_header_sys_sha2_h" = "yes"; then
				# this lib needed for sha2 on solaris
				LIBS="$LIBS -lmd"
			fi
			AC_SEARCH_LIBS([clock_gettime], [rt])
		;;
		Linux|*)
			AC_LIBOBJ(getentropy_linux)
			dnl AC_CHECK_FUNCS([SHA512_Update],,[
			dnl	AC_DEFINE([COMPAT_SHA512], [1], [Do sha512 definitions in config.h])
			dnl	AC_LIBOBJ(sha512)
			dnl])
			AC_CHECK_HEADERS([sys/sysctl.h],,, [AC_INCLUDES_DEFAULT])
			AC_CHECK_FUNCS([getauxval])
			AC_SEARCH_LIBS([clock_gettime], [rt])
		;;
		esac
	    fi
	])
fi

AC_DEFINE(USE_MINI_EVENT, 1, [Needed for sync stub resolver functions])

AC_TYPE_SIGNAL

AH_BOTTOM([
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif

#if !defined(HAVE_STRLCPY) || !HAVE_DECL_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#else
#define __BSD_VISIBLE 1
#endif
#if !defined(HAVE_ARC4RANDOM) || !HAVE_DECL_ARC4RANDOM
uint32_t arc4random(void);
#endif
#if !defined(HAVE_ARC4RANDOM_UNIFORM) || !HAVE_DECL_ARC4RANDOM_UNIFORM 
uint32_t arc4random_uniform(uint32_t upper_bound);
#endif
#ifndef HAVE_ARC4RANDOM
void explicit_bzero(void* buf, size_t len);
int getentropy(void* buf, size_t len);
void arc4random_buf(void* buf, size_t n);
void _ARC4_LOCK(void);
void _ARC4_UNLOCK(void);
#endif
#ifdef COMPAT_SHA512
#ifndef SHA512_DIGEST_LENGTH
#define SHA512_BLOCK_LENGTH             128
#define SHA512_DIGEST_LENGTH            64
#define SHA512_DIGEST_STRING_LENGTH     (SHA512_DIGEST_LENGTH * 2 + 1)
typedef struct _SHA512_CTX {
        uint64_t        state[8];
        uint64_t        bitcount[2];
        uint8_t buffer[SHA512_BLOCK_LENGTH];
} SHA512_CTX;
#endif /* SHA512_DIGEST_LENGTH */
void SHA512_Init(SHA512_CTX*);
void SHA512_Update(SHA512_CTX*, void*, size_t);
void SHA512_Final(uint8_t[SHA512_DIGEST_LENGTH], SHA512_CTX*);
unsigned char *SHA512(void* data, unsigned int data_len, unsigned char *digest);
#endif /* COMPAT_SHA512 */

#ifdef __cplusplus
}
#endif

/** Use on-board gldns */
#define USE_GLDNS 1
#ifdef HAVE_SSL
#  define GLDNS_BUILD_CONFIG_HAVE_SSL 1
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#include <errno.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_ATTR_FORMAT
#  define ATTR_FORMAT(archetype, string_index, first_to_check) \
    __attribute__ ((format (archetype, string_index, first_to_check)))
#else /* !HAVE_ATTR_FORMAT */
#  define ATTR_FORMAT(archetype, string_index, first_to_check) /* empty */
#endif /* !HAVE_ATTR_FORMAT */

#if defined(DOXYGEN)
#  define ATTR_UNUSED(x)  x
#elif defined(__cplusplus)
#  define ATTR_UNUSED(x)
#elif defined(HAVE_ATTR_UNUSED)
#  define ATTR_UNUSED(x)  x __attribute__((unused))
#else /* !HAVE_ATTR_UNUSED */
#  define ATTR_UNUSED(x)  x
#endif /* !HAVE_ATTR_UNUSED */

/* detect if we need to cast to unsigned int for FD_SET to avoid warnings */
#ifdef HAVE_WINSOCK2_H
#define FD_SET_T (u_int)
#else
#define FD_SET_T 
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_BSD_STRING_H
#include <bsd/string.h>
#endif
])

dnl ---------------------------------------------------------------------------
dnl -----
dnl ----- End of "Things needed for gldns" section
dnl -----


AC_CONFIG_HEADER([src/config.h])
AC_OUTPUT
