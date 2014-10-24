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
AC_INIT([getdns], [0.1.5], [stub-resolver@verisignlabs.com], [], [http://getdnsapi.net])
CURRENT_DATE=`LC_ALL=C date`
GETDNS_COMPILATION_COMMENT="AC_PACKAGE_STRING configured on $CURRENT_DATE for the September 2014 version of the API"
AC_SUBST(GETDNS_COMPILATION_COMMENT)
AC_CONFIG_SRCDIR([src/getdns/getdns.h.in])
# AM_INIT_AUTOMAKE
# LT_INIT
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_CPP

# Checks for programs.
AC_CANONICAL_HOST
case "$host_os" in
  linux* ) CFLAGS="$CFLAGS -D_BSD_SOURCE"
  ;;
  solaris* ) CFLAGS="$CFLAGS -D__EXTENSIONS__"  # for strdup() from <string.h>
  ;;
esac

# always use ./libtool unless override from commandline (libtool=mylibtool)
if test -z "$libtool"; then
	libtool="`pwd`/libtool"
fi
AC_SUBST(libtool)
AC_PROG_LIBTOOL
AC_PROG_INSTALL

dnl Add option to disable the evil rpath. Check whether to use rpath or not.
dnl Adds the --disable-rpath option. Uses trick to edit the ./libtool.
AC_DEFUN([ACX_ARG_RPATH],
[
AC_ARG_ENABLE(rpath,
        [  --disable-rpath         disable hardcoded rpath (default=enabled)],
	enable_rpath=$enableval, enable_rpath=yes)
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
		# TODO: Check if it is available (linux only)
		AC_MSG_NOTICE([TCP Fast Open enabled])
		AC_DEFINE_UNQUOTED([USE_TCP_FASTOPEN], [1], [Define this to enable TCP fast open.])
		;;
	no|*)
		AC_MSG_NOTICE([TCP Fast Open not enabled])
		;;
esac

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

getdns_LIBS=$LIBS
getdns_LDFLAGS=$LDFLAGS

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
    [CHECK_EVENT_PROG=check_getdns_event])

AC_SUBST(have_libevent)
AC_SUBST(EXTENSION_LIBEVENT_LIB)
AC_SUBST(EXTENSION_LIBEVENT_EXT_LIBS)
AC_SUBST(EXTENSION_LIBEVENT_LDFLAGS)
AC_SUBST(CHECK_EVENT_PROG)

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
    [CHECK_UV_PROG=check_getdns_uv])

AC_SUBST(have_libuv)
AC_SUBST(EXTENSION_LIBUV_LIB)
AC_SUBST(EXTENSION_LIBUV_EXT_LIBS)
AC_SUBST(EXTENSION_LIBUV_LDFLAGS)
AC_SUBST(CHECK_UV_PROG)

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
AC_SUBST(CHECK_EV_PROG)

# end libev extension

LIBS=$getdns_LIBS
LDFLAGS=$getdns_LDFLAGS

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

AC_CHECK_HEADERS([stdarg.h stdint.h netinet/in.h arpa/inet.h netdb.h time.h bsd/string.h],,, [AC_INCLUDES_DEFAULT])

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

AC_REPLACE_FUNCS(strlcpy)

AC_DEFINE(USE_MINI_EVENT, 1, [Needed for sync stub resolver functions])

AC_TYPE_SIGNAL

AH_BOTTOM([
/** Use on-board gldns */

#define USE_GLDNS 1
#ifdef HAVE_SSL
#  define GLDNS_BUILD_CONFIG_HAVE_SSL 1
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#include <errno.h>

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
