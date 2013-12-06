#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# known to work with autconf version: autoconf (GNU Autoconf) 2.69
#
# @configure_input@
#

AC_PREREQ([2.56])
AC_INIT([getdns], [0.1.0], [melinda.shore@nomountain.net])
AC_CONFIG_SRCDIR([src/getdns/getdns.h])
# AM_INIT_AUTOMAKE
# LT_INIT
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_CPP

# Checks for programs.
AC_CANONICAL_HOST
case "$host_os" in
  linux* ) CFLAGS="$CFLAGS -D_XOPEN_SOURCE=501" # unfortunate, but needed to
                                                # pick up strdup() declaration
                                                # in <string.h>
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

# search to set include and library paths right
# find libidn
AC_ARG_WITH(libidn, AC_HELP_STRING([--with-libidn=pathname],
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
AC_ARG_WITH(libldns, AC_HELP_STRING([--with-libldns=pathname],
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
AC_ARG_WITH(libunbound, AC_HELP_STRING([--with-libunbound=pathname],
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
AC_MSG_NOTICE([Checking for dependencies libevent, ldns])
AC_SEARCH_LIBS([event_loop], [event_core event], [], [found_all_libs=0])
AC_CHECK_LIB([ldns], [ldns_dname_new_frm_str], [], [found_all_libs=0])
AC_CHECK_LIB([idn], [idna_to_ascii_8z], [], [found_all_libs=0])

if test $found_all_libs == 0
then
    AC_MSG_ERROR([One more dependencies is missing])
fi

# break out libunbound from other libraries since we are currently using a 
# patch to the sources
found_libunbound=1
AC_MSG_NOTICE([Checking for dependency libunbound])
AC_CHECK_LIB([unbound], [ub_ctx_set_event], [], [found_libunbound=0])
if test $found_libunbound == 0
then
    AC_MSG_ERROR([libunbound is missing or does not incude event code, you may need to patch your libunbound sources and rebuild.  See the getdns build instructions])
fi

AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
    then AC_MSG_WARN([Doxygen not found, continuing without])
fi

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h netinet/in.h stdint.h stdlib.h string.h event2/event.h],,, [AC_INCLUDES_DEFAULT])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_CHECK_FUNCS([event_base_new event_base_free])
AH_BOTTOM([
#ifndef HAVE_EVENT_BASE_FREE
#define event_base_free(x) /* nop */
#endif
#ifndef HAVE_EVENT_BASE_NEW
#define event_base_new event_init
#endif
])

AC_CONFIG_FILES([Makefile src/Makefile src/getdns/Makefile src/example/Makefile src/test/Makefile doc/Makefile])
if [ test -n "$DOXYGEN" ]
    then AC_CONFIG_FILES([src/Doxyfile])
fi
AC_CONFIG_HEADER([src/config.h])
AC_OUTPUT
