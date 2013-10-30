#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# known to work with autconf version: autoconf (GNU Autoconf) 2.69
#
# @configure_input@
#

AC_PREREQ([2.68])
AC_INIT([getdns], [0.320], [melinda.shore@nomountain.net])
AC_CONFIG_SRCDIR([src/getdns/getdns.h])
# AM_INIT_AUTOMAKE
# LT_INIT
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_CANONICAL_HOST
case "$host_os" in
  linux* ) CFLAGS="$CFLAGS -D_XOPEN_SOURCE=501" # unfortunate, but needed to
                                                # pick up strdup() declaration
                                                # in <string.h>
  ;;     
esac

AC_PROG_CC
AC_PROG_CPP

# Checks for libraries.
found_all_libs=1
AC_MSG_NOTICE([Checking for dependencies libevent, ldns and unbound])
AC_CHECK_LIB([event_core], [event_base_new], [], [found_all_libs=0])
AC_CHECK_LIB([ldns], [ldns_dname_new_frm_str], [], [found_all_libs=0])
AC_CHECK_LIB([unbound], [ub_ctx_set_event], [], [found_all_libs=0])
if test $found_all_libs == 0
then
    AC_MSG_ERROR([One more dependencies is missing])
fi

AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
    then AC_MSG_WARN([Doxygen not found, continuing without])
fi

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h netinet/in.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_CONFIG_FILES([Makefile src/Makefile src/getdns/Makefile src/example/Makefile src/test/Makefile])
if [ test -n "$DOXYGEN" ]
    then AC_CONFIG_FILES([src/Doxyfile])
fi

AC_CONFIG_SUBDIRS([src/ src/getdns/ src/example/ src/test/])
AC_OUTPUT
