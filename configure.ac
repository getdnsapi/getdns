#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# @configure_input@
#

AC_PREREQ([2.68])
AC_INIT([getdns], [0.320], [melinda.shore@nomountain.net])
# AM_INIT_AUTOMAKE([getkey], [0.320])
AC_CONFIG_SRCDIR([configure.ac])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([event_core], [event_base_new])
AC_CHECK_LIB([getdns], [getdns_context_create])
AC_CHECK_LIB([ldns], [ldns_dname_new_frm_str])

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h netinet/in.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_CONFIG_FILES([Makefile src/common/Makefile src/test/Makefile])
AC_OUTPUT
