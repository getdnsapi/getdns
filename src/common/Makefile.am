AM_CPPFLAGS = -Wall -Werror -g -fPIC -I$(srcdir)/ -I /usr/local/include -std=c99
lib_LTLIBRARIES = libgetdns.la
libgetdns_la_SOURCES = getdns_address.c getdns_context.c getdns_convert.c \
    getdns_dict.c getdns_general.c getdns_hostname.c getdns_list.c \
    getdns_service.c getdns_sync.c getdns_validate_dnssec.c \
    getdns_core_only.h getdns_libevent.h getdns_context.h
include_HEADERS = getdns_core_only.h
