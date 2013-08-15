SUBDIRS = example test
AM_CPPFLAGS = -Wall -Werror -g -fPIC -I$(srcdir)/ -I /usr/local/include -std=c99
lib_LTLIBRARIES = libgetdns.la
libgetdns_la_SOURCES = context.c convert.c \
    dict.c general.c hostname.c list.c \
    service.c sync.c validate_dnssec.c
