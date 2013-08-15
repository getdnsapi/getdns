AM_CPPFLAGS = -Wall -Werror -g -fPIC -I$(srcdir)/ -I/usr/local/include -I$(top_srcdir)/src -std=c99
AM_LDFLAGS =-L$(top_srcdir)/src -L/usr/local/lib -lgetdns 
bin_PROGRAMS = tests_list tests_dict
tests_list_SOURCES = tests_list.c testmessages.c
tests_dict_SOURCES = tests_dict.c testmessages.c
