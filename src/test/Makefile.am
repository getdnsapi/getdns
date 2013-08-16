AM_CPPFLAGS = -Wall -Werror -g -fPIC -I$(srcdir)/ -I/usr/local/include -I$(top_srcdir)/src -std=c99
AM_LDFLAGS =-L$(top_srcdir)/src -L/usr/local/lib -lgetdns 
noinst_PROGRAMS = tests_list tests_dict tests_stub_async
tests_list_SOURCES = tests_list.c testmessages.c
tests_dict_SOURCES = tests_dict.c testmessages.c
tests_stub_async_SOURCES = tests_stub_async.c testmessages.c
