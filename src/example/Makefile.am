AM_CPPFLAGS = -Wall -Werror -g -fPIC -I$(srcdir)/ -I/usr/local/include -I../common -std=c99
AM_LDFLAGS = -L../common -L/usr/local/lib -lgetdns -lldns -levent
bin_PROGRAMS = example_all_functions example_synchronous \
    example_simple_answers example_tree
example_all_functions_SOURCES = example_all_functions.c		
example_synchronous_SOURCES = example_synchronous.c
example_simple_answers_SOURCES = example_simple_answers.c	
example_tree_SOURCES =  example_tree.c


