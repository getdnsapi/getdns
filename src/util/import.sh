#!/bin/sh

# Meant to be run from this directory

mkdir ub || true
cd ub
for f in mini_event.c mini_event.h rbtree.c rbtree.h
do
	wget http://unbound.net/svn/trunk/util/$f || \
	ftp  http://unbound.net/svn/trunk/util/$f || continue
	sed -e 's/event_/_getdns_event_/g' \
	    -e 's/signal_add/_getdns_signal_add/g' \
	    -e 's/signal_del/_getdns_signal_del/g' \
	    -e 's/signal_set/_getdns_signal_set/g' \
	    -e 's/evtimer_/_getdns_evtimer_/g' \
	    -e 's/struct event/struct _getdns_event/g' \
	    -e 's/mini_ev_cmp/_getdns_mini_ev_cmp/g' \
	    -e 's/static void handle_timeouts/void handle_timeouts/g' \
	    -e 's/handle_timeouts/_getdns_handle_timeouts/g' \
	    -e 's/static int handle_select/int handle_select/g' \
	    -e 's/handle_select/_getdns_handle_select/g' \
	    -e 's/#include "rbtree\.h"/#include "util\/rbtree.h"/g' \
	    -e 's/rbnode_/_getdns_rbnode_/g' \
	    -e 's/rbtree_/_getdns_rbtree_/g' \
	    -e 's/traverse_post/_getdns_traverse_post/g' \
	    -e 's/#include "fptr_wlist\.h"/#include "util\/fptr_wlist.h"/g' \
	    -e 's/#include "log\.h"/#include "util\/log.h"/g' \
	    -e '/^#define _getdns_.* mini_getdns_/d' \
	    -e '/^\/\* redefine to use our own namespace so that on platforms where$/d' \
	    -e '/^ \* linkers crosslink library-private symbols with other symbols, it works \*\//d' \
	    $f > ../$f
done
cd ..
rm -r ub
