#!/bin/sh

# Meant to be run from this directory

mkdir ub || true
cd ub
for f in mini_event.c mini_event.h rbtree.c rbtree.h
do
	wget http://unbound.net/svn/trunk/util/$f
	sed -e 's/event_/getdns_event_/g' -e 's/signal_add/getdns_signal_add/g' -e 's/signal_del/getdns_signal_del/g' -e 's/struct event/struct getdns_event/g' -e 's/mini_ev_cmp/getdns_mini_ev_cmp/g' -e 's/#include "rbtree\.h"/#include "util\/rbtree.h"/g' -e 's/rbnode_/getdns_rbnode_/g' -e 's/rbtree_/getdns_rbtree_/g' -e 's/#include "fptr_wlist\.h"/#include "util\/fptr_wlist.h"/g' -e 's/#include "log\.h"/#include "util\/log.h"/g' $f > ../$f
done
cd ..
rm -r ub
