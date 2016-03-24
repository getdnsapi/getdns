#!/bin/sh

# Meant to be run from this directory

mkdir ub || true
cd ub
for f in rbtree.c rbtree.h
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
for f in val_secalgo.h val_secalgo.c
do
	wget http://unbound.net/svn/trunk/validator/$f || \
	ftp  http://unbound.net/svn/trunk/validator/$f || continue
	sed -e 's/sldns/gldns/g' \
	    -e '/^\/\* packed_rrset on top to define enum types (forced by c99 standard) \*\/$/d' \
	    -e '/^#include "util\/data\/packed_rrset.h"$/d' \
	    -e 's/^#include "validator/#include "util/g' \
	    -e 's/^#include "gldns\/sbuffer/#include "gldns\/gbuffer/g' \
	    -e 's/^#include "util\/val_nsec3.h"/#define NSEC3_HASH_SHA1 0x01/g' \
	    -e 's/ds_digest_size_supported/_getdns_ds_digest_size_supported/g' \
	    -e 's/secalgo_ds_digest/_getdns_secalgo_ds_digest/g' \
	    -e 's/dnskey_algo_id_is_supported/_getdns_dnskey_algo_id_is_supported/g' \
	    -e 's/verify_canonrrset/_getdns_verify_canonrrset/g' \
	    -e 's/LDNS_/GLDNS_/g' \
	    -e 's/enum sec_status/int/g' \
	    -e 's/sec_status_bogus/0/g' \
	    -e 's/sec_status_unchecked/0/g' \
	    -e 's/sec_status_secure/1/g' \
	    $f > ../$f
done

cd ..
rm -r ub
