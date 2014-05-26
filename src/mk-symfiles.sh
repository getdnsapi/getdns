#!/bin/sh

write_symbols() {
	OUTPUT=$1
	shift
	grep 'getdns_[0-9a-zA-Z_]*(' $* | grep -v '^#' \
	| sed -e 's/(.*$//g' -e 's/^.*getdns_/getdns_/g' > $OUTPUT
}

write_symbols libgetdns.symbols getdns/getdns.h.in getdns/getdns_extra.h
write_symbols extension/libevent.symbols getdns/getdns_ext_libevent.h
write_symbols extension/libev.symbols getdns/getdns_ext_libev.h
write_symbols extension/libuv.symbols getdns/getdns_ext_libuv.h

