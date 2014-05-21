#!/bin/sh

cat getdns/getdns.h.in getdns/*.h | grep 'getdns_[0-9a-zA-Z_]*(' \
| grep -v '^#' | sed -e 's/(.*$//g' -e 's/^.*getdns_/getdns_/g' > SYMFILE

