#!/bin/sh

# Meant to be run from this directory

svn co http://unbound.net/svn/trunk/ldns/
for f in ldns/*.[ch]
do
	sed -e 's/sldns_/gldns_/g' -e 's/LDNS_/GLDNS_/g' -e 's/include "ldns/include "gldns/g' -e 's/<ldns\/rrdef\.h>/"gldns\/rrdef.h"/g' -e 's/sbuffer\.h/gbuffer.h/g' $f > ${f#ldns/}
done
mv sbuffer.h gbuffer.h
mv sbuffer.c gbuffer.c
rm -r ldns
