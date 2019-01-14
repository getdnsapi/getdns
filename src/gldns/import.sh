#!/bin/sh

# Meant to be run from this directory

if [ -d gldns ]
then
	# Import synchronised files from comparison directory
	for f in gldns/*.[ch]
	do
		sed -e 's/sldns_/gldns_/g' \
		    -e 's/LDNS_/GLDNS_/g' \
		    -e 's/include "sldns/include "gldns/g' \
		    -e 's/<sldns\/rrdef\.h>/<gldns\/rrdef.h>/g' \
		    -e 's/sbuffer\.h/gbuffer.h/g' $f > ${f#gldns/}
	done
	mv sbuffer.h gbuffer.h
	mv sbuffer.c gbuffer.c
else
	svn co https://nlnetlabs.nl/svn/unbound/trunk/sldns/
	for f in ldns/*.[ch]
	do
		sed -e 's/sldns_/gldns_/g' \
		    -e 's/LDNS_/GLDNS_/g' \
		    -e 's/include "sldns/include "gldns/g' \
		    -e 's/<sldns\/rrdef\.h>/<gldns\/rrdef.h>/g' \
		    -e 's/sbuffer\.h/gbuffer.h/g' $f > ${f#ldns/}
	done
	mv sbuffer.h gbuffer.h
	mv sbuffer.c gbuffer.c
	rm -fr sldns
fi
