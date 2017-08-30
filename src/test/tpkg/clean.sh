#!/bin/sh

export SRCDIR=`dirname $0`
(	cd $SRCDIR
	./tpkg clean
	rm -fr build build-stub-only build-event-loops build-static-analysis install scan-build-reports .tpkg.var.master *.info
)
