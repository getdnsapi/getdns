#!/bin/sh

export SRCDIR=`dirname $0`
(	cd $SRCDIR
	./tpkg clean
	rm -fr build build-stub-only build-event-loops build-static-analysis install install-stub-only install-event-loops install-static-analysis scan-build-reports .tpkg.var.master *.info Makefile
)
