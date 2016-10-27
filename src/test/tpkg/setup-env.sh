#!/bin/sh

export SRCDIR=`dirname $0`
export SRCROOT=`(cd "${SRCDIR}/../../.."; pwd)`
export TPKG="${SRCDIR}/tpkg"
export BUILDDIR=`pwd`
export BUILDROOT=`(cd "${BUILDDIR}/../../.."; pwd)`
export LIBTOOL="${BUILDROOT}/libtool"

if [ ! -f "${SRCROOT}/src/test/jsmn/jsmn.c" ]
then
	(cd "${SRCROOT}"; git submodule update --init)
fi
if [ ! -f "${SRCROOT}/libtool" ]
then
	(cd "${SRCROOT}"; (glibtoolize -fic || libtoolize -fic))
fi
if [ ! -f "${SRCROOT}/configure" ]
then
	(cd "${SRCROOT}"; autoreconf -fi)
fi
if [ -f .tpkg.var.master ]
then
	cat .tpkg.var.master \
	    | egrep -v '^export SRCDIR=|^export SRCROOT=|^export TPKG=' \
	    | egrep -v 'export BUILDDIR|^export BUILDROOT=|^export LIBTOOL=' \
	        >.tpkg.var.master.cleanup
	mv .tpkg.var.master.cleanup .tpkg.var.master
fi
cat >>.tpkg.var.master << END_OF_TPKG_VAR_MASTER
export SRCDIR="${SRCDIR}"
export SRCROOT="${SRCROOT}"
export BUILDDIR="${BUILDDIR}"
export BUILDROOT="${BUILDROOT}"
export TPKG="${TPKG}"
export LIBTOOL="${LIBTOOL}"
END_OF_TPKG_VAR_MASTER

