#!/bin/sh

export SRCDIR=`dirname $0`
. `dirname $0`/setup-env.sh

# pass a single test name as the first parameter
ONE_TEST=${1%/}
ONE_TEST=${ONE_TEST%.tpkg}
shift

"${TPKG}" $* exe ${SRCDIR}/${ONE_TEST}.tpkg
"${TPKG}" -n -1 r
