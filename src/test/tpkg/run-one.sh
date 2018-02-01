#!/bin/sh

export SRCDIR=`dirname $0`
. `dirname $0`/setup-env.sh

# pass a single test name as the first parameter (without .tpgk extension)
ONE_TEST=$1
shift

"${TPKG}" $* exe ${SRCDIR}/${ONE_TEST}.tpkg
"${TPKG}" -n -1 r
