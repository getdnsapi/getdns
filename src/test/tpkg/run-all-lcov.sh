#!/bin/sh

export SRCDIR=`dirname $0`
. `dirname $0`/setup-env.sh

LCOV_MERGE=""
for TEST_PKG in ${SRCDIR}/*.tpkg
do
    # when we run our test, we need to compile with profiling
	CFLAGS="-fprofile-arcs -ftest-coverage -O0" "${TPKG}" $* exe "${TEST_PKG}"
    # after the test is complete, we need to collect the coverage data
    INFO_FILE=`echo $TEST_PKG | sed 's/.tpkg$//'`.info
    geninfo $SRCDIR/.. -o $INFO_FILE
    LCOV_MERGE="$LCOV_MERGE -a $INFO_FILE"
done
lcov $LCOV_MERGE -o run-all.info
genhtml run-all.info --output-directory coverage-html
"${TPKG}" r
