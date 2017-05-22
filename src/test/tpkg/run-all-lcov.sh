#!/bin/sh

export SRCDIR=`dirname $0`
. `dirname $0`/setup-env.sh

control_c()
# run if user hits control-c
{
  echo -en "\n*** Exiting ***\n"
  exit $?
}


LCOV_MERGE=""
for TEST_PKG in ${SRCDIR}/*.tpkg
do
    # when we run our test, we need to compile with profiling
    LDFLAGS="-lgcov --coverage" CFLAGS="-g -fprofile-arcs -ftest-coverage -O0" "${TPKG}" $* exe "${TEST_PKG}"
    # after the test is complete, we need to collect the coverage data
    INFO_FILE=`echo $TEST_PKG | sed 's/.tpkg$//'`.info
    geninfo $SRCDIR/.. -o $INFO_FILE
    [ -s $INFO_FILE ] && LCOV_MERGE="$LCOV_MERGE -a $INFO_FILE"
    # trap keyboard interrupt (control-c)
    trap control_c 2
done
lcov $LCOV_MERGE -o run-all.info
genhtml run-all.info --output-directory coverage-html
"${TPKG}" r
