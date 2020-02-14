#!/bin/sh

export SRCDIR=`dirname $0`
. `dirname $0`/setup-env.sh

control_c()
# run if user hits control-c
{
  echo -en "\n*** Exiting ***\n"
  exit $?
}

for TEST_PKG in 080-iana-rr-types.tpkg 125-valgrind-checks.tpkg \
	    130-run-unit-tests.tpkg 225-stub-only-valgrind-checks.tpkg \
	    230-stub-only-run-unit-tests.tpkg 270-header-extension.tpkg \
	    290-transports.tpkg 330-event-loops-unit-tests.tpkg \
	    340-run-stubby.tpkg
do
	"${TPKG}" $* fake "${TEST_PKG}"
done
for TEST_PKG in ${SRCDIR}/*.tpkg
do
	"${TPKG}" $* exe "${TEST_PKG}"
	# trap keyboard interrupt (control-c)
	trap control_c 2
done
"${TPKG}" -n -1 r
