#!/bin/sh

export SRCDIR=`dirname $0`
. `dirname $0`/setup-env.sh

control_c()
# run if user hits control-c
{
  echo -en "\n*** Exiting ***\n"
  exit $?
}


for TEST_PKG in ${SRCDIR}/*.tpkg
do
	"${TPKG}" $* exe "${TEST_PKG}"
	# trap keyboard interrupt (control-c)
	trap control_c 2
done
"${TPKG}" -n -1 r
