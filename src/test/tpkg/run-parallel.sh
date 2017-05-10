#!/bin/sh

export SRCDIR=`dirname $0`
. `dirname $0`/setup-env.sh

cat > Makefile << MAKEFILE_HEADER
all: retry results

retry:
	for f in result.* ; do if test ! -e .done-\$\${f#result.} ; then rm -f \$\$f ; fi; done

MAKEFILE_HEADER

# Resource depletion tests should be performed one-by-one after all
# other tests have been done.
#
RD_TESTS=""
OTHERS=""
ALL="results:"
for TEST_PKG in `echo ${SRCDIR}/*.tpkg | xargs -n1 echo | sort`
do
	P="${TEST_PKG#${SRCDIR}/}"
	P="${P%.tpkg}"
	R="result.${P}"
	ALL="${ALL} ${R}"
	if grep -q 'Category:.*Resource depletion' "${TEST_PKG}/${P}.dsc"
	then
		RD_TESTS="${R} ${RD_TESTS}"
	else
		OTHERS="${OTHERS} ${R}"
	fi
done
echo "${ALL}" >> Makefile
printf '\t"%s" r\n\n' "${TPKG}" >> Makefile
printf 'clean:\n\t"%s" clean\n\trm -fr build build-stub-only build-event-loops build-static-analysis install scan-build-reports .tpkg.var.master *.info\n\n' "${TPKG}" >> Makefile
for P in ${OTHERS}
do
	P="${P#result.}"
	TEST_PKG="${SRCDIR}/${P}.tpkg"
	DEPS="result.${P}:"
	for D in `grep "^Depends: " "${TEST_PKG}/${P}.dsc" | sed 's/^Depends: //g'`
	do
		D="${D%.tpkg}"
		DEPS="${DEPS} result.${D}"
	done
	echo "${DEPS}" >> Makefile
	printf '\t"%s" %s exe "%s"\n\n' "${TPKG}" "$*" "${TEST_PKG}" >> Makefile
done
for RD in ${RD_TESTS}
do
	RD_TESTS="${RD_TESTS#$RD }"
	TEST_PKG="${RD#result.}"
	printf '%s: %s %s\n\t"%s" %s exe "%s/%s.tpkg"\n\n' "${RD}" "${OTHERS}" "${RD_TESTS}" "${TPKG}" "$*" "${SRCDIR}" "${TEST_PKG}" >> Makefile
done
make -j 2
