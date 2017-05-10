#!/bin/sh

export SRCDIR=`dirname $0`
. `dirname $0`/setup-env.sh

cat > Makefile << MAKEFILE_HEADER
all: retry results

retry:
	for f in result.* ; do if test ! -e .done-\$\${f#result.} ; then rm -f \$\$f ; fi; done

MAKEFILE_HEADER

ALL="results:"
for TEST_PKG in ${SRCDIR}/*.tpkg
do
	P=${TEST_PKG#${SRCDIR}/}
	P=${P%.tpkg}
	DONE="result.$P"
	ALL="$ALL $DONE"
done
echo $ALL >> Makefile
printf '\t"%s" r\n\n' "${TPKG}" >> Makefile
printf 'clean:\n\t"%s" clean\n\trm -fr build build-stub-only build-event-loops build-static-analysis install scan-build-reports .tpkg.var.master *.info\n\n' "${TPKG}" >> Makefile
for TEST_PKG in ${SRCDIR}/*.tpkg
do
	P=${TEST_PKG#${SRCDIR}/}
	P=${P%.tpkg}
	DONE="result.$P:"
	for D in `grep "^Depends: " "${TEST_PKG}/${P}.dsc" | sed 's/^Depends: //g'`
	do
		D=${D%.tpkg}
		DONE="$DONE result.$D"
	done
	echo $DONE >> Makefile
	printf '\t"%s" %s exe "%s"\n\n' "${TPKG}" "$*" "${TEST_PKG}" >> Makefile
	echo "" >> Makefile
done
make -j 2
