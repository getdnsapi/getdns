#!/bin/sh

make clean || true
rm -fr CMakeCache.txt *_out valgrind.log
