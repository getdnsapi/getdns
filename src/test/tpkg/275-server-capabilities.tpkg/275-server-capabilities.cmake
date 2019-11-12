cmake_minimum_required(VERSION 3.5)
project (@TPKG_NAME@)
add_executable(@TPKG_NAME@ @TPKG_NAME@.c)

target_include_directories(@TPKG_NAME@ PRIVATE @BUILDDIR@)

add_library(libgetdns SHARED IMPORTED )
set_target_properties(libgetdns PROPERTIES IMPORTED_LOCATION @BUILDDIR@/libgetdns.dylib )
target_link_libraries(@TPKG_NAME@ libgetdns)