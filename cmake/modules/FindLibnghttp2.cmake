#[=======================================================================[.rst:
FindLibnghttp2
-----------

Find the Libnghttp2 library

Imported targets
^^^^^^^^^^^^^^^^

This module defines the following :prop_tgt:`IMPORTED` targets:

``Libnghttp2::Libnghttp2``
  The Libnghttp2 library, if found.

Result variables
^^^^^^^^^^^^^^^^

This module will set the following variables in your project:

``Libnghttp2_FOUND``
  If false, do not try to use Libnghttp2.
``LIBNGHTTP2_INCLUDE_DIR``
  where to find libnghttp2 headers.
``LIBNGHTTP2_LIBRARIES``
  the libraries needed to use Libnghttp2.
``LIBNGHTTP2_VERSION``
  the version of the Libnghttp2 library found

#]=======================================================================]

find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
    pkg_check_modules(PkgLibNghttp2 IMPORTED_TARGET GLOBAL libnghttp2)
endif ()

if (PkgLibNghttp2_FOUND)
  set(LIBNGHTTP2_INCLUDE_DIR ${PkgLibNghttp2_INCLUDE_DIRS} CACHE FILEPATH "libnghttp2 include path")
  set(LIBNGHTTP2_LIBRARIES ${PkgLibNghttp2_LIBRARIES} CACHE STRING "libnghttp2 libraries")
  set(LIBNGHTTP2_VERSION ${PkgLibNghttp2_VERSION})
  add_library(Libnghttp2::Libnghttp2 ALIAS PkgConfig::PkgLibNghttp2)
    if (NOT TARGET Libnghttp2::Libnghttp2)
      message(STATUS "No Libnghttp2::Libnghttp2 target")
      add_library(Libnghttp2::Libnghttp2 UNKNOWN IMPORTED)
      set_target_properties(Libnghttp2::Libnghttp2 PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${LIBNGHTTP2_INCLUDE_DIR}"
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
        IMPORTED_LOCATION "${LIBNGHTTP2_LIBRARIES}"
      )
    endif ()
  set(Libnghttp2_FOUND ON)
else ()
  find_path(LIBNGHTTP2_INCLUDE_DIR nghttp2/nghttp2.h
    HINTS
      "${LIBNGHTTP2_DIR}"
      "${LIBNGHTTP2_DIR}/include"
  )

  find_library(LIBNGHTTP2_LIBRARIES NAMES nghttp2 libnghttp2
    HINTS
      "${LIBNGHTTP2_DIR}"
      "${LIBNGHTTP2_DIR}/lib"
  )

  if (LIBNGHTTP2_INCLUDE_DIR AND LIBNGHTTP2_LIBRARIES)
    if (NOT TARGET Libnghttp2::Libnghttp2)
      add_library(Libnghttp2::Libnghttp2 UNKNOWN IMPORTED)
      set_target_properties(Libnghttp2::Libnghttp2 PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${LIBNGHTTP2_INCLUDE_DIR}"
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
        IMPORTED_LOCATION "${LIBNGHTTP2_LIBRARIES}"
      )
    endif ()

    if (NOT LIBNGHTTP2_VERSION AND LIBNGHTTP2_INCLUDE_DIR AND EXISTS "${LIBNGHTTP2_INCLUDE_DIR}/nghttp2/nghttp2.h")
      file(STRINGS "${LIBNGHTTP2_INCLUDE_DIR}/nghttp2/nghttp2.h" LIBNGHTTP2_H REGEX "^[ \t]*#[ \t]*define[ \t]+NGHTTP2_VERSION[ \t]")
      string(REGEX REPLACE "^.*NGHTTP2_VERSION[ \t]+\"([0-9.]+)\".*$" "\\1" LIBNGHTTP2_VERSION "${LIBNGHTTP2_H}")
    endif ()
  endif ()
  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Libnghttp2
    REQUIRED_VARS LIBNGHTTP2_LIBRARIES LIBNGHTTP2_INCLUDE_DIR
    VERSION_VAR LIBNGHTTP2_VERSION
  )
endif ()

mark_as_advanced(LIBNGHTTP2_INCLUDE_DIR LIBNGHTTP2_LIBRARIES)
