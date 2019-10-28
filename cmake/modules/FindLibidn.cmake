#[=======================================================================[.rst:
FindLibidn
----------

Find the Libidn library

Imported targets
^^^^^^^^^^^^^^^^

This module defines the following :prop_tgt:`IMPORTED` targets:

``Libidn::Libidn``
  The Libidn library, if found.

Result variables
^^^^^^^^^^^^^^^^

This module will set the following variables in your project:

``Libidn_FOUND``
  If false, do not try to use Libidn.
``LIBIDN_INCLUDE_DIR``
  where to find check.h, etc.
``LIBIDN_LIBRARIES``
  the libraries needed to use Libidn.

#]=======================================================================]

find_path(LIBIDN_INCLUDE_DIR idna.h
  HINTS
  "${LIBIDN_DIR}"
  "${LIBIDN_DIR}/include"
)

find_library(LIBIDN_LIBRARY NAMES idn
  HINTS
  "${LIBIDN_DIR}"
  "${LIBIDN_DIR}/lib"
)

set(LIBIDN_LIBRARIES "")

if (LIBIDN_INCLUDE_DIR AND LIBIDN_LIBRARY)
  if (NOT TARGET Libidn::Libidn)
    add_library(Libidn::Libidn UNKNOWN IMPORTED)
    set_target_properties(Libidn::Libidn PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${LIBIDN_INCLUDE_DIR}"
      IMPORTED_LINK_INTERFACE_LANGUAGES "C"
      IMPORTED_LOCATION "${LIBIDN_LIBRARY}"
      )
  endif()
endif()

list(APPEND LIBIDN_LIBRARIES "${LIBIDN_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libidn
  REQUIRED_VARS LIBIDN_LIBRARIES LIBIDN_INCLUDE_DIR
  )

mark_as_advanced(LIBIDN_INCLUDE_DIR LIBIDN_LIBRARIES LIBIDN_LIBRARY)
