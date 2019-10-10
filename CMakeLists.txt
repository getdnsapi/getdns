cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

set(CMAKE_VERBOSE_MAKEFILE_ON)

# The following must be set BEFORE doing project() or enable_language().
if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type defined; defaulting to 'Debug'")
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING
    "The type of build. Possible values are: Debug, Release, RelWithDebInfo and MinSizeRel.")
endif()

set(PACKAGE "getdns")
set(PACKAGE_NAME "getdns")
set(PACKAGE_VERSION "1.5.2")
set(PACKAGE_BUGREPORT "team@getdnsapi.net")
set(PACKAGE_URL "https://getdnsapi.net")

set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
set(PACKAGE_TARNAME "${PACKAGE}-${PACKAGE_VERSION}")

# Dont forget to put a dash in front of the release candidate!!!
# That is how it is done with semantic versioning!
set(RELEASE_CANDIDATE "")

set(GETDNS_VERSION "${PACKAGE_VERSION}${RELEASE_CANDIDATE}")
set(GETDNS_NUMERIC_VERSION 0x01050200)
set(API_VERSION "December 2015")
set(API_NUMERIC_VERSION 0x07df0c00)
set(GETDNS_COMPILATION_COMMENT "${PACKAGE_NAME} ${GETDNS_VERSION} configured on <date> for the ${API_VERSION} of the API")

set(GETDNS_LIBVERSION "11:2:1")

include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckTypeSize)

project(getdns VERSION ${PACKAGE_VERSION})

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(PkgConfig)

# Directories
include(GNUInstallDirs)

if (DEFINED CMAKE_INSTALL_FULL_RUNSTATEDIR)
  set(RUNSTATEDIR "${CMAKE_INSTALL_FULL_RUNSTATEDIR}")
else ()
  set(RUNSTATEDIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/run")
endif ()
install(
  DIRECTORY
  DESTINATION ${RUNSTATEDIR}
  DIRECTORY_PERMISSIONS
  OWNER_READ OWNER_WRITE OWNER_EXECUTE
  GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE
  )

# Always have build dir as an include directory.
include_directories(
  ${CMAKE_CURRENT_BINARY_DIR}
  )

# Target Platform
if (WIN32 OR MINGW OR MSYS OR CYGWIN)
  set(HOSTOS "windows")
  set(GETDNS_ON_WINDOWS 1)
elseif (APPLE)
  set(HOSTOS "macos")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DARWIN_C_SOURCE")
elseif (UNIX)
  set(HOSTOS "unix")

  if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(LINUX 1)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_BSD_SOURCE -D_DEFAULT_SOURCE")
  elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Solaris")
    set(SOLARIS 1)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__EXTENSIONS_")
  endif()
endif ()

# File locations
set(TRUST_ANCHOR_FILE "${CMAKE_INSTALL_FULL_SYSCONF_DIR}/unbound/getdns-root.key")
set(GETDNS_FN_RESOLVCONF "${CMAKE_INSTALL_FULL_SYSCONF_DIR}/resolv.conf")
if (WIN32)
  # BUG! Don't hardcode the Windows directory and drive.
  set(GETDNS_FN_HOSTS "C:/Windows/System32/Drivers/etc/hosts")
else()
  set(GETDNS_FN_HOSTS "${CMAKE_INSTALL_FULL_SYSCONF_DIR}/hosts")
endif()

# Options.
set(DNSSEC_ROADBLOCK_AVOIDANCE 1)        # Nail on, as build fails if off.
set(STUB_NATIVE_DNSSEC 1)                # Nail on for now.
set(MAXIMUM_UPSTREAM_OPTION_SPACE 3000)
set(EDNS_PADDING_OPCODE 12)
set(MAX_CNAME_REFERRALS 100)
set(DRAFT_RRTYPES 1)
set(EDNS_COOKIE_OPCODE 10)
set(EDNS_COOKIE_ROLLOVER_TIME "(24*60*60)")
set(UDP_MAX_BACKOFF 1000)

# Does the compiler accept the "format" attribute?
try_compile(HAVE_ATTR_FORMAT
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tests/test_format_attr.c
  )
# Does the compiler accept the "unused" attribute?
try_compile(HAVE_ATTR_UNUSED
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tests/test_unused_attr.c
  )

# Compiler flags

# Check for include files
check_include_file(assert.h HAVE_ASSERT_H)
check_include_file(inttypes.h HAVE_INTTYPES_H)
check_include_file(limits.h HAVE_LIMITS_H)
check_include_file(sys/limits.h HAVE_SYS_LIMITS_H)
check_include_file(stdarg.h HAVE_STDARG_H)
check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(stdio.h HAVE_STDIO_H)
check_include_file(stdlib.h HAVE_STDLIB_H)
check_include_file(string.h HAVE_STRING_H)
check_include_file(time.h HAVE_TIME_H)
check_include_file(unistd.h HAVE_UNISTD_H)

check_include_file(fcntl.h HAVE_FCNTL_H)

check_include_file(signal.h HAVE_SIGNAL_H)
check_include_file(sys/poll.h HAVE_SYS_POLL_H)
check_include_file(poll.h HAVE_POLL_H)
check_include_file(resource.h HAVE_RESOURCE_H)
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(sys/stat.h HAVE_SYS_STAT_H)

check_include_file(netinet/in.h HAVE_NETINET_IN_H)
check_include_file(arpa/inet.h HAVE_ARPA_INET_H)
check_include_file(netdb.h HAVE_NETDB_H)
check_include_file(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_file(sys/time.h HAVE_SYS_TIME_H)
check_include_file(sys/select.h HAVE_SYS_SELECT_H)
check_include_file(endian.h HAVE_ENDIAN_H)
check_include_file(sys/wait.h HAVE_SYS_WAIT_H)

check_include_file(windows.h HAVE_WINDOWS_H)
check_include_file(winsock.h HAVE_WINSOCK_H)
check_include_file(winsock2.h HAVE_WINSOCK2_H)
check_include_file(ws2tcpip.h HAVE_WS2TCPIP_H)

# Check for include declarations
check_symbol_exists(inet_pton arpa/inet.h HAVE_DECL_INET_PTON)
check_symbol_exists(inet_ntop arpa/inet.h HAVE_DECL_INET_NTOP)
check_symbol_exists(sigemptyset signal.h HAVE_DECL_SIGEMPTYSET)
check_symbol_exists(sigfillset signal.h HAVE_DECL_SIGFILLSET)
check_symbol_exists(sigaddset signal.h HAVE_DECL_SIGADDSET)
check_symbol_exists(strptime time.h HAVE_DECL_STRPTIME)

# Check for functions
check_function_exists(fcntl HAVE_FCNTL)
check_function_exists(inet_pton HAVE_INET_PTON)
check_function_exists(inet_ntop HAVE_INET_NTOP)
check_function_exists(ioctlsocket HAVE_IOCTLSOCKET)
check_function_exists(sigemptyset HAVE_SIGEMPTYSET)
check_function_exists(sigfillset HAVE_SIGFILLSET)
check_function_exists(sigaddset HAVE_SIGADDSET)
check_function_exists(strptime HAVE_STRPTIME)

# Check for types
check_type_size(sigset_t SIGSET_T)
check_type_size(_sigset_t _SIGSET_T)

# SSL library
find_package(OpenSSL "1.0.2" REQUIRED)

set(HAVE_SSL 1)

set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
check_include_file(openssl/ssl.h HAVE_OPENSSL_SSL_H)
check_include_file(openssl/evp.h HAVE_OPENSSL_EVP_H)
check_include_file(openssl/err.h HAVE_OPENSSL_ERR_H)
check_include_file(openssl/rand.h HAVE_OPENSSL_RAND_H)
check_include_file(openssl/conf.h HAVE_OPENSSL_CONF_H)
check_include_file(openssl/engine.h HAVE_OPENSSL_ENGINE_H)

set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
check_function_exists(DSA_SIG_set0 HAVE_DSA_SIG_SET0)
check_function_exists(DSA_set0_pqg HAVE_DSA_SET0_PQG)
check_function_exists(DSA_set0_key HAVE_DSA_SET0_KEY)

check_function_exists(RSA_set0_key HAVE_RSA_SET0_KEY)

check_function_exists(EVP_md5 HAVE_EVP_MD5)
check_function_exists(EVP_sha1 HAVE_EVP_SHA1)
check_function_exists(EVP_sha224 HAVE_EVP_SHA224)
check_function_exists(EVP_sha256 HAVE_EVP_SHA256)
check_function_exists(EVP_sha384 HAVE_EVP_SHA384)
check_function_exists(EVP_sha512 HAVE_EVP_SHA512)

check_function_exists(EVP_dss1 HAVE_EVP_DSS1)
check_function_exists(EVP_DigestVerify HAVE_EVP_DIGESTVERIFY)

check_function_exists(EVP_MD_CTX_new HAVE_EVP_MD_CTX_NEW)

check_function_exists(HMAC_CTX_new HAVE_HMAC_CTX_NEW)

check_function_exists(TLS_client_method HAVE_TLS_CLIENT_METHOD)

check_function_exists(OpenSSL_version_num HAVE_OPENSSL_VERSION_NUM)
check_function_exists(OpenSSL_version HAVE_OPENSSL_VERSION)

check_function_exists(SSL_CTX_dane_enable HAVE_SSL_CTX_DANE_ENABLE)

check_function_exists(SSL_CTX_set_ciphersuites HAVE_SSL_CTX_SET_CIPHERSUITES)
check_function_exists(SSL_set_ciphersuites HAVE_SSL_SET_CIPHERSUITES)

check_function_exists(OPENSSL_init_crypto HAVE_OPENSSL_INIT_CRYPTO)

check_symbol_exists(SSL_dane_enable "openssl/ssl.h" HAVE_SSL_DANE_ENABLE)
check_symbol_exists(SSL_CTX_set1_curves_list "openssl/ssl.h" HAVE_DECL_SSL_CTX_SET1_CURVES_LIST)
check_symbol_exists(SSL_set1_curves_list "openssl/ssl.h" HAVE_DECL_SSL_SET1_CURVES_LIST)
check_symbol_exists(SSL_set_min_proto_version "openssl/ssl.h" HAVE_DECL_SSL_SET_MIN_PROTO_VERSION)
check_symbol_exists(X509_get_notAfter "openssl/x509.h" HAVE_X509_GET_NOTAFTER)
check_symbol_exists(X509_get0_notAfter "openssl/x509.h" HAVE_X509_GET0_NOTAFTER)


# Threading library
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

if (CMAKE_USE_PTHREADS_INIT)
  set(HAVE_PTHREAD 1)
elseif (CMAKE_USE_WIN32_THREADS_INIT)
  set(HAVE_WINDOWS_THREADS 1)
else()
  message(WARNING "Neither pthreads nor Windows threading available.")
endif()

# Stuff that might be in a BSD library
check_symbol_exists(strlcpy string.h HAVE_DECL_STRLCPY)
check_symbol_exists(arc4random stdlib.h HAVE_DECL_ARC4RANDOM)
check_symbol_exists(arc4random_uniform stdlib.h HAVE_DECL_ARC4RANDOM_UNIFORM)

check_function_exists(strlcpy HAVE_STRLCPY)
check_function_exists(arc4random HAVE_ARC4RANDOM)
check_function_exists(arc4random_uniform HAVE_ARC4RANDOM_UNIFORM)

if (NOT
    (HAVE_STRLCPY AND HAVE_DECL_STRLCPY AND
     HAVE_ARC4RANDOM AND HAVE_DECL_ARC4RANDOM AND
     HAVE_ARC4RANDOM_UNIFORM AND HAVE_DECL_ARC4RANDOM_UNIFORM))
  pkg_check_modules(LIBBSD libbsd)
  set(CMAKE_REQUIRED_FLAGS "${LIBBSD_CFLAGS} ${LIBBSD_LDFLAGS}")
  set(CMAKE_REQUIRED_INCLUDES ${LIBBSD_INCLUDE_DIRS})
  set(CMAKE_REQUIRED_LIBRARIES ${LIBBSD_LIBRARIES})

  check_symbol_exists(strlcpy bsd/string.h HAVE_DECL_STRLCPY)
  check_symbol_exists(arc4random bsd/stdlib.h HAVE_DECL_ARC4RANDOM)
  check_symbol_exists(arc4random_uniform bsd/stdlib.h HAVE_DECL_ARC4RANDOM_UNIFORM)

  check_function_exists(strlcpy HAVE_STRLCPY)
  check_function_exists(arc4random HAVE_ARC4RANDOM)
  check_function_exists(arc4random_uniform HAVE_ARC4RANDOM_UNIFORM)

  # TODO: Make module optional and fallback to compat versions for arc4random.
endif()

# Event loop extension
# TODO: other event loops
set(DEFAULT_EVENTLOOP "select_eventloop")
if (HAVE_SYS_POLL_H)
  set(TEST_CFLAG "HAVE_SYS_POLL_H=1")
endif()
try_compile(USE_POLL_DEFAULT_EVENTLOOP
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tests/test_poll.c
  COMPILE_DEFINITIONS "${TEST_CFLAG}"
  )
if (USE_POLL_DEFAULT_EVENTLOOP)
  set(DEFAULT_EVENTLOOP "poll_eventloop")
endif()

# Main library

set(getdns_SOURCES
  src/anchor.c
  src/const-info.c
  src/convert.c
  src/context.c
  src/dict.c
  src/dnssec.c
  src/general.c
  src/list.c
  src/request-internal.c
  src/mdns.c
  src/platform.c
  src/pubkey-pinning.c
  src/rr-dict.c
  src/rr-iter.c
  src/server.c
  src/stub.c
  src/sync.c
  src/ub_loop.c
  src/util-internal.c

  src/compat/gettimeofday.c
  src/compat/inet_pton.c
  src/compat/inet_ntop.c
  src/compat/strlcpy.c
  src/compat/strptime.c

  src/extension/${DEFAULT_EVENTLOOP}.c

  src/gldns/keyraw.c
  src/gldns/gbuffer.c
  src/gldns/wire2str.c
  src/gldns/parse.c
  src/gldns/parseutil.c
  src/gldns/rrdef.c
  src/gldns/str2wire.c

  src/util/rbtree.c
  src/util/lruhash.c
  src/util/lookup3.c
  src/util/locks.c

  src/jsmn/jsmn.c

  src/yxml/yxml.c

  src/tls/val_secalgo.c
  src/tls/anchor-internal.c

  src/openssl/tls.c
  src/openssl/pubkey-pinning-internal.c
  src/openssl/keyraw-internal.c

  ${CMAKE_CURRENT_BINARY_DIR}/version.c
  )

set(getdns_INCLUDES
  PRIVATE src
  PRIVATE src/util/auxiliary
  PRIVATE src/openssl
  PRIVATE src/tls
  PRIVATE src/yxml
  PRIVATE stubby/src    # Wrong, wrong, wrong.

  PRIVATE ${OPENSSL_INCLUDE_DIR}
  PRIVATE ${LIBBSD_INCLUDE_DIRS}
  PRIVATE Threads::Threads
  )

set(getdns_LIBS
  PUBLIC ${OPENSSL_LIBRARIES}
  PUBLIC Threads::Threads
  PUBLIC ${LIBBSD_LDFLAGS}
  PUBLIC ${LIBBSD_LIBRARIES}
  )

if (NOT HAVE_SSL_DANE_ENABLE)
  set(getdns_SOURCES
    ${getdns_SOURCES}
    src/ssl_dane/danessl.c
    )
  set(getdns_INCLUDES
    ${getdns_INCLUDES}
    PRIVATE src/ssl_dane
    )
  set(USE_DANESSL 1)
endif()

add_library(getdns ${getdns_SOURCES})
target_include_directories(getdns ${getdns_INCLUDES})
target_link_libraries(getdns ${getdns_LIBS})

set_property(TARGET getdns PROPERTY C_STANDARD 11)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/include/cmakeconfig.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/getdns/getdns.h.in ${CMAKE_CURRENT_BINARY_DIR}/getdns/getdns.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/getdns/getdns_extra.h.in ${CMAKE_CURRENT_BINARY_DIR}/getdns/getdns_extra.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version.c.in ${CMAKE_CURRENT_BINARY_DIR}/version.c)
