if (UNIX)
  set(OPENSSL_ROOT_DIR "/usr/local/Cellar/openssl/1.0.2l")
endif()

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
set(EXTRA_LIBS ${EXTRA_LIBS} ${OPENSSL_LIBRARIES})

include_directories(${CMAKE_SOURCE_DIR}/src/util)
set(EXTRA_LIBS ${EXTRA_LIBS} dsa_util)

add_library(crypto ecdh.cc hash.cc hmac.cc misc.cc)
target_link_libraries(crypto ${EXTRA_LIBS})
target_compile_features(crypto PRIVATE cxx_range_for)
install (TARGETS crypto
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
