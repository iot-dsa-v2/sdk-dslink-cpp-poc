cmake_minimum_required(VERSION 3.7)

project (sdk-dslink-cpp-poc)

set(CMAKE_CXX_STANDARD 11)

set (Boost_DEBUG ON)

set (Boost_NO_SYSTEM_PATHS ON)
set (Boost_USE_STATIC_LIBS OFF)
set (Boost_USE_MULTITHREAD ON)
set (Boost_USE_STATIC_RUNTIME OFF)

if (UNIX)
  set(OPENSSL_ROOT_DIR "/usr/local/Cellar/openssl/1.0.2l")
  set(BOOST_INCLUDEDIR "/usr/local/Cellar/boost/1.64.0_1/include")
  set(BOOST_LIBRARYDIR "/usr/local/Cellar/boost/1.64.0_1/lib")
endif()

find_package(OpenSSL REQUIRED)
find_package(Boost 1.6 REQUIRED system thread)

if (UNIX)
  include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS})
  # include_directories(${Boost_INCLUDE_DIRS})
endif()

include_directories(${CMAKE_SOURCE_DIR}/src/crypto)

set(EXTRA_LIBS ${EXTRA_LIBS} 
  ${OPENSSL_LIBRARIES}
  ${Boost_LIBRARIES}
  crypto)

# set(EXTRA_LIBS ${EXTRA_LIBS} ${Boost_LIBRARIES})

set (SOURCE_FILES
	message.cpp
	connection.cpp
	main.cpp)

add_executable(main ${SOURCE_FILES})
target_link_libraries(main ${EXTRA_LIBS})
install(TARGETS main RUNTIME DESTINATION bin)

# target_compile_features(client PRIVATE cxx_range_for)
