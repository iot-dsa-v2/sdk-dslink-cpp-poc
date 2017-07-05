cmake_minimum_required(VERSION 3.7)

project (sdk-dslink-cpp-poc)

set(CMAKE_CXX_STANDARD 11)

set (Boost_DEBUG ON)

set (Boost_NO_SYSTEM_PATHS ON)
set (Boost_USE_STATIC_LIBS OFF)
set (Boost_USE_MULTITHREAD ON)
set (Boost_USE_STATIC_RUNTIME OFF)


find_package(OpenSSL REQUIRED)
# include_directories(${OPENSSL_INCLUDE_DIR})
set(EXTRA_LIBS ${EXTRA_LIBS} ${OPENSSL_LIBRARIES})

find_package(Boost 1.6 REQUIRED system)
include_directories(${Boost_INCLUDE_DIRS})
set(EXTRA_LIBS ${EXTRA_LIBS} ${Boost_LIBRARIES})

set (SOURCE_FILES
	message.cpp
	connection.cpp)
add_executable(xyz ${SOURCE_FILES})
target_link_libraries(xyz ${EXTRA_LIBS})

# target_compile_features(client PRIVATE cxx_range_for)
