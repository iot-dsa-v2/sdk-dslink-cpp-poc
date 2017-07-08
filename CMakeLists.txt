cmake_minimum_required(VERSION 3.7)
project(sdk-dslink-cpp-poc)

set(CMAKE_CXX_STANDARD 11)

set(PROJECT_SOURCE_DIR src)

option(USE_SSL "use secure tcp" OFF)

if (USE_SSL)
  add_definitions(-DUSE_SSL=true)
endif(USE_SSL)

add_subdirectory("${PROJECT_SOURCE_DIR}/client")
add_subdirectory("${PROJECT_SOURCE_DIR}/server")
add_subdirectory("${PROJECT_SOURCE_DIR}/crypto")
add_subdirectory("${PROJECT_SOURCE_DIR}/message")
add_subdirectory("${PROJECT_SOURCE_DIR}/main")