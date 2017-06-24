cmake_minimum_required (VERSION 3.0)

project (sdk-dslink-cpp)

set_property (GLOBAL PROPERTY USE_FOLDERS ON)

if (WIN32)

#-------------------------------------------------
# Boost
#

set (Boost_DEBUG ON) 
set (BOOST_ROOT C:\\local\\boost_1_64_0)
set (BOOST_INCLUDEDIR ${BOOST_ROOT}\\include\\boost-1_64)

set (Boost_NO_SYSTEM_PATHS ON)
set (Boost_USE_STATIC_LIBS ON)
set (Boost_USE_MULTITHREAD ON)
set (Boost_USE_STATIC_RUNTIME OFF)

set (BOOST_LIBS system)

find_package (Boost 1.64.0 REQUIRED COMPONENTS ${BOOST_LIBS})
if (Boost_FOUND)
  include_directories (${Boost_INCLUDE_DIRS})
  link_directories (${Boost_LIBRARY_DIRS})
endif (Boost_FOUND)

set (USED_LIBS ${BOOST_LIBRARIES})

#-------------------------------------------------
# Build
#

# add_executable (bt_main bt_main.cpp)
# target_link_libraries (bt_main ${USED_LIBS})

endif (WIN32)
