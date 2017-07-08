set(CMAKE_CXX_STANDARD 11)

if (UNIX)
  set(BOOST_INCLUDEDIR "/usr/local/Cellar/boost/1.64.0_1/include")
  set(BOOST_LIBRARYDIR "/usr/local/Cellar/boost/1.64.0_1/lib")
endif()

find_package(Boost 1.6 REQUIRED COMPONENTS system thread date_time)

include_directories(${Boost_INCLUDE_DIRS})
set(EXTRA_LIBS ${EXTRA_LIBS} ${Boost_LIBRARIES})

add_library(message message.cpp)
target_link_libraries(message ${EXTRA_LIBS})
target_compile_features(message PRIVATE cxx_range_for)
install (TARGETS message
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)