add_library(message message.cpp)
target_link_libraries(message ${EXTRA_LIBS})
target_compile_features(message PRIVATE cxx_range_for)
install (TARGETS message
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)