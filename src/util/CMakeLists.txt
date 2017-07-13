add_library(dsa_util buffer.cc)
install (TARGETS dsa_util
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
