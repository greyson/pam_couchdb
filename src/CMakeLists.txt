add_library( pam_couch_lib STATIC
  curl.cpp
)
target_link_libraries( pam_couch_lib ${CURL_LIBRARIES} )

# Testing targets

include_directories( ${CMAKE_CURRENT_SOURCE_DIR} )

add_executable( testCouchAuth tests/testCouchAuth.cpp )
target_link_libraries( testCouchAuth pam_couch_lib )