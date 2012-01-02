project( pam_couchdb CXX )

cmake_minimum_required( VERSION 2.6 )

list( APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules/ )

find_package( CURL REQUIRED )

#include( Dejagnu )

include_directories(
  ${CURL_INCLUDE_DIRS}
)

link_directories(
  ${CURL_LIBRARY_DIRS}
)

add_subdirectory( src )