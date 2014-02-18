project(libtrace CXX)
cmake_minimum_required(VERSION 2.6.2)

set(CMAKE_SUPPRESS_REGENERATION TRUE)

# Force pedantic and Wall flags.
if(MSVC)
  # Activate warning level 4.
  # Disable 4481 warning C4481: nonstandard extension used: override
  # specifier 'override'
  if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
    string(REGEX REPLACE "/W[0-4]" "/W4 /wd4481"
           CMAKE_CXX_FLAGS
           "${CMAKE_CXX_FLAGS}")
  else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
  endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
  # Update if necessary
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-long-long")
endif()

# Force a unicode project.
if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D _UNICODE /D UNICODE")
endif()

# Add ETW-Parser library.
if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D USE_ETW_PARSER")
  set(ETW_PARSER_SOURCES
          src/parser/etw/etw_parser.cc
          src/parser/etw/etw_parser.h
          )
  set(ETW_PARSER_UNITTEST
          src/parser/etw/etw_parser_unittest.cc
          )
else()
  set(ETW_PARSER_SOURCES "")
  set(ETW_PARSER_UNITTEST "")
endif()

# Add files of the "base" library that are specific to Windows.
if(WIN32)
  set(BASE_WIN_SOURCES
          src/base/win/scoped_handle.cc
          src/base/win/scoped_handle.h
          )
  set(BASE_WIN_UNITTEST
          src/base/win/scoped_handle_unittest.cc
          )
else()
  set(BASE_WIN_SOURCES "")
  set(BASE_WIN_UNITTEST "")
endif()

# Add thread library.
if(MSVC)
  set(PTHREAD_LIB "")
else()
  set(PTHREAD_LIB "pthread")
endif()

# Find the location of gmock library.
find_path(GMOCK_FOLDER NAMES gmock/CMakeLists.txt
          HINTS .. third_party ../third_party)
if(GMOCK_FOLDER)
  set(GMOCK_ROOT ${GMOCK_FOLDER}/gmock)
  set(GMOCK_FOUND 1)
else()
  message("gmock folder not found.")
endif(GMOCK_FOLDER)

# Add include search paths for gmock.
if(GMOCK_FOUND)
  include_directories(
      ${GMOCK_ROOT}/include
      ${GMOCK_ROOT}
      ${GMOCK_ROOT}/gtest/include
      ${GMOCK_ROOT}/gtest
      )
endif(GMOCK_FOUND)

# Add the libtrace default include paths.
include_directories(src)

####################
# Libraries
####################

add_library(base
    src/base/base.h
    src/base/observer.h
    src/base/logging.cc
    src/base/logging.h
    src/base/string_utils.cc
    src/base/string_utils.h
    src/base/scoped_ptr.h
    ${BASE_WIN_SOURCES}
    )
    
add_custom_target(flyweight SOURCES
    src/flyweight/flyweight.h
    src/flyweight/flyweight_key.h
    src/flyweight/internals/flyweight_tree_map_impl.h
    )

add_library(event
    src/event/event.cc
    src/event/event.h
    src/event/utils.cc
    src/event/utils.h
    src/event/value.cc
    src/event/value.h
    )
target_link_libraries(event
    base
    )

add_library(parser
    src/parser/decoder.cc
    src/parser/decoder.h
    src/parser/parser.cc
    src/parser/parser.h
    src/parser/etw/etw_raw_kernel_payload_decoder.cc
    src/parser/etw/etw_raw_kernel_payload_decoder.h
    src/parser/etw/etw_raw_payload_decoder_utils.cc
    src/parser/etw/etw_raw_payload_decoder_utils.h
    ${ETW_PARSER_SOURCES}
    )
target_link_libraries(parser
    base
    event
    )

####################
# Unittests
####################

if(GMOCK_FOUND)
add_executable(unittests
    src/base/observer_unittest.cc
    src/base/logging_unittest.cc
    src/base/scoped_ptr_unittest.cc
    src/base/string_utils_unittest.cc
    ${BASE_WIN_UNITTEST}
    src/event/event_unittest.cc
    src/event/utils_unittest.cc
    src/event/value_unittest.cc
    src/flyweight/flyweight_key_unittest.cc
    src/flyweight/flyweight_unittest.cc
    src/flyweight/internals/flyweight_impl_unittest.cc
    src/parser/decoder_unittest.cc
    src/parser/parser_unittest.cc
    src/parser/etw/etw_raw_kernel_payload_decoder_unittest.cc
    src/parser/etw/etw_raw_payload_decoder_utils_unittest.cc
    ${ETW_PARSER_UNITTEST}
    ${GMOCK_ROOT}/gtest/src/gtest-all.cc
    ${GMOCK_ROOT}/src/gmock-all.cc
    ${GMOCK_ROOT}/src/gmock_main.cc
    )

target_link_libraries(unittests
    base
    event
    parser
    ${PTHREAD_LIB}
    )
endif(GMOCK_FOUND)
