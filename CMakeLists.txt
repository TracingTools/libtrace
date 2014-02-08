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

if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D USE_ETW_PARSER")
endif()

# Add thread library.
if(MSVC)
  set(PTHREAD_LIB "")
else()
  set(PTHREAD_LIB "pthread")
endif()

# TODO(etienneb): Detect gmock installation automatically.
set(GMOCK_ROOT "third_party/gmock")

# Includes search path
include_directories(
    ${GMOCK_ROOT}/include
    ${GMOCK_ROOT}
    ${GMOCK_ROOT}/gtest/include
    ${GMOCK_ROOT}/gtest
    src
    )

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
    )
    
add_custom_target(flyweight SOURCES
    src/flyweight/flyweight.h
    src/flyweight/flyweight_key.h
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
    base)

add_library(parser
    src/parser/decoder.cc
    src/parser/decoder.h
    src/parser/parser.cc
    src/parser/parser.h
    )
target_link_libraries(parser
    base
    event
    )

####################
# Executables
####################

# TODO(etienneb): Plug executables here.

####################
# Unittests
####################

add_executable(unittests
    src/base/observer_unittest.cc
    src/base/logging_unittest.cc
    src/base/scoped_ptr_unittest.cc
    src/base/string_utils_unittest.cc
    src/event/event_unittest.cc
    src/event/utils_unittest.cc
    src/event/value_unittest.cc
    src/flyweight/flyweight_key_unittest.cc
    src/flyweight/flyweight_unittest.cc
    src/parser/decoder_unittest.cc
    src/parser/parser_unittest.cc
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
