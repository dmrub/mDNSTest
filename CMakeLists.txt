cmake_minimum_required(VERSION 2.8)

project(mDNSTest)

# User options

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" "${PROJECT_SOURCE_DIR}/cmake/modules")


# Detect compiler
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(C_IS_GNU   1)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(C_IS_GNU   1)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
  set(C_IS_INTEL 1)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  set(C_IS_MSVC  1)
endif()

# Enable C99 mode
if(C_IS_GNU)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
endif()

if(C_IS_INTEL)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -restrict")
endif()

# Enable C++11 mode
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
elseif(COMPILER_SUPPORTS_CXX0X)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
else()
  message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

# Find packages

find_package(Threads REQUIRED)
find_package(Bonjour)
find_package(Avahi)



if (BONJOUR_FOUND)
  include_directories(${BONJOUR_INCLUDE_DIR})

  add_executable(mDNSTestService testservice.cpp )
  target_link_libraries(mDNSTestService ${BONJOUR_LIBRARIES})

  add_executable(mDNSTestClient client.cpp )
  target_link_libraries(mDNSTestClient ${BONJOUR_LIBRARIES})
endif()
