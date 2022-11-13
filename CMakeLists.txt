cmake_minimum_required(VERSION 3.1)
project(userDataCollector)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

message(STATUS "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# lib & its dependencies
add_subdirectory(3rd_party/json)
add_subdirectory(3rd_party/openssl-cmake)

# Boost it quite difficult to install locally, so consider it is installed on the system
find_package(Boost 1.7 REQUIRED COMPONENTS regex system)
if(Boost_FOUND)
  message(STATUS "Boost lib found!")
else()
  message(FATAL_ERROR "Boost lib can't be found!")
endif()

add_subdirectory(lib)

add_subdirectory(server)
add_subdirectory(client)

if (DEFINED WITH_TESTS)
  add_subdirectory(3rd_party/googletest)
  enable_testing()
  
  add_subdirectory(tests)
endif()
