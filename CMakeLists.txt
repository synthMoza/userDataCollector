cmake_minimum_required(VERSION 3.10)

# Set flags for Release/Debug
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

add_subdirectory(lib) # lib will be used by client & server, build it first
add_subdirectory(server)
add_subdirectory(client)
