cmake_minimum_required(VERSION 3.1)
project(tests)

if (DEFINED WITH_PERF_TESTS)
    add_subdirectory(perf_tests)
endif()

add_subdirectory(unit_tests)
