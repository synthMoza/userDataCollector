project(perf_tests)

set(SRC_DIR source)
set(INCLUDE_DIR include)

set(SRC 
    ${SRC_DIR}/main.cpp
    ${SRC_DIR}/cryptors_bench.cpp
)

add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME} PUBLIC benchmark::benchmark)
target_link_libraries(${PROJECT_NAME} PUBLIC lib)

target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR})
set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_test(${PROJECT_NAME} ${PROJECT_NAME})