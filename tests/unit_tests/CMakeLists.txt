project(unit_tests)

set(SRC_DIR source)
set(INCLUDE_DIR include)

set(SRC 
    ${SRC_DIR}/main.cpp 
    ${SRC_DIR}/data_tests.cpp
    ${SRC_DIR}/cryptor_tests.cpp
)

add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME} PUBLIC gtest gtest_main)
target_link_libraries(${PROJECT_NAME} PUBLIC lib)

target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR})
set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_test(${PROJECT_NAME} ${PROJECT_NAME})

add_executable(measure ${SRC_DIR}/measure.cpp)
target_link_libraries(measure PUBLIC lib)

target_include_directories(measure PUBLIC ${INCLUDE_DIR})
set_target_properties(measure PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

file(COPY analyze_measure.py DESTINATION ${CMAKE_BINARY_DIR}/bin)
if (UNIX)
    file(COPY generate_random_files.sh DESTINATION ${CMAKE_BINARY_DIR}/bin)
    file(COPY measure_gpg.sh DESTINATION ${CMAKE_BINARY_DIR}/bin)
    file(COPY run_measure.sh DESTINATION ${CMAKE_BINARY_DIR}/bin)
endif() # TODO (eganian.aa@phystech.edu): create script for Windows
