project(unit_tests)

set(SRC_DIR source)
set(INCLUDE_DIR include)

set(SRC ${SRC_DIR}/main.cpp ${SRC_DIR}/file_data_tests.cpp)

add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME} PUBLIC gtest gtest_main)
target_link_libraries(${PROJECT_NAME} PUBLIC lib)

target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR})

add_test(${PROJECT_NAME} ${PROJECT_NAME})