project(client)

set(SOURCE_DIR source)
set(INCLUDE_DIR include)

set(SOURCE ${SOURCE_DIR}/)

add_executable(${PROJECT_NAME} ${SOURCE})
target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIR})
