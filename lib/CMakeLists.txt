project(lib) # TODO (eganian.aa@phystech.edu): come up with a good name for library

set(SOURCE_DIR source)
set(INCLUDE_DIR include)

set(SOURCE ${SOURCE_DIR}/)
set(INCLUDE 
    ${INCLUDE_DIR}/data.h
    ${INCLUDE_DIR}/types.h
)

add_library(${PROJECT_NAME} STATIC ${SOURCE})
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR})
