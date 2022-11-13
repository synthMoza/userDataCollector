project(lib) # TODO (eganian.aa@phystech.edu): come up with a good name for library

set(SOURCE_DIR source)
set(INCLUDE_DIR include)

set(SOURCE ${SOURCE_DIR}/)
set(INCLUDE 
    ${INCLUDE_DIR}/cryptor.h
    ${INCLUDE_DIR}/data.h
    ${INCLUDE_DIR}/file_data.h
    ${INCLUDE_DIR}/types.h
)

add_library(${PROJECT_NAME} SHARED ${SOURCE} ${INCLUDE})

target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC nlohmann_json::nlohmann_json) # JSON lib for JsonData class
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)
