project(lib) # TODO (eganian.aa@phystech.edu): come up with a good name for library

set(SOURCE_DIR source)
set(INCLUDE_DIR include)

set(SOURCE 
    ${SOURCE_DIR}/AES128_cryptor.cpp
    ${SOURCE_DIR}/RSA_cryptor.cpp
    ${SOURCE_DIR}/SHA256_hash.cpp
)
set(INCLUDE 
    ${INCLUDE_DIR}/cryptor.h
    ${INCLUDE_DIR}/data.h
    ${INCLUDE_DIR}/file_data.h
    ${INCLUDE_DIR}/types.h
    ${INCLUDE_DIR}/AES128_cryptor.h
    ${INCLUDE_DIR}/RSA_cryptor.h
    ${INCLUDE_DIR}/double_cryptor.h
    ${INCLUDE_DIR}/hash.h
    ${INCLUDE_DIR}/SHA256_hash.h
    ${INCLUDE_DIR}/signature.h
    ${INCLUDE_DIR}/hash_based_signature.h
    ${INCLUDE_DIR}/PGP_cryptor.h
)

add_library(${PROJECT_NAME} SHARED ${SOURCE} ${INCLUDE})

target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC nlohmann_json::nlohmann_json)  # JSON lib for JsonData class
target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::SSL)                  # OpenSSL for
target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto)               # crypting
target_link_libraries(${PROJECT_NAME} PUBLIC Threads::Threads)              # required for Boost lib
target_link_libraries(${PROJECT_NAME} PUBLIC OpenCL::OpenCL)                # required for OpenCL lib
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)
