cmake_minimum_required(VERSION 3.20)
project(libs3 C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Compiler warnings
add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

# Find dependencies
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

# Library sources
set(S3_SOURCES
    src/s3_crypto.c
    src/s3_xml.c
    src/s3_sigv4.c
    src/s3_http.c
    src/s3_error.c
    src/s3_client.c
    src/s3_log.c
    src/s3_retry.c
    src/s3_object.c
    src/s3_object_config.c
    src/s3_list.c
    src/s3_multipart.c
    src/s3_bucket.c
    src/s3_bucket_config.c
    src/s3_presign.c
    src/s3_select.c
    src/s3_checksum.c
    src/s3_sse.c
    src/s3_async.c
    src/s3_pool.c
    src/s3_highlevel.c
    src/s3_control.c
    src/s3_access_point.c
    src/s3_object_lambda.c
    src/s3_access_grants.c
    src/s3_mrap.c
    src/s3_batch.c
    src/s3_storage_lens.c
    src/s3_express.c
    src/s3_tables.c
    src/s3_vectors.c
    src/s3_outposts.c
)

# Shared library
add_library(s3 SHARED ${S3_SOURCES})
target_include_directories(s3 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(s3 PUBLIC CURL::libcurl Threads::Threads)

# Static library
add_library(s3_static STATIC ${S3_SOURCES})
target_include_directories(s3_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(s3_static PUBLIC CURL::libcurl Threads::Threads)
set_target_properties(s3_static PROPERTIES OUTPUT_NAME s3)

# Unit tests
add_executable(test_unit tests/test_crypto.c)
target_link_libraries(test_unit s3_static)

# Integration tests
add_executable(test_integration tests/test_integration.c)
target_link_libraries(test_integration s3_static)

# Examples
file(GLOB EXAMPLE_SOURCES examples/*.c)
foreach(example_src ${EXAMPLE_SOURCES})
    get_filename_component(example_name ${example_src} NAME_WE)
    add_executable(${example_name} ${example_src})
    target_link_libraries(${example_name} s3_static)
endforeach()
