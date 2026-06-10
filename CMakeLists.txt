cmake_minimum_required(VERSION 3.20)
project(libs3 C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(CURL REQUIRED)

add_compile_options(-Wall -Wextra -Wpedantic)

# --- optional coverage instrumentation -------------------------------
# Applied globally before targets. All tests link the single s3_test
# library, so libs3.c has one instrumented instance -> the lcov number
# is the true union across the whole suite (no multi-instance merge).
option(LIBS3_COVERAGE "Build with gcov/lcov coverage instrumentation" OFF)
if(LIBS3_COVERAGE)
  add_compile_options(--coverage -O0 -g)
  add_link_options(--coverage)
endif()

# --- library (static + shared) ---------------------------------------
add_library(s3 STATIC libs3.c)
target_link_libraries(s3 PUBLIC CURL::libcurl)
target_include_directories(s3 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
find_package(Threads REQUIRED)
target_link_libraries(s3 PUBLIC Threads::Threads)

add_library(s3_shared SHARED libs3.c)
set_target_properties(s3_shared PROPERTIES OUTPUT_NAME s3)
target_link_libraries(s3_shared PUBLIC CURL::libcurl Threads::Threads)
target_include_directories(s3_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# --- optional sanitizer builds ---------------------------------------
# ASan/UBSan work with the default compiler (gcc or clang).
option(LIBS3_ASAN "Build with Address/UB sanitizers" OFF)
if(LIBS3_ASAN)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

# ThreadSanitizer: configure with a clang toolchain, e.g.
#   cmake -S . -B build-tsan -DLIBS3_TSAN=ON \
#     -DCMAKE_C_COMPILER=clang-21
option(LIBS3_TSAN "Build with ThreadSanitizer (use a clang compiler)" OFF)
if(LIBS3_TSAN)
  add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g -O1)
  add_link_options(-fsanitize=thread)
endif()

# TypeSanitizer (LLVM >= 21): strict-aliasing / type-confusion checker.
#   cmake -S . -B build-tysan -DLIBS3_TYSAN=ON \
#     -DCMAKE_C_COMPILER=clang-21
option(LIBS3_TYSAN "Build with TypeSanitizer (clang >= 21)" OFF)
if(LIBS3_TYSAN)
  add_compile_options(-fsanitize=type -fno-omit-frame-pointer -g -O1)
  add_link_options(-fsanitize=type)
endif()

# --- tests -----------------------------------------------------------
enable_testing()

add_executable(test_url test/test_url.c)
target_link_libraries(test_url PRIVATE s3_test)
add_test(NAME url COMMAND test_url)

# White-box tests reach internal helpers via libs3_internal.h. They link
# a dedicated static lib built with -DLIBS3_TESTING (widens 6 helper
# symbols to external linkage); production s3/s3_shared are unaffected.
# One instrumented translation unit -> trustworthy coverage numbers.
add_library(s3_test STATIC libs3.c)
target_compile_definitions(s3_test PUBLIC LIBS3_TESTING)
target_link_libraries(s3_test PUBLIC CURL::libcurl Threads::Threads)
target_include_directories(s3_test PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_parsers test/test_parsers.c)
target_link_libraries(test_parsers PRIVATE s3_test)
add_test(NAME parsers COMMAND test_parsers)

add_executable(test_live_s3 test/test_live_s3.c)
target_link_libraries(test_live_s3 PRIVATE s3_test)
add_test(NAME live_s3 COMMAND test_live_s3)

add_executable(test_creds test/test_creds.c)
target_link_libraries(test_creds PRIVATE s3_test)
add_test(NAME creds COMMAND test_creds)

add_executable(test_minio test/test_minio.c)
target_link_libraries(test_minio PRIVATE s3_test)
add_test(NAME minio COMMAND test_minio)

add_executable(test_api test/test_api.c)
target_link_libraries(test_api PRIVATE s3_test)
add_test(NAME api COMMAND test_api)

# Live-network bench (not a ctest test): build/bench_ranged
add_executable(bench_ranged test/bench_ranged.c)
target_link_libraries(bench_ranged PRIVATE s3)

# Mock-IMDS: runs anywhere (local metadata server, no EC2).
add_executable(test_imds_mock test/test_imds_mock.c)
target_link_libraries(test_imds_mock PRIVATE s3_test)
add_test(NAME imds_mock COMMAND test_imds_mock)

# Real-EC2 IMDSv2 test: self-skips unless LIBS3_IMDS=1 on an instance
# with an IAM role. Links the production lib (no test hooks needed).
add_executable(test_imds_ec2 test/test_imds_ec2.c)
target_link_libraries(test_imds_ec2 PRIVATE s3)
add_test(NAME imds_ec2 COMMAND test_imds_ec2)

# Concurrency stress (shared client, abort races) -- run under TSan.
add_executable(test_concurrency test/test_concurrency.c)
target_link_libraries(test_concurrency PRIVATE s3_test)
add_test(NAME concurrency COMMAND test_concurrency)

# --- examples --------------------------------------------------------
add_executable(cat_object examples/cat_object.c)
target_link_libraries(cat_object PRIVATE s3)

add_executable(list_bucket examples/list_bucket.c)
target_link_libraries(list_bucket PRIVATE s3)

# --- coverage report target ------------------------------------------
# `cmake --build build-cov --target coverage` runs the test suite and
# writes an lcov HTML report to build-cov/coverage/index.html plus a
# text summary. Requires -DLIBS3_COVERAGE=ON at configure time.
if(LIBS3_COVERAGE)
  find_program(LCOV lcov REQUIRED)
  find_program(GENHTML genhtml REQUIRED)
  add_custom_target(coverage
    COMMAND ${LCOV} --directory . --zerocounters --quiet
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure || true
    COMMAND ${LCOV} --directory . --capture
            --output-file coverage.info --quiet
            --ignore-errors mismatch,negative,unused
    # keep only libs3.c; drop test harness + system headers
    COMMAND ${LCOV} --extract coverage.info "*/libs3.c"
            --output-file coverage.info --quiet
            --ignore-errors unused
    COMMAND ${GENHTML} coverage.info --output-directory coverage
            --quiet --ignore-errors source
    COMMAND ${LCOV} --list coverage.info
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running tests and generating lcov coverage report"
    USES_TERMINAL)
endif()
