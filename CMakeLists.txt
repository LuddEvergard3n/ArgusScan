cmake_minimum_required(VERSION 3.20)

project(ArgusScan VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(ARGUS_BUILD_TESTS "Build ArgusScan unit tests" ON)

add_library(argus_core STATIC
    src/engine/port_state.c
    src/engine/timing.c
    src/net/checksum.c
)

target_include_directories(argus_core PUBLIC src)

if(MSVC)
    target_compile_options(argus_core PRIVATE /W4 /WX)
else()
    target_compile_options(argus_core PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        -Werror
    )
endif()

add_executable(argusscan src/main.c)
target_link_libraries(argusscan PRIVATE argus_core)

if(MSVC)
    target_compile_options(argusscan PRIVATE /W4 /WX)
else()
    target_compile_options(argusscan PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        -Werror
    )
endif()

if(ARGUS_BUILD_TESTS)
    enable_testing()

    add_executable(argus_unit_tests
        tests/test_main.c
        tests/test_checksum.c
        tests/test_engine.c
    )
    target_link_libraries(argus_unit_tests PRIVATE argus_core)

    if(MSVC)
        target_compile_options(argus_unit_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(argus_unit_tests PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wshadow
            -Werror
        )
    endif()

    add_test(NAME argus_unit_tests COMMAND argus_unit_tests)
endif()

