cmake_minimum_required(VERSION 3.20)

project(ArgusScan VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_compile_definitions(_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)

option(ARGUS_BUILD_TESTS "Build ArgusScan unit tests" ON)

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)

add_library(argus_core STATIC
    src/engine/port_list.c
    src/engine/port_state.c
    src/engine/thread_pool.c
    src/engine/target_parser.c
    src/engine/timing.c
    src/fingerprint/os_detect.c
    src/fingerprint/service_detect.c
    src/net/checksum.c
    src/net/packet_builder.c
    src/net/packet_capture.c
    src/net/packet_parser.c
    src/net/raw_socket.c
    src/net/route.c
    src/net/target_resolver.c
    src/output/report.c
    src/scan/connect_engine.c
    src/scan/raw_tcp.c
    src/scan/response_classifier.c
    src/scan/tcp_connect.c
    src/scan/udp.c
)

target_include_directories(argus_core PUBLIC src)
target_link_libraries(argus_core PUBLIC Threads::Threads PkgConfig::PCAP)

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
        tests/test_capture_frame.c
        tests/test_connect.c
        tests/test_engine.c
        tests/test_os_detect.c
        tests/test_response_classifier.c
        tests/test_packet.c
        tests/test_service.c
        tests/test_port_list.c
        tests/test_thread_pool.c
        tests/test_target_parser.c
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

    add_executable(argus_test_listener tests/loopback_listener.c)
    add_executable(argus_test_udp_listener tests/udp_loopback_listener.c)
    if(MSVC)
        target_compile_options(argus_test_listener PRIVATE /W4 /WX)
    else()
        target_compile_options(argus_test_listener PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wshadow
            -Werror
        )
        target_compile_options(argus_test_udp_listener PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wshadow
            -Werror
        )
    endif()
endif()
