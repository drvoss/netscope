cmake_minimum_required(VERSION 3.21)

# Project identifier is "netscope" per the plan's naming table; the binary is
# "nscope" so both implementations can be installed side by side.
project(netscope VERSION 0.3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(ftxui CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(doctest CONFIG REQUIRED)

# ---------------------------------------------------------------- core library
# Everything except main() lives here so the tests can link against it.
add_library(nscope_core STATIC
    src/model.cpp
    src/net_compat.cpp
    src/child_process.cpp
    src/json.cpp
    src/stats.cpp
    src/engine.cpp
    src/replay.cpp
    src/probe_parse.cpp
    src/probe_command.cpp
    src/probe_select.cpp
    src/resolve.cpp
    src/health.cpp
    src/sysinfo.cpp
    src/runner.cpp
    src/ui.cpp
)

if(WIN32)
    target_sources(nscope_core PRIVATE src/probe_helper_win.cpp)
else()
    target_sources(nscope_core PRIVATE src/probe_raw_posix.cpp)
endif()

target_include_directories(nscope_core PUBLIC src)

target_link_libraries(nscope_core PUBLIC
    asio::asio
    ftxui::screen
    ftxui::dom
    ftxui::component
)

if(WIN32)
    # winhttp gives HTTPS through the system trust store with no third-party TLS
    # dependency, so an https:// target works out of the box.
    target_link_libraries(nscope_core PUBLIC ws2_32 iphlpapi dnsapi winhttp)
    target_compile_definitions(nscope_core PUBLIC
        _WIN32_WINNT=0x0A00
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
else()
    find_package(Threads REQUIRED)
    target_link_libraries(nscope_core PUBLIC Threads::Threads)
    # res_query lives in libresolv on glibc; it is part of libc on musl and BSD,
    # so the library is linked only when it actually exists.
    find_library(RESOLV_LIBRARY resolv)
    if(RESOLV_LIBRARY)
        target_link_libraries(nscope_core PUBLIC ${RESOLV_LIBRARY})
    endif()
endif()

# Asio is used in standalone (non-Boost) mode, without its deprecated APIs.
target_compile_definitions(nscope_core PUBLIC
    ASIO_STANDALONE
    ASIO_NO_DEPRECATED
)

# Warning discipline: our own code must build warning-free (DoD). Third-party
# headers are consumed as SYSTEM includes by their imported targets, so their
# noise does not gate the build.
if(MSVC)
    target_compile_options(nscope_core PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(nscope_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------- binary
add_executable(nscope src/main.cpp)
target_link_libraries(nscope PRIVATE nscope_core)
if(MSVC)
    target_compile_options(nscope PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(nscope PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------- tests
enable_testing()

add_executable(nscope_tests
    tests/test_main.cpp
    tests/test_stats.cpp
    tests/test_engine.cpp
    tests/test_parse.cpp
    tests/test_json.cpp
    tests/test_layout.cpp
    tests/test_select.cpp
)
target_link_libraries(nscope_tests PRIVATE nscope_core doctest::doctest)
if(MSVC)
    target_compile_options(nscope_tests PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(nscope_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Golden fixtures live at the repository root so both implementations parse the
# same bytes.
target_compile_definitions(nscope_tests PRIVATE
    NETSCOPE_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../testdata"
)

add_test(NAME nscope_tests COMMAND nscope_tests)
