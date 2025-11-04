cmake_minimum_required(VERSION 3.5)
project(mpcc LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/EHsc>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/execution-charset:utf-8>")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY lib)

# src
set(LIBRARY_SOURCES
    src/ast/ast.cpp
    src/env/environment.cpp
    src/lexer/token.cpp
    src/lexer/lexer.cpp
    src/parser/parser.cpp
    src/util.cpp
    src/object/object.cpp
    src/program/program.cpp
    src/vm/vm.cpp
    src/vm/gct.cpp
    src/plugins/plugin.cpp
    src/plugins/base.cpp
    src/plugins/io.cpp
    src/plugins/math.cpp
    src/plugins/fileio.cpp
    src/plugins/mkar.cpp
    src/common.cpp
    src/earchive.cpp
    src/darchive.cpp
    src/platform.cpp
)

set(PROGRAM_SOURCES src/main.cpp)

add_library(libmkar SHARED ${LIBRARY_SOURCES})
target_include_directories(libmkar PUBLIC
    include
    ${PROJECT_BINARY_DIR}
)

set_target_properties(libmkar PROPERTIES OUTPUT_NAME "mkar")

find_package(zstd CONFIG REQUIRED)
find_package(cryptopp CONFIG REQUIRED)
find_package(CURL REQUIRED)

target_link_libraries(libmkar PUBLIC zstd::libzstd cryptopp::cryptopp CURL::libcurl)

add_executable(mkar ${PROGRAM_SOURCES})

set_target_properties(mkar PROPERTIES OUTPUT_NAME "mkar")

if(WIN32)
    enable_language(RC)
    target_sources(mkar PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/resources.rc)
endif()

target_link_libraries(mkar PRIVATE libmkar)