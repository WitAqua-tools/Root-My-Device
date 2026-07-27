cmake_minimum_required(VERSION 3.22.1)
project(witaqua_native LANGUAGES C)

add_library(witaqua_native SHARED native_probe.c)
target_compile_options(witaqua_native PRIVATE -O2 -Wall -Wextra -Werror)
target_link_libraries(witaqua_native PRIVATE log)

