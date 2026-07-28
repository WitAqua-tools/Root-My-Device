cmake_minimum_required(VERSION 3.22.1)
project(witaqua_native LANGUAGES C)

add_library(witaqua_native SHARED native_probe.c)
target_compile_options(witaqua_native PRIVATE -O2 -Wall -Wextra -Werror)
target_link_libraries(witaqua_native PRIVATE log)

# The bootstrap helper, built from source rather than committed as a binary.
#
# Its source belongs to the payload repository and stays there: the payload's
# standalone route execs the same program from a fixed path, which both target
# headers name (ROOT_HELPER_PATH / ROOT_UMH_PATH), so `make` there still has to
# produce it. This application is the other consumer, and it gets the same
# source through the submodule rather than a copy -- one source, and the
# submodule commit records exactly which revision of it an APK was built from.
set(PAYLOADS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../payloads")
set(SU_DAEMON_DIR "${PAYLOADS_DIR}/src/payloads/su_daemon")

# Checked one file at a time, because the two ways this goes wrong need
# different answers: nothing there at all is an uninitialised submodule, and
# some of it there is a pin from before the helper was split into three.
set(SU_DAEMON_SOURCES su_daemon.c late_load.c hold_refs.c)
foreach(source IN LISTS SU_DAEMON_SOURCES)
    if(NOT EXISTS "${SU_DAEMON_DIR}/${source}")
        if(EXISTS "${SU_DAEMON_DIR}")
            message(FATAL_ERROR
                "${SU_DAEMON_DIR}/${source} is missing, but the directory is "
                "there. The payloads submodule is pinned at a revision that "
                "predates it; bump the pin:\n"
                "    git -C payloads fetch && git -C payloads checkout <sha>")
        endif()
        message(FATAL_ERROR
            "${SU_DAEMON_DIR} is missing. The bootstrap helper is built from "
            "the payload repository, which is a submodule of this one:\n"
            "    git submodule update --init payloads")
    endif()
endforeach()

# Named libcve43499root.so, and an executable rather than a library.
#
# Both halves of that are load-bearing. It has to be an executable because
# InstallViewModel runs it with ProcessBuilder, which needs the PT_INTERP and
# entry point that -shared would not give it. It has to be called lib*.so
# because that is what the platform extracts out of an APK into
# nativeLibraryDir as a real file with the execute bit set -- which is also why
# jniLibs.useLegacyPackaging must stay true in build.gradle.kts.
add_executable(cve43499root
    "${SU_DAEMON_DIR}/su_daemon.c"
    "${SU_DAEMON_DIR}/late_load.c"
    "${SU_DAEMON_DIR}/hold_refs.c")
set_target_properties(cve43499root PROPERTIES PREFIX "lib" SUFFIX ".so")
target_include_directories(cve43499root PRIVATE "${SU_DAEMON_DIR}")
target_compile_options(cve43499root PRIVATE -O2 -Wall -Wextra -Werror)
target_link_options(cve43499root PRIVATE -pie)
target_link_libraries(cve43499root PRIVATE dl)
