cmake_minimum_required(VERSION 3.20)

project(readrtp VERSION 0.1.0 LANGUAGES CXX)

option(READRTP_BUILD_TESTS "Build the tests" ON)

include(GNUInstallDirs)

set(READRTP_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_library(readrtp STATIC
    src/error.cpp
    src/buffer.cpp
    src/types.cpp
    src/checksum.cpp
    src/patch_applier.cpp
    src/parse.cpp
    src/decompression.cpp
    src/apply.cpp
)

target_include_directories(readrtp
    PUBLIC
        "${READRTP_INCLUDE_DIR}"
)

target_compile_features(readrtp PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(readrtp PRIVATE /W4 /permissive-)
else()
    target_compile_options(readrtp PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(apply
    src/cli/apply_main.cpp
)
target_link_libraries(apply PRIVATE readrtp)

install(TARGETS apply
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

if(UNIX AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_program(READRTP_APPIMAGETOOL_EXECUTABLE appimagetool)

    set(READRTP_APPDIR "${CMAKE_CURRENT_BINARY_DIR}/AppDir")
    set(READRTP_APPIMAGE_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/readrtp-${PROJECT_VERSION}-${CMAKE_SYSTEM_PROCESSOR}.AppImage")

    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/AppRun.in"
        "${CMAKE_CURRENT_BINARY_DIR}/AppRun"
        @ONLY
    )
    file(CHMOD
        "${CMAKE_CURRENT_BINARY_DIR}/AppRun"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )

    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/readrtp.desktop.in"
        "${CMAKE_CURRENT_BINARY_DIR}/readrtp.desktop"
        @ONLY
    )
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/readrtp.svg.in"
        "${CMAKE_CURRENT_BINARY_DIR}/readrtp.svg"
        @ONLY
    )

    if(READRTP_APPIMAGETOOL_EXECUTABLE)
        add_custom_command(
            OUTPUT "${READRTP_APPIMAGE_OUTPUT}"
            COMMAND "${CMAKE_COMMAND}" -E rm -rf "${READRTP_APPDIR}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory
                "${READRTP_APPDIR}/usr/bin"
                "${READRTP_APPDIR}/usr/share/applications"
                "${READRTP_APPDIR}/usr/share/icons/hicolor/scalable/apps"
            COMMAND "${CMAKE_COMMAND}" -E copy "$<TARGET_FILE:apply>" "${READRTP_APPDIR}/usr/bin/apply"
            COMMAND "${CMAKE_COMMAND}" -E copy "${CMAKE_CURRENT_BINARY_DIR}/AppRun" "${READRTP_APPDIR}/AppRun"
            COMMAND "${CMAKE_COMMAND}" -E copy "${CMAKE_CURRENT_BINARY_DIR}/readrtp.desktop" "${READRTP_APPDIR}/readrtp.desktop"
            COMMAND "${CMAKE_COMMAND}" -E copy "${CMAKE_CURRENT_BINARY_DIR}/readrtp.desktop" "${READRTP_APPDIR}/usr/share/applications/readrtp.desktop"
            COMMAND "${CMAKE_COMMAND}" -E copy "${CMAKE_CURRENT_BINARY_DIR}/readrtp.svg" "${READRTP_APPDIR}/readrtp.svg"
            COMMAND "${CMAKE_COMMAND}" -E copy "${CMAKE_CURRENT_BINARY_DIR}/readrtp.svg" "${READRTP_APPDIR}/usr/share/icons/hicolor/scalable/apps/readrtp.svg"
            COMMAND "${READRTP_APPIMAGETOOL_EXECUTABLE}" --no-appstream "${READRTP_APPDIR}" "${READRTP_APPIMAGE_OUTPUT}"
            DEPENDS apply
                "${CMAKE_CURRENT_BINARY_DIR}/AppRun"
                "${CMAKE_CURRENT_BINARY_DIR}/readrtp.desktop"
                "${CMAKE_CURRENT_BINARY_DIR}/readrtp.svg"
            VERBATIM
        )

        add_custom_target(readrtp_appimage
            DEPENDS "${READRTP_APPIMAGE_OUTPUT}"
        )
    else()
        message(STATUS "appimagetool was not found; the readrtp_appimage target will not be generated.")
    endif()
endif()

if(READRTP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
