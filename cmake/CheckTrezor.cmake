OPTION(USE_DEVICE_TREZOR "Trezor support compilation" ON)
OPTION(USE_DEVICE_TREZOR_LIBUSB "Trezor LibUSB compilation" ON)

# Use Trezor master switch
if (USE_DEVICE_TREZOR)
    # Protobuf is required to build protobuf messages for Trezor
    include(FindProtobuf OPTIONAL)
    find_package(Protobuf)
    if(NOT Protobuf_FOUND)
        message(STATUS "Could not find Protobuf")
    endif()

else()
    message(STATUS "Trezor support disabled by USE_DEVICE_TREZOR")
endif()

# Try to build protobuf messages
if(Protobuf_FOUND AND USE_DEVICE_TREZOR)
    if ("$ENV{PYTHON3}" STREQUAL "")
        set(PYTHON3 "python3")
    else()
        set(PYTHON3 "$ENV{PYTHON3}" CACHE INTERNAL "Copied from environment variable")
    endif()

    execute_process(COMMAND ${PYTHON3} tools/build_protob.py WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../src/device_trezor/trezor RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE ERR)
    if(RET)
        message(WARNING "Trezor protobuf messages could not be regenerated (err=${RET}, python ${PYTHON})."
                "OUT: ${OUT}, ERR: ${ERR}."
                "Please read src/device_trezor/trezor/tools/README.md")
    else()
        message(STATUS "Trezor protobuf messages regenerated ${OUT}")
        set(DEVICE_TREZOR_READY 1)
        add_definitions(-DDEVICE_TREZOR_READY=1)

        if (PROTOBUF_INCLUDE_DIR)
            include_directories(${PROTOBUF_INCLUDE_DIR})
        endif()

        # LibUSB support, check for particular version
        # Include support only if compilation test passes
        if (USE_DEVICE_TREZOR_LIBUSB)
            find_package(LibUSB)
        endif()

        if (LibUSB_COMPILE_TEST_PASSED)
            add_definitions(-DHAVE_TREZOR_LIBUSB=1)
            if(LibUSB_INCLUDE_DIRS)
                include_directories(${LibUSB_INCLUDE_DIRS})
            endif()
        endif()
    endif()
endif()
