OPTION(USE_DEVICE_TREZOR "Option description" ON)

# Use Trezor master switch
if (USE_DEVICE_TREZOR)

    # Protobuf is required to build protobuf messages for Trezor
    include(FindProtobuf)
    find_package(Protobuf)
    if(Protobuf_FOUND)
        add_definitions(-DHAVE_PROTOBUF=1)
    else(Protobuf_FOUND)
        message(STATUS "Could not find Protobuf")
    endif()

    # LibUSB support, check for particular version
    # Include support only if compilation test passes
    find_package(LibUSB)
    if ( LibUSB_COMPILE_TEST )
        add_definitions(-DHAVE_TREZOR_LIBUSB=1)
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
    endif()
endif()
