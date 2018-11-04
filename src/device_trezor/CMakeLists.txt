# Copyright (c) 2014-2017, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set(TREZOR_PROTOB_H
        trezor/messages/messages.pb.h
        trezor/messages/messages-common.pb.h
        trezor/messages/messages-management.pb.h
        trezor/messages/messages-monero.pb.h
)

set(TREZOR_PROTOB_CPP
        trezor/messages/messages.pb.cc
        trezor/messages/messages-common.pb.cc
        trezor/messages/messages-management.pb.cc
        trezor/messages/messages-monero.pb.cc
)

set(trezor_headers
        trezor/exceptions.hpp
        trezor/messages_map.hpp
        trezor/protocol.hpp
        trezor/transport.hpp
        device_trezor_base.hpp
        device_trezor_lite.hpp
        device_trezor.hpp
        trezor.hpp
        ${TREZOR_PROTOB_H}
)

set(trezor_sources
        trezor/messages_map.cpp
        trezor/protocol.cpp
        trezor/transport.cpp
        device_trezor_base.cpp
        device_trezor_lite.cpp
        device_trezor.cpp
        ${TREZOR_PROTOB_CPP}
)

set(trezor_private_headers)


include(FindProtobuf)
find_package(Protobuf)  # REQUIRED
find_library(LIBUSB-1.0_LIBRARY usb-1.0)
find_package(LibUSB)

# Debug link
if(TREZOR_DEBUG)
    list(APPEND trezor_headers trezor/debug_link.hpp trezor/messages/messages-debug.pb.h)
    list(APPEND trezor_sources trezor/debug_link.cpp trezor/messages/messages-debug.pb.cc)
    set(TREZOR_PROTOB_FLAGS "--debug-msg")
    message(STATUS "Trezor debug link enabled")
endif(TREZOR_DEBUG)

# Test for HAVE_PROTOBUF from the parent
if(Protobuf_FOUND AND HAVE_PROTOBUF)
    if ("$ENV{PYTHON3}" STREQUAL "")
        set(PYTHON3 "python3")
    else()
        set(PYTHON3 "$ENV{PYTHON3}" CACHE INTERNAL "Copied from environment variable")
    endif()

    execute_process(COMMAND ${PYTHON3} tools/build_protob.py ${TREZOR_PROTOB_FLAGS} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/trezor RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE ERR)
    if(RET)
        message(WARNING "Trezor protobuf messages could not be regenerated (err=${RET}, python ${PYTHON})."
                        "OUT: ${OUT}, ERR: ${ERR}."
                        "Please read src/device_trezor/trezor/tools/README.md")
    else()
        message(STATUS "Trezor protobuf messages regenerated ${OUT}")
        set(TREZOR_PROTOBUF_GENERATED 1)
    endif()
endif()


if(TREZOR_PROTOBUF_GENERATED)
    message(STATUS "Trezor support enabled")

    add_definitions(-DPROTOBUF_INLINE_NOT_IN_HEADERS=0)
    set ( libdevice_trezor_hdr "" )
    set ( libdevice_trezor_lib "" )

    if(LIBUSB-1.0_LIBRARY)
        list(APPEND libdevice_trezor_hdr ${LIBUSB-1.0_INCLUDE_DIR})
        list(APPEND libdevice_trezor_lib ${LIBUSB-1.0_LIBRARY})
        message(STATUS "LibUSB found, w1")
    elseif(LibUSB_FOUND)
        list(APPEND libdevice_trezor_hdr ${LibUSB_INCLUDE_DIRS})
        list(APPEND libdevice_trezor_lib ${LibUSB_LIBRARIES})
        message(STATUS "LibUSB found, w2")
    endif()

    monero_private_headers(device_trezor
            ${device_private_headers}
            ${PROTOBUF_INCLUDE_DIR}
            ${libdevice_trezor_hdr})

    monero_add_library(device_trezor
            ${trezor_sources}
            ${trezor_headers}
            ${trezor_private_headers})

    target_link_libraries(device_trezor
            PUBLIC
            device
            cncrypto
            ringct_basic
            cryptonote_core
            common
            ${SODIUM_LIBRARY}
            ${Boost_CHRONO_LIBRARY}
            ${PROTOBUF_LIBRARY}
            ${libdevice_trezor_lib}
            PRIVATE
            ${EXTRA_LIBRARIES})

    # set(WITH_DEVICE_TREZOR 1 PARENT_SCOPE)
    # add_definitions(-DWITH_DEVICE_TREZOR=1)

else()
    monero_private_headers(device_trezor)
    monero_add_library(device_trezor device_trezor.cpp)
    target_link_libraries(device_trezor PUBLIC cncrypto)
endif()
