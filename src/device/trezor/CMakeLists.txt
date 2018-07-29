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
        messages/messages.pb.h
        messages/messages-common.pb.h
        messages/messages-management.pb.h
        messages/messages-monero.pb.h
)

set(TREZOR_PROTOB_CPP
        messages/messages.pb.cc
        messages/messages-common.pb.cc
        messages/messages-management.pb.cc
        messages/messages-monero.pb.cc
)

set(trezor_headers
        messages_map.h
        ${TREZOR_PROTOB_H}
)

set(trezor_sources
        messages_map.cpp
        ${TREZOR_PROTOB_CPP}
)

set(trezor_private_headers)


include(FindProtobuf)
find_package(Protobuf REQUIRED)

monero_private_headers(device_trezor
        ${device_private_headers}
        ${PROTOBUF_INCLUDE_DIR})

monero_add_library(device_trezor
        ${trezor_sources}
        ${trezor_headers}
        ${trezor_private_headers})

target_link_libraries(device_trezor
        PUBLIC
        cncrypto
        ringct_basic
        ${OPENSSL_CRYPTO_LIBRARIES}
        ${PROTOBUF_LIBRARY}
        PRIVATE
        ${EXTRA_LIBRARIES})
