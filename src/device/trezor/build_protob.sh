#!/usr/bin/env bash
protoc external/trezor-common/protob/{messages.proto,messages-common.proto,messages-management.proto,messages-monero.proto} \
    --cpp_out=src/device/trezor/messages/ \
    --descriptor_set_out=src/device/trezor/descriptor \
    -I external/trezor-common/protob/ -I /usr/local/include
