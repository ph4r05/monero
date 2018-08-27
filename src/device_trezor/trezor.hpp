//
// Created by Dusan Klinec on 16/08/2018.
//

#ifndef MONERO_TREZOR_HPP
#define MONERO_TREZOR_HPP

#if HAVE_PROTOBUF && !defined(WITHOUT_TREZOR)
  #define WITH_DEVICE_TREZOR 1
#else
  #define WITH_DEVICE_TREZOR 0
#endif

#ifndef WITH_DEVICE_TREZOR_LITE
#define WITH_DEVICE_TREZOR_LITE 0
#endif

#if HAVE_PROTOBUF
#include "trezor/transport.hpp"
#include "trezor/messages/messages.pb.h"
#include "trezor/messages/messages-common.pb.h"
#include "trezor/messages/messages-management.pb.h"
#include "trezor/messages/messages-monero.pb.h"
#include "trezor/protocol.hpp"
#endif

#endif //MONERO_TREZOR_HPP
