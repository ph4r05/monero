//
// Created by Dusan Klinec on 29/07/2018.
//

#include "messages_map.h"
#include "messages/messages.pb.h"
#include "messages/messages-common.pb.h"
#include "messages/messages-management.pb.h"
#include "messages/messages-monero.pb.h"

using namespace hw::trezor;


google::protobuf::Message MessageMapper::get_message(int wire_number) {
  throw std::runtime_error("not implemented");
}
