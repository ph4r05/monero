//
// Created by Dusan Klinec on 29/07/2018.
//

#ifndef MONERO_MESSAGES_MAP_H
#define MONERO_MESSAGES_MAP_H

#include <string>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_enum_reflection.h>
#include "google/protobuf/descriptor.pb.h"

#include "messages/messages.pb.h"

namespace hw {
namespace trezor {

  class MessageMapper{
    public:
      MessageMapper() {

      }

    static ::google::protobuf::Message * get_message(int wire_number);
    static ::google::protobuf::Message * get_message(messages::MessageType);
    static ::google::protobuf::Message * get_message(const std::string & msg_name);
    static messages::MessageType get_message_wire_number(const google::protobuf::Message * msg);
    static messages::MessageType get_message_wire_number(const google::protobuf::Message & msg);
    static messages::MessageType get_message_wire_number(const std::string & msg_name);
  };

}}

#endif //MONERO_MESSAGES_MAP_H
