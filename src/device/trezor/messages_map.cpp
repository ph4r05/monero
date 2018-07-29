//
// Created by Dusan Klinec on 29/07/2018.
//

#include "messages_map.h"
#include "messages/messages.pb.h"
#include "messages/messages-common.pb.h"
#include "messages/messages-management.pb.h"
#include "messages/messages-monero.pb.h"

using namespace std;
using namespace hw::trezor;

namespace hw{
namespace trezor
{

  const char * TYPE_PREFIX = "MessageType_";
  const char * PACKAGES[] = {
      "hw.trezor.messages.",
      "hw.trezor.messages.common.",
      "hw.trezor.messages.management.",
      "hw.trezor.messages.monero."
  };

  google::protobuf::Message * MessageMapper::get_message(int wire_number) {
    return MessageMapper::get_message(static_cast<messages::MessageType>(wire_number));
  }

  google::protobuf::Message * MessageMapper::get_message(messages::MessageType wire_number) {
    const string &messageTypeName = hw::trezor::messages::MessageType_Name(wire_number);
    if (messageTypeName.empty()) {
      throw std::runtime_error(std::string("Message descriptor not found: ") + std::to_string(wire_number));
    }

    string messageName = messageTypeName.substr(strlen(TYPE_PREFIX));
    return MessageMapper::get_message(messageName);
  }

  google::protobuf::Message * MessageMapper::get_message(const std::string & msg_name) {
    // Each package instantiation so lookup works
    hw::trezor::messages::common::Success::default_instance();
    hw::trezor::messages::management::Cancel::default_instance();
    hw::trezor::messages::monero::MoneroGetAddress::default_instance();

    google::protobuf::Descriptor const * desc = nullptr;
    for(const string &text : PACKAGES){
      desc = google::protobuf::DescriptorPool::generated_pool()
          ->FindMessageTypeByName(text + msg_name);
      if (desc != nullptr){
        break;
      }
    }

    if (desc == nullptr){
      throw std::runtime_error("Message descriptor not found: ");
    }

    google::protobuf::Message* message =
        google::protobuf::MessageFactory::generated_factory()
            ->GetPrototype(desc)->New();

    return message;

//    // CODEGEN way, fast
//    switch(wire_number){
//      case 501:
//        return new hw::trezor::messages::monero::MoneroTransactionSignRequest();
//      default:
//        throw std::runtime_error("not implemented");
//    }
  }

  messages::MessageType MessageMapper::get_message_wire_number(const google::protobuf::Message * msg){
    return MessageMapper::get_message_wire_number(msg->GetDescriptor()->name());
  }

  messages::MessageType MessageMapper::get_message_wire_number(const std::string & msg_name){
    string enumMessageName = std::string(TYPE_PREFIX) + msg_name;

    messages::MessageType res;
    bool r = hw::trezor::messages::MessageType_Parse(enumMessageName, &res);
    if (!r){
      throw std::runtime_error(std::string("Message ") + msg_name + " not found");
    }

    return res;
  }

}
}
