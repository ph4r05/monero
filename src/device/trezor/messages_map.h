//
// Created by Dusan Klinec on 29/07/2018.
//

#ifndef MONERO_MESSAGES_MAP_H
#define MONERO_MESSAGES_MAP_H

#include <string>
#include <type_traits>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_enum_reflection.h>
#include "google/protobuf/descriptor.pb.h"

#include "messages/messages.pb.h"
#include "exceptions.h"

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

    template<class t_message>
    static messages::MessageType get_message_wire_number() {
      BOOST_STATIC_ASSERT(boost::is_base_of<google::protobuf::Message, t_message>::value);
      return get_message_wire_number(t_message::default_instance().GetDescriptor()->name());
    }
  };

  template<class t_message>
  std::shared_ptr<t_message> message_ptr_retype(std::shared_ptr<google::protobuf::Message> & in){
    BOOST_STATIC_ASSERT(boost::is_base_of<google::protobuf::Message, t_message>::value);
    if (!in){
      return nullptr;
    }

    return std::dynamic_pointer_cast<t_message>(in);
  }

  template<class t_message>
  std::shared_ptr<t_message> message_ptr_retype_static(std::shared_ptr<google::protobuf::Message> & in){
    BOOST_STATIC_ASSERT(boost::is_base_of<google::protobuf::Message, t_message>::value);
    if (!in){
      return nullptr;
    }

    return std::static_pointer_cast<t_message>(in);
  }

}}

#endif //MONERO_MESSAGES_MAP_H
