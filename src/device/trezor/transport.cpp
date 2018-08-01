//
// Created by Dusan Klinec on 01/08/2018.
//

#include "transport.h"
#include <boost/endian/conversion.hpp>

using namespace std;
using json = nlohmann::json;


namespace hw{
namespace trezor{

  bool t_serialize(const std::string & in, std::string & out){
    out = in;
    return true;
  }

  bool t_serialize(const json & in, std::string & out){
    out = in.dump();
    return true;
  }

  bool t_deserialize(const std::string & in, std::string & out){
    out = in;
    return true;
  }

  bool t_deserialize(const std::string & in, json & out){
    out = json::parse(in);
    return true;
  }

  //
  // Helpers
  //

#define PROTO_HEADER_SIZE 6

  static size_t message_size(const google::protobuf::Message &req){
    return req.ByteSize();
  }

  static size_t serialize_message_buffer_size(size_t msg_size) {
    return PROTO_HEADER_SIZE + msg_size;  // tag 2B + len 4B
  }

  static void serialize_message_header(void * buff, uint16_t tag, uint32_t len){
    uint16_t wire_tag = boost::endian::native_to_big(static_cast<uint16_t>(tag));
    uint32_t wire_len = boost::endian::native_to_big(static_cast<uint32_t>(len));
    memcpy(buff, (void *) &wire_tag, 2);
    memcpy((uint8_t*)buff + 2, (void *) &wire_len, 4);
  }

  static void deserialize_message_header(const void * buff, uint16_t & tag, uint32_t & len){
    uint16_t wire_tag;
    uint32_t wire_len;
    memcpy(&wire_tag, buff, 2);
    memcpy(&wire_len, (uint8_t*)buff + 2, 4);

    tag = boost::endian::big_to_native(wire_tag);
    len = boost::endian::big_to_native(wire_len);
  }

  static bool serialize_message(const google::protobuf::Message &req, size_t msg_size, uint8_t * buff, size_t buff_size) {
    auto msg_wire_num = MessageMapper::get_message_wire_number(req);
    const auto req_buffer_size = serialize_message_buffer_size(msg_size);
    if (req_buffer_size > buff_size){
      return false;
    }

    serialize_message_header(buff, msg_wire_num, msg_size);
    if (!req.SerializeToArray(buff + 6, msg_size)){
      return false;
    }

    return true;
  }

  static bool serialize_message(const google::protobuf::Message &req, std::string &res) {
    auto req_len = req.ByteSize();
    const auto buffer_size = serialize_message_buffer_size(req_len);

    std::unique_ptr<uint8_t[]> req_buff(new uint8_t[buffer_size]);
    uint8_t * req_buff_raw = req_buff.get();

    if (!serialize_message(req, req_len, req_buff_raw, buffer_size)){
      return false;
    }

    res.assign(reinterpret_cast<char*>(req_buff_raw), buffer_size);
    return true;
  }


  //
  // Communication protocol
  //

#define REPLEN 64

  bool ProtocolV1::write(Transport & transport, const google::protobuf::Message & req){
    const auto msg_size = message_size(req);
    const auto buff_size = serialize_message_buffer_size(msg_size) + 2;

    std::unique_ptr<uint8_t[]> req_buff(new uint8_t[buff_size]);
    uint8_t * req_buff_raw = req_buff.get();
    req_buff_raw[0] = '#';
    req_buff_raw[1] = '#';

    if (!serialize_message(req, msg_size, req_buff_raw + 2, buff_size - 2)){
      return false;
    }

    size_t offset = 0;
    std::unique_ptr<uint8_t[]> chunk_buff(new uint8_t[REPLEN]);
    uint8_t * chunk_buff_raw = chunk_buff.get();

    // Chunk by chunk upload
    while(offset < buff_size){
      auto to_copy = std::min((size_t)(buff_size - offset), (size_t)(REPLEN - 1));

      chunk_buff_raw[0] = '?';
      memcpy(chunk_buff_raw + 1, req_buff_raw + offset, to_copy);

      // Pad with zeros
      if (to_copy < REPLEN - 1){
        memset(chunk_buff_raw + 1 + to_copy, 0, REPLEN - 1 - to_copy);
      }

      std::string chunk((char*)(chunk_buff_raw), REPLEN);
      if (!transport.write_chunk(chunk)){
        return false;
      }

      offset += REPLEN - 1;
    }
    return true;
  }

  bool ProtocolV1::read(Transport & transport, std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type){
    std::string chunk;

    // Initial chunk read
    if (!transport.read_chunk(chunk)){
      return false;
    }

    if (chunk.substr(0, 3) != "?##" || chunk.size() < 3 + PROTO_HEADER_SIZE){
      return false;
    }

    uint16_t tag;
    uint32_t len, nread=chunk.size() - 3 - 6;
    deserialize_message_header(chunk.c_str() + 3, tag, len);

    std::string data_acc(chunk.c_str() + 3 + 6, nread);
    while(nread < len){
      std::string chunk;
      if (!transport.read_chunk(chunk)){
        return false;
      }

      data_acc.append(chunk);
      nread += chunk.size();
    }

    if (msg_type){
      *msg_type = static_cast<messages::MessageType>(tag);
    }

    std::shared_ptr<google::protobuf::Message> msg_wrap(MessageMapper::get_message(tag));
    if (!msg_wrap->ParseFromArray(data_acc.c_str(), len)){
      return false;
    }
    msg = msg_wrap;
    return true;
  }

  //
  // Bridge transport
  //

  bool BridgeTransport::enumerate(t_transport_vect & res) {
    json bridge_res;
    std::string req;

    bool req_status = invoke_bridge_http("/enumerate", req, bridge_res, m_http_client);
    if (!req_status){
      return false;
    }

    for (auto& element : bridge_res) {
      std::cout << element << endl;
      res.push_back(std::make_shared<BridgeTransport>(element["path"].get<std::string>()));
    }
    return true;
  }

  bool BridgeTransport::open() {
    if (!m_device_path){
      return false;
    }

    std::string uri = "/acquire/" + m_device_path.get() + "/null";
    std::string req;
    json bridge_res;
    bool req_status = invoke_bridge_http(uri, req, bridge_res, m_http_client);
    if (!req_status){
      return false;
    }

    m_session = boost::make_optional(bridge_res["session"]);
    return true;
  }

  bool BridgeTransport::close() {
    if (!m_device_path || !m_session){
      return false;
    }

    std::string uri = "/release/" + m_session.get();
    std::string req;
    json bridge_res;
    bool req_status = invoke_bridge_http(uri, req, bridge_res, m_http_client);
    if (!req_status){
      return false;
    }

    m_session = boost::none;
    return true;
  }

  bool BridgeTransport::write(const google::protobuf::Message &req) {
    m_response = boost::none;
    std::string req_buff;

    if (!serialize_message(req, req_buff)){
      return false;
    }

    std::string uri = "/call/" + m_session.get();
    std::string req_hex = epee::string_tools::buff_to_hex_nodelimer(req_buff);
    std::string res_hex;

    std::cerr << "REQ: " << req_hex << endl;
    bool req_status = invoke_bridge_http(uri, req_hex, res_hex, m_http_client);
    if (!req_status){
      return false;
    }

    std::cerr << "RES: " << res_hex << endl;
    m_response = res_hex;
    return true;
  }

  bool BridgeTransport::read(std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type) {
    if (!m_response){
      return false;
    }

    std::string bin_data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(m_response.get(), bin_data)){
      return false;
    }

    uint16_t msg_tag;
    uint32_t msg_len;
    deserialize_message_header(bin_data.c_str(), msg_tag, msg_len);
    if (bin_data.size() != msg_len + 6){
      return false;
    }

    if (msg_type){
      *msg_type = static_cast<messages::MessageType>(msg_tag);
    }

    std::shared_ptr<google::protobuf::Message> msg_wrap(MessageMapper::get_message(msg_tag));
    if (!msg_wrap->ParseFromArray(bin_data.c_str() + 6, msg_len)){
      return false;
    }
    msg = msg_wrap;
    return true;
  }

}
}

