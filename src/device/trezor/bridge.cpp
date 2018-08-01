//
// Created by Dusan Klinec on 01/08/2018.
//

#include "bridge.h"
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
    if (m_device_path.empty()){
      return false;
    }

    std::string uri = "/acquire/" + m_device_path + "/null";
    std::string req;
    json bridge_res;
    bool req_status = invoke_bridge_http(uri, req, bridge_res, m_http_client);
    if (!req_status){
      return false;
    }

    m_session = bridge_res["session"];
    return true;
  }

  bool BridgeTransport::close() {
    if (m_device_path.empty() || m_session.empty()){
      return false;
    }

    std::string uri = "/release/" + m_session;
    std::string req;
    json bridge_res;
    bool req_status = invoke_bridge_http(uri, req, bridge_res, m_http_client);
    if (!req_status){
      return false;
    }

    m_session.clear();
    return true;
  }

  bool BridgeTransport::write(const google::protobuf::Message &req) {
    m_response = boost::none;

    auto req_len = req.ByteSize();
    auto msg_wire_num = MessageMapper::get_message_wire_number(req);
    const auto buffer_size = 2 + 4 + req_len;

    std::unique_ptr<uint8_t[]> req_buff(new uint8_t[buffer_size]);
    uint8_t * req_buff_raw = req_buff.get();

    uint16_t wire_tag = boost::endian::native_to_big(static_cast<uint16_t>(msg_wire_num));
    uint32_t wire_len = boost::endian::native_to_big(static_cast<uint32_t>(req_len));
    memcpy(req_buff_raw, (void*)&wire_tag, 2);
    memcpy(req_buff_raw + 2, (void*)&wire_len, 4);
    req.SerializeToArray(req_buff_raw + 6, req_len);

    std::string uri = "/call/" + m_session;
    std::string req_hex = epee::string_tools::buff_to_hex_nodelimer(std::string(reinterpret_cast<char*>(req_buff_raw),
                                                                                (unsigned long) buffer_size));
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

    uint16_t wire_tag;
    uint32_t wire_len;
    memcpy(&wire_tag, bin_data.c_str(), 2);
    memcpy(&wire_len, bin_data.c_str() + 2, 4);

    auto msg_tag = boost::endian::big_to_native(wire_tag);
    auto msg_len = boost::endian::big_to_native(wire_len);
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

