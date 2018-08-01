//
// Created by Dusan Klinec on 01/08/2018.
//

#include "bridge.h"

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

}
}

