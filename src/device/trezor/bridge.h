//
// Created by Dusan Klinec on 01/08/2018.
//

#ifndef MONERO_BRIDGE_H
#define MONERO_BRIDGE_H

#include <boost/utility/string_ref.hpp>
#include <net/http_base.h>
#include "net/http_client.h"
#include "json.hpp"


namespace hw {
  namespace trezor {

    using json = nlohmann::json;
    namespace http = epee::net_utils::http;

    const std::string DEFAULT_BRIDGE = "127.0.0.1:21325";

    bool t_serialize(const std::string & in, std::string & out);
    bool t_serialize(const json & in, std::string & out);

    bool t_deserialize(const std::string & in, std::string & out);
    bool t_deserialize(const std::string & in, json & out);

    // Flexible json
    template<class t_req, class t_res, class t_transport>
    bool invoke_bridge_http(const boost::string_ref uri, const t_req & out_struct, t_res & result_struct, t_transport& transport, const boost::string_ref method = "POST", std::chrono::milliseconds timeout = std::chrono::seconds(15))
    {
      std::string req_param;
      t_serialize(out_struct, req_param);

      http::fields_list additional_params;
      additional_params.push_back(std::make_pair("Origin","https://python.trezor.io"));
      additional_params.push_back(std::make_pair("Content-Type","application/json; charset=utf-8"));

      const http::http_response_info* pri = NULL;
      if(!transport.invoke(uri, method, req_param, timeout, std::addressof(pri), std::move(additional_params)))
      {
        LOG_PRINT_L1("Failed to invoke http request to  " << uri);
        return false;
      }

      if(!pri)
      {
        LOG_PRINT_L1("Failed to invoke http request to  " << uri << ", internal error (null response ptr)");
        return false;
      }

      if(pri->m_response_code != 200)
      {
        LOG_PRINT_L1("Failed to invoke http request to  " << uri << ", wrong response code: " << pri->m_response_code);
        return false;
      }

      t_deserialize(pri->m_body, result_struct);
      return true;
    }

    class Transport;
    typedef std::vector<std::shared_ptr<Transport>> t_transport_vect;

    class Transport {
    public:
      Transport() = default;

      virtual bool open(){return false;};
      virtual bool close(){return false;};
    };

    class BridgeTransport : public Transport {
    public:
      BridgeTransport(
          const std::string & device_path="",
          const std::string & bridge_host=DEFAULT_BRIDGE):
              m_device_path(device_path),
              m_bridge_host(bridge_host)
      {
        m_http_client.set_server(m_bridge_host, boost::none, false);
      }

      bool enumerate(t_transport_vect & res);

      bool open();
      bool close();

    private:
      epee::net_utils::http::http_simple_client m_http_client;
      std::string m_bridge_host;
      std::string m_device_path;
      std::string m_session;
    };

  }}

#endif //MONERO_BRIDGE_H
