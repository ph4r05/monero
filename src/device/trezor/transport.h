//
// Created by Dusan Klinec on 01/08/2018.
//

#ifndef MONERO_TRANSPORT_H
#define MONERO_TRANSPORT_H


#include <boost/utility/string_ref.hpp>
#include <boost/asio.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/array.hpp>

#include <net/http_base.h>
#include "net/http_client.h"
#include "json.hpp"
#include "messages_map.h"


namespace hw {
namespace trezor {

  using json = nlohmann::json;
  namespace http = epee::net_utils::http;

  const std::string DEFAULT_BRIDGE = "127.0.0.1:21325";

  // Base HTTP comm serialization.
  bool t_serialize(const std::string & in, std::string & out);
  bool t_serialize(const json & in, std::string & out);

  bool t_deserialize(const std::string & in, std::string & out);
  bool t_deserialize(const std::string & in, json & out);

  // Flexible json serialization. HTTP client tailored for bridge API
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

  // Forward decl
  class Transport;

  // Communication protocol
  class Protocol {
  public:
    Protocol() = default;
    virtual bool session_begin(Transport & transport){ return false; };
    virtual bool session_end(Transport & transport){ return false; };
    virtual bool write(Transport & transport, const google::protobuf::Message & req)= 0;
    virtual bool read(Transport & transport, std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr)= 0;
  };

  class ProtocolV1 : public Protocol {
  public:
    ProtocolV1() = default;

    bool write(Transport & transport, const google::protobuf::Message & req) override;
    bool read(Transport & transport, std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr) override;
  };


  // Base transport
  typedef std::vector<std::shared_ptr<Transport>> t_transport_vect;

  class Transport {
  public:
    Transport() = default;

    virtual bool ping() { return false; };
    virtual std::string get_path() const { return ""; };
    virtual bool enumerate(t_transport_vect & res){ return false; };
    virtual bool open(){return false;};
    virtual bool close(){return false;};
    virtual bool write(const google::protobuf::Message & req) =0;
    virtual bool read(std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr) =0;

    virtual bool write_chunk(const void * buff, size_t size) { return false; };
    virtual size_t read_chunk(void * buff, size_t size) { return 0; };
    virtual std::ostream& dump(std::ostream& o) const { return o << "Transport<>"; }
  };

  // Bridge transport
  class BridgeTransport : public Transport {
  public:
    BridgeTransport(
        boost::optional<std::string> device_path = boost::none,
        boost::optional<std::string> bridge_host = boost::none):
        m_device_path(device_path),
        m_bridge_host(bridge_host ? bridge_host.get() : DEFAULT_BRIDGE),
        m_response(boost::none),
        m_session(boost::none)
    {
      m_http_client.set_server(m_bridge_host, boost::none, false);
    }

    static const char * PATH_PREFIX;

    std::string get_path() const override;
    bool enumerate(t_transport_vect & res) override;

    bool open() override;
    bool close() override;

    bool write(const google::protobuf::Message &req) override;
    bool read(std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr) override;

    boost::optional<json> device_info() const;
    std::ostream& dump(std::ostream& o) const override;

  private:
    epee::net_utils::http::http_simple_client m_http_client;
    std::string m_bridge_host;
    boost::optional<std::string> m_device_path;
    boost::optional<std::string> m_session;
    boost::optional<std::string> m_response;
    boost::optional<json> m_device_info;
  };

  // UdpTransport transport
  using boost::asio::ip::udp;

  class UdpTransport : public Transport {
  public:

    UdpTransport(
        boost::optional<std::string> device_path=boost::none,
        boost::optional<std::shared_ptr<Protocol>> proto=boost::none);

    static const char * PATH_PREFIX;
    static const char * DEFAULT_HOST;
    static const int DEFAULT_PORT;

    bool ping() override;
    std::string get_path() const override;
    bool enumerate(t_transport_vect & res) override;

    bool open() override;
    bool close() override;

    bool write(const google::protobuf::Message &req) override;
    bool read(std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr) override;

    bool write_chunk(const void * buff, size_t size) override;
    size_t read_chunk(void * buff, size_t size) override;

    std::ostream& dump(std::ostream& o) const override;

  private:
    void require_socket();
    ssize_t receive(void * buff, size_t size);
    void check_deadline();
    static void handle_receive(const boost::system::error_code& ec, std::size_t length,
                               boost::system::error_code* out_ec, std::size_t* out_length);

    std::shared_ptr<Protocol> m_proto;
    std::string m_device_host;
    int m_device_port;

    std::unique_ptr<udp::socket> m_socket;
    boost::asio::io_service m_io_service;
    boost::asio::deadline_timer m_deadline;
    udp::endpoint m_endpoint;
  };

  //
  // General helpers
  //

  bool enumerate(t_transport_vect & res);
  std::shared_ptr<Transport> transport(std::string path);

  template<class t_transport>
  std::shared_ptr<t_transport> transport_typed(std::string path){
    auto t = transport(path);
    if (!t){
      return nullptr;
    }

    return std::dynamic_pointer_cast<t_transport>(t);
  }

}}

std::ostream& operator<<(std::ostream& o, hw::trezor::Transport const& t);
std::ostream& operator<<(std::ostream& o, std::shared_ptr<hw::trezor::Transport> const& t);

#endif //MONERO_TRANSPORT_H
