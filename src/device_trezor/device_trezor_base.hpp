// Copyright (c) 2017-2018, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#ifndef MONERO_DEVICE_TREZOR_BASE_H
#define MONERO_DEVICE_TREZOR_BASE_H


#include <cstddef>
#include <string>
#include "device/device.hpp"
#include "device/device_default.hpp"
#include "device/device_cold.hpp"
#include <boost/scope_exit.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include "cryptonote_config.h"
#include "trezor.hpp"

namespace hw {
namespace trezor {

#if WITH_DEVICE_TREZOR
  class device_trezor_base;

  /**
   * Default trezor protocol client callback
   */
  class trezor_callback {
  protected:
    device_trezor_base & device;

  public:
    trezor_callback() = default;
    explicit trezor_callback(device_trezor_base & device): device(device) {}

    std::shared_ptr<google::protobuf::Message> on_button_request(const messages::common::ButtonRequest * msg){
      MDEBUG("on_button_request");
      return std::make_shared<messages::common::ButtonAck>();
    }

    std::shared_ptr<google::protobuf::Message> on_message(const google::protobuf::Message * msg, messages::MessageType message_type){
      MDEBUG("on_general_message");
      return on_message_dispatch(msg, message_type);
    }

    std::shared_ptr<google::protobuf::Message> on_message_dispatch(const google::protobuf::Message * msg, messages::MessageType message_type){
      if (message_type == messages::MessageType_ButtonRequest){
        return on_button_request(dynamic_cast<const messages::common::ButtonRequest*>(msg));
      } else {
        return nullptr;
      }
    }
  };

  /**
   * TREZOR device template with basic functions
   */
  class device_trezor_base : public hw::core::device_default {
    protected:

      // Locker for concurrent access
      mutable boost::recursive_mutex  device_locker;
      mutable boost::mutex  command_locker;

      std::shared_ptr<Transport> m_transport;
      std::shared_ptr<trezor_callback> m_callback;

      std::string full_name;

      cryptonote::network_type network_type;

      //
      // Internal methods
      //

      void require_connected();
      void call_ping_unsafe();
      void test_ping();

      /**
       * Client communication wrapper, handles specific Trezor protocol.
       *
       * @throws UnexpectedMessageException if the response message type is different than expected.
       * Exception contains message type and the message itself.
       */
      template<class t_message>
      std::shared_ptr<t_message>
      client_exchange(const std::shared_ptr<const google::protobuf::Message> &req,
                      boost::optional<messages::MessageType> resp_type = boost::none,
                      boost::optional<std::vector<messages::MessageType>> resp_types = boost::none,
                      boost::optional<messages::MessageType*> resp_type_ptr = boost::none,
                      bool open_session = false,
                      unsigned depth=0)
      {
        // Require strictly protocol buffers response in the template.
        BOOST_STATIC_ASSERT(boost::is_base_of<google::protobuf::Message, t_message>::value);
        const bool accepting_base = boost::is_same<google::protobuf::Message, t_message>::value;
        if (resp_types && !accepting_base){
          throw std::invalid_argument("Cannot specify list of accepted types and not using generic response");
        }

        // Open session if required
        if (open_session && depth == 0){
          bool r = m_transport->open();
          if (!r){
            throw exc::SessionException("Could not open session");
          }
        }

        // Scoped session closer
        BOOST_SCOPE_EXIT_ALL(&, this) {
          if (open_session && depth == 0){
            this->getTransport()->close();
          }
        };

        // Write the request
        CHECK_AND_ASSERT_THROW_MES(req, "Request is null");
        this->getTransport()->write(*req);

        // Read the response
        std::shared_ptr<google::protobuf::Message> msg_resp;
        hw::trezor::messages::MessageType msg_resp_type;

        // We may have several roundtrips with the handler
        this->getTransport()->read(msg_resp, &msg_resp_type);
        if (resp_type_ptr){
          *(resp_type_ptr.get()) = msg_resp_type;
        }

        // Determine type of expected message response
        messages::MessageType required_type = accepting_base ? messages::MessageType_Success :
            (resp_type ? resp_type.get() : MessageMapper::get_message_wire_number<t_message>());

        if (msg_resp_type == messages::MessageType_Failure) {
          throw_failure_exception(dynamic_cast<messages::common::Failure *>(msg_resp.get()));

        } else if (!accepting_base && msg_resp_type == required_type) {
          return message_ptr_retype<t_message>(msg_resp);

        } else {
          auto resp = this->getCallback()->on_message(msg_resp.get(), msg_resp_type);
          if (resp) {
            return this->client_exchange<t_message>(resp, boost::none, resp_types, resp_type_ptr, false, depth + 1);

          } else if (accepting_base && (!resp_types ||
                     std::find(resp_types.get().begin(), resp_types.get().end(), msg_resp_type) != resp_types.get().end())) {
            return message_ptr_retype<t_message>(msg_resp);

          } else {
            throw exc::UnexpectedMessageException(msg_resp_type, msg_resp);
          }
        }
      }

      /**
       * Utility method to set address_n and network type to the message requets.
       */
      template<class t_message>
      void set_msg_addr(t_message * msg,
                        boost::optional<std::vector<uint32_t>> path = boost::none,
                        boost::optional<cryptonote::network_type> network_type = boost::none)
      {
        msg->clear_address_n();
        if (path){
          for(auto x : path.get()){
            msg->add_address_n(x);
          }
        } else {
          for (unsigned int i : DEFAULT_BIP44_PATH) {
            msg->add_address_n(i);
          }
        }

        if (network_type){
          msg->set_network_type(static_cast<uint32_t>(network_type.get()));
        } else {
          msg->set_network_type(static_cast<uint32_t>(this->network_type));
        }
      }

    public:
    device_trezor_base();
    ~device_trezor_base() override;

    device_trezor_base(const device_trezor_base &device) = delete ;
    device_trezor_base& operator=(const device_trezor_base &device) = delete;

    explicit operator bool() const override {return true;}
    device_type get_type() const override {return device_type::TREZOR;};

    bool reset(void);

    // Default derivation path for Monero
    static const uint32_t DEFAULT_BIP44_PATH[5];

    std::shared_ptr<Transport> getTransport(){
      return m_transport;
    }

    std::shared_ptr<trezor_callback> getCallback(){
      return m_callback;
    }

    /* ======================================================================= */
    /*                              SETUP/TEARDOWN                             */
    /* ======================================================================= */
    bool set_name(const std::string &name) override;

    const std::string get_name() const override;
    bool init(void) override;
    bool release() override;
    bool connect(void) override;
    bool disconnect() override;

    /* ======================================================================= */
    /*  LOCKER                                                                 */
    /* ======================================================================= */
    void lock(void)  override;
    void unlock(void) override;
    bool try_lock(void) override;

    /* ======================================================================= */
    /*                              TREZOR PROTOCOL                            */
    /* ======================================================================= */

    /**
     * Device ping, no-throw
     */
    bool ping();
  };

#endif

}
}
#endif //MONERO_DEVICE_TREZOR_BASE_H
