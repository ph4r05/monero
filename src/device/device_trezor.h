//
// Created by Dusan Klinec on 01/08/2018.
//

#ifndef MONERO_DEVICE_TREZOR_H
#define MONERO_DEVICE_TREZOR_H


#include <cstddef>
#include <string>
#include "device.hpp"
#include "device_default.hpp"
#include <boost/scope_exit.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include "cryptonote_config.h"
#include "wallet/wallet2.h"

// TODO: propagate to all targets
#ifndef WITH_DEVICE_TREZOR
#define WITH_DEVICE_TREZOR 1
#endif

#if WITH_DEVICE_TREZOR
#include "trezor/transport.h"
#include "trezor/messages/messages.pb.h"
#include "trezor/messages/messages-common.pb.h"
#include "trezor/messages/messages-management.pb.h"
#include "trezor/messages/messages-monero.pb.h"
#include "trezor/protocol.h"
#endif

namespace hw {
namespace trezor {

  void register_all(std::map<std::string, std::unique_ptr<device>> &registry);

#if WITH_DEVICE_TREZOR
  class device_trezor;

  /**
   * Default trezor protocol client callback
   */
  class trezor_callback {
  private:
    device_trezor & device;

  public:
    trezor_callback() = default;
    explicit trezor_callback(device_trezor & device): device(device) {}

    std::shared_ptr<google::protobuf::Message> on_button_request(const messages::common::ButtonRequest * msg){
      MDEBUG("on_botton_request");
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
   * Main device
   */
  class device_trezor : public hw::core::device_default {
    private:
      // Locker for concurrent access
      mutable boost::recursive_mutex   device_locker;
      mutable boost::mutex   command_locker;
      std::shared_ptr<Transport> m_transport;
      std::shared_ptr<trezor_callback> m_callback;

      // hw running mode
      device_mode mode;
      std::string full_name;

      // To speed up blockchain parsing the view key maybe handle here.
      crypto::secret_key viewkey;
      cryptonote::network_type network_type;

      bool has_view_key;

      //
      // Internal methods
      //

      void require_connected();

      /**
       * Client communication wrapper, handles specific Trezor protocol.
       *
       * @tparam t_message
       * @param transport
       * @param req
       * @param resp
       * @param resp_type
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

        // Scoped session closer
        BOOST_SCOPE_EXIT_ALL(&, this) {
          if (open_session && depth == 0){
            this->getTransport()->close();
          }
        };

        // Open session if required
        if (open_session && depth == 0){
          bool r = m_transport->open();
          if (!r){
            throw exc::SessionException("Could not open session");
          }
        }

        // Write the request
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
          for(size_t i = 0; i < sizeof(DEFAULT_BIP44_PATH)/sizeof(DEFAULT_BIP44_PATH[0]); ++i){
            msg->add_address_n(DEFAULT_BIP44_PATH[i]);
          }
        }

        if (network_type){
          msg->set_network_type(static_cast<uint32_t>(network_type.get()));
        } else {
          msg->set_network_type(static_cast<uint32_t>(this->network_type));
        }
      }

    // High level protocol ping
    //bool ping();

    public:
      device_trezor();
      ~device_trezor() override;

      device_trezor(const device_trezor &device) = delete ;
      device_trezor& operator=(const device_trezor &device) = delete;

      explicit operator bool() const override {return true;}

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

      bool set_mode(device_mode mode) override;

      /* ======================================================================= */
      /*  LOCKER                                                                 */
      /* ======================================================================= */
      void lock(void)  override;
      void unlock(void) override;
      bool try_lock(void) override;

      /* ======================================================================= */
      /*                             WALLET & ADDRESS                            */
      /* ======================================================================= */
      bool  get_public_address(cryptonote::account_public_address &pubkey) override;
      bool  get_secret_keys(crypto::secret_key &viewkey , crypto::secret_key &spendkey) override;

      /* ======================================================================= */
      /*                              TREZOR PROTOCOL                            */
      /* ======================================================================= */

      /**
       * Device ping, no-throw
       * @return
       */
      bool ping();

      /**
       * Get address. Throws.
       * @param path
       * @param network_type
       * @return
       */
      std::shared_ptr<messages::monero::MoneroAddress> get_address(
          boost::optional<std::vector<uint32_t>> path = boost::none,
          boost::optional<cryptonote::network_type> network_type = boost::none);

      /**
       * Get watch key from device. Throws.
       * @param path
       * @param network_type
       * @return
       */
      std::shared_ptr<messages::monero::MoneroWatchKey> get_watch_key(
          boost::optional<std::vector<uint32_t>> path = boost::none,
          boost::optional<cryptonote::network_type> network_type = boost::none);

      /**
       * Key image sync with the Trezor.
       * @param wallet
       * @param transfers
       * @param ski
       */
      void ki_sync(::tools::wallet2 * wallet,
                   const std::vector<tools::wallet2::transfer_details> & transfers,
                   protocol::exported_key_image & ski);

      /**
       * Signs unsigned transaction with the Trezor.
       * @param wallet
       * @param unsigned_tx
       */
      void tx_sign(::tools::wallet2 * wallet,
                   const tools::wallet2::unsigned_tx_set & unsigned_tx);
    };

#endif

}
}
#endif //MONERO_DEVICE_TREZOR_H
