//
// Created by Dusan Klinec on 01/08/2018.
//

#include "device_trezor.h"

#if WITH_DEVICE_TREZOR
#include "trezor/messages/messages.pb.h"
#include "trezor/messages/messages-common.pb.h"
#include "trezor/messages/messages-management.pb.h"
#include "trezor/messages/messages-monero.pb.h"
#include "trezor/protocol.h"
#endif

namespace hw {
namespace trezor {

#if WITH_DEVICE_TREZOR

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor"

    static device_trezor *trezor_device = nullptr;
    void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
      if (!trezor_device) {
        trezor_device = new device_trezor();
        trezor_device->set_name("Trezor");
      }
      registry.insert(std::make_pair("Trezor", std::unique_ptr<device>(trezor_device)));
    }

    const uint32_t device_trezor::DEFAULT_BIP44_PATH[] = {0x8000002c, 0x80000080, 0x80000000, 0, 0};

    device_trezor::device_trezor() {

    }

    device_trezor::~device_trezor() {

    }

    /* ======================================================================= */
    /*                              SETUP/TEARDOWN                             */
    /* ======================================================================= */

    bool device_trezor::reset(void) {
      return false;
    }

    bool device_trezor::set_name(const std::string & name) {
      this->name = name;
      return true;
    }

    const std::string device_trezor::get_name() const {
      if (this->full_name.empty()) {
        return std::string("<disconnected:").append(this->name).append(">");
      }
      return this->full_name;
    }

    bool device_trezor::init(void) {
      release();
      if (!m_callback){
        m_callback = std::make_shared<trezor_callback>(*this);
      }

      return true;
    }

    bool device_trezor::release() {
      disconnect();
      return true;
    }

    bool device_trezor::connect(void) {
      disconnect();

      // Enumerate all available devices
      hw::trezor::t_transport_vect trans;
      if (!enumerate(trans)){
        LOG_PRINT_L1("Enumeration failed");
        return false;
      }

      LOG_PRINT_L4("Enumeration yielded " << std::to_string(trans.size()) << " devices");
      for(auto & cur : trans){
        LOG_PRINT_L4(std::string("  device: ") << *(cur.get()));
        std::string cur_path = cur->get_path();
        if (boost::starts_with(cur_path, this->name)){
          MDEBUG("Device Match: " << cur_path);
          m_transport = cur;
          break;
        }
      }

      if (!m_transport){
        return false;
      }

      bool r = m_transport->open();
      // TODO: load watch only credentials / address
      return r;
    }

    bool device_trezor::disconnect() {
      if (m_transport){
        m_transport->close();
      }
      return true;
    }

    bool device_trezor::set_mode(device::device_mode mode) {
      this->mode = mode;
      return true;
    }

    /* ======================================================================= */
    /*  LOCKER                                                                 */
    /* ======================================================================= */

    //automatic lock one more level on device ensuring the current thread is allowed to use it
    #define AUTO_LOCK_CMD() \
      /* lock both mutexes without deadlock*/ \
      boost::lock(device_locker, command_locker); \
      /* make sure both already-locked mutexes are unlocked at the end of scope */ \
      boost::lock_guard<boost::recursive_mutex> lock1(device_locker, boost::adopt_lock); \
      boost::lock_guard<boost::mutex> lock2(command_locker, boost::adopt_lock)

    //lock the device for a long sequence
    void device_trezor::lock(void) {
      MDEBUG( "Ask for LOCKING for device "<<this->name << " in thread ");
      device_locker.lock();
      MDEBUG( "Device "<<this->name << " LOCKed");
    }

    //lock the device for a long sequence
    bool device_trezor::try_lock(void) {
      MDEBUG( "Ask for LOCKING(try) for device "<<this->name << " in thread ");
      bool r = device_locker.try_lock();
      if (r) {
        MDEBUG( "Device "<<this->name << " LOCKed(try)");
      } else {
        MDEBUG( "Device "<<this->name << " not LOCKed(try)");
      }
      return r;
    }

    //lock the device for a long sequence
    void device_trezor::unlock(void) {
      try {
        MDEBUG( "Ask for UNLOCKING for device "<<this->name << " in thread ");
      } catch (...) {
      }
      device_locker.unlock();
      MDEBUG( "Device "<<this->name << " UNLOCKed");
    }

    /* ======================================================================= */
    /*                             WALLET & ADDRESS                            */
    /* ======================================================================= */

    bool device_trezor::get_public_address(cryptonote::account_public_address &pubkey) {
      auto res = get_address();

      cryptonote::address_parse_info info;
      bool r = cryptonote::get_account_address_from_str(info, this->network_type, res->address());
      if (!r){
        LOG_PRINT_L2("Returned address parse fail: " + res->address());
        throw std::runtime_error("Could not parse returned address");
      }

      if (info.is_subaddress){
        throw std::runtime_error("Trezor returned runtime address");
      }

      pubkey = info.address;
      return true;
    }

    bool  device_trezor::get_secret_keys(crypto::secret_key &viewkey , crypto::secret_key &spendkey) {
      auto res = get_watch_key();
      if (res->watch_key().size() != 32){
        throw std::runtime_error("Trezor returned invalid view key");
      }

      spendkey = crypto::null_skey; // not given
      memcpy(viewkey.data, res->watch_key().data(), 32);

      return true;
    }

    /* ======================================================================= */
    /*  Helpers                                                                */
    /* ======================================================================= */

    void device_trezor::require_connected(){
      if (!m_transport){
        throw exc::NotConnectedException();
      }
    }

    /* ======================================================================= */
    /*                              TREZOR PROTOCOL                            */
    /* ======================================================================= */

    bool device_trezor::ping() {
      AUTO_LOCK_CMD();
      if (!m_transport){
        LOG_PRINT_L2("Ping failed, device not connected");
        return false;
      }

      auto pingMsg = std::make_shared<messages::management::Ping>();
      pingMsg->set_message("PING");

      try {
        auto success = this->client_exchange<messages::common::Success>(pingMsg);  // messages::MessageType_Success
        MDEBUG("Ping response " << success->message());
        return true;

      } catch(std::exception const& e) {
        LOG_PRINT_L1(std::string("Ping failed, exception thrown ") << e.what());
      } catch(...){
        LOG_PRINT_L1(std::string("Ping failed, general exception thrown") << boost::current_exception_diagnostic_information());
      }

      return false;
    }

    std::shared_ptr<messages::monero::MoneroAddress> device_trezor::get_address(
        boost::optional<std::vector<uint32_t>> path,
        boost::optional<cryptonote::network_type> network_type){
      AUTO_LOCK_CMD();
      require_connected();

      auto req = std::make_shared<messages::monero::MoneroGetAddress>();
      this->set_msg_addr<messages::monero::MoneroGetAddress>(req.get(), path, network_type);

      auto response = this->client_exchange<messages::monero::MoneroAddress>(req);
      MDEBUG("Get address response received");
      return response;
    }

    std::shared_ptr<messages::monero::MoneroWatchKey> device_trezor::get_watch_key(
        boost::optional<std::vector<uint32_t>> path,
        boost::optional<cryptonote::network_type> network_type){
      AUTO_LOCK_CMD();
      require_connected();

      auto req = std::make_shared<messages::monero::MoneroGetWatchKey>();
      this->set_msg_addr<messages::monero::MoneroGetWatchKey>(req.get(), path, network_type);

      auto response = this->client_exchange<messages::monero::MoneroWatchKey>(req);
      MDEBUG("Get watch key response received");
      return response;
    }

    void device_trezor::ki_sync(tools::wallet2 * wallet,
                                const std::vector<tools::wallet2::transfer_details> & transfers,
                                protocol::exported_key_image & ski)
    {
      AUTO_LOCK_CMD();
      require_connected();

      std::shared_ptr<messages::monero::MoneroKeyImageExportInitRequest> req;

      std::vector<protocol::MoneroTransferDetails> mtds;
      std::vector<protocol::MoneroExportedKeyImage> kis;
      protocol::ki::key_image_data(wallet, transfers, mtds);

      bool res = protocol::ki::generate_commitment(mtds, transfers, req);
      this->set_msg_addr<messages::monero::MoneroKeyImageExportInitRequest>(req.get());

      auto env = std::make_shared<messages::monero::MoneroKeyImageSyncRequest>();
      env->set_allocated_init(req.get());
      auto ack1 = this->client_exchange<messages::monero::MoneroKeyImageExportInitAck>(env);

      const auto batch_size = 10;
      const auto num_batches = static_cast<uint64_t>(ceil(mtds.size() / static_cast<double>(batch_size)));
      for(uint64_t cur = 0; cur < num_batches; ++cur){
        auto step_req = std::make_shared<messages::monero::MoneroKeyImageSyncStepRequest>();
        auto idx_finish = std::min(static_cast<uint64_t>((cur + 1) * batch_size), static_cast<uint64_t>(mtds.size()));
        for(uint64_t idx = cur * batch_size; idx < idx_finish; ++idx){
          auto added_tdis = step_req->add_tdis();
          *added_tdis = mtds[idx];
        }

        env = std::make_shared<messages::monero::MoneroKeyImageSyncRequest>();
        env->set_allocated_step(step_req.get());

        auto step_ack = this->client_exchange<messages::monero::MoneroKeyImageSyncStepAck>(env);
        auto kis_size = step_ack->kis_size();
        for(int i = 0; i < kis_size; ++i){
          auto ckis = step_ack->kis(i);
          kis.push_back(ckis);
        }
      }

      auto final_req = std::make_shared<messages::monero::MoneroKeyImageSyncFinalRequest>();
      env = std::make_shared<messages::monero::MoneroKeyImageSyncRequest>();
      env->set_allocated_final_msg(final_req.get());
      auto final_ack = this->client_exchange<messages::monero::MoneroKeyImageSyncFinalAck>(env);

      for(auto & sub : kis){
        char buff[32*3];
        protocol::crypto::chacha::decrypt(sub.blob().data(), sub.blob().size(),
                                          reinterpret_cast<const uint8_t *>(final_ack->enc_key().data()),
                                          reinterpret_cast<const uint8_t *>(sub.iv().data()), buff);

        ::crypto::signature sig;
        ::crypto::key_image ki;
        memcpy(ki.data, buff, 32);
        memcpy(sig.c.data, buff + 32, 32);
        memcpy(sig.r.data, buff + 64, 32);
        ski.push_back(std::make_pair(ki, sig));
      }
    }


    void device_trezor::tx_sign(::tools::wallet2 * wallet, const tools::wallet2::unsigned_tx_set & unsigned_tx){
      std::shared_ptr<const tools::wallet2::unsigned_tx_set> unsigned_tx_ptr(std::addressof(unsigned_tx));
      size_t num_tx = unsigned_tx.txes.size();

      for(size_t tx_idx = 0; tx_idx < num_tx; ++tx_idx) {
        auto signer = std::make_shared<protocol::tx::Signer>(wallet, unsigned_tx_ptr, tx_idx);
        auto & cur_tx = unsigned_tx.txes[tx_idx];
        auto num_sources = cur_tx.sources.size();
        auto num_outputs = cur_tx.splitted_dsts.size();

        // Step: Init
        auto init_msg = signer->step_init();
        this->set_msg_addr(init_msg.get());
        auto req_msg = std::make_shared<messages::monero::MoneroTransactionSignRequest>();
        req_msg->mutable_init()->CopyFrom(*init_msg);

        auto response = this->client_exchange<messages::monero::MoneroTransactionInitAck>(req_msg);
        signer->step_init_ack(response);

        // Step: Set transaction inputs
        for(size_t cur_src = 0; cur_src < num_sources; ++cur_src){
          auto src = signer->step_set_input(cur_src);
          auto req = std::make_shared<messages::monero::MoneroTransactionSignRequest>();
          req->mutable_set_input()->CopyFrom(*src);

          auto ack = this->client_exchange<messages::monero::MoneroTransactionSetInputAck>(req);
          signer->step_set_input_ack(ack);
        }

        // Step: Permute

      }




    }

#else //WITH_DEVICE_TREZOR

    void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
    }

#endif //WITH_DEVICE_TREZOR
}}