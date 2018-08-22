//
// Created by Dusan Klinec on 01/08/2018.
//

#include "device_trezor.hpp"

namespace hw {
namespace trezor {

#if WITH_DEVICE_TREZOR

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor"

#define HW_TREZOR_NAME "Trezor"

    static device_trezor *trezor_device = nullptr;
    static device_trezor *ensure_trezor_device(){
      if (!trezor_device) {
        trezor_device = new device_trezor();
        trezor_device->set_name(HW_TREZOR_NAME);
      }
      return trezor_device;
    }

    void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
      registry.insert(std::make_pair(HW_TREZOR_NAME, std::unique_ptr<device>(ensure_trezor_device())));
    }

    void register_all() {
      hw::register_device(HW_TREZOR_NAME, ensure_trezor_device());
    }

    const uint32_t device_trezor::DEFAULT_BIP44_PATH[] = {0x8000002c, 0x80000080, 0x80000000, 0, 0};

    device_trezor::device_trezor() {

    }

    device_trezor::~device_trezor() {
      try {
        disconnect();
        release();
      } catch(std::exception & e){
        LOG_PRINT_L1(std::string("Could not disconnect and release: ") + e.what());
      }
    }

    /* ======================================================================= */
    /*                              SETUP/TEARDOWN                             */
    /* ======================================================================= */

    bool device_trezor::reset(void) {
      return false;
    }

    bool device_trezor::set_name(const std::string & name) {
      this->full_name = name;
      this->name = name;

      auto delim = name.find(':');
      if (delim != std::string::npos) {
        this->name = name.substr(delim + 1);
      }

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
      return r;
    }

    bool device_trezor::disconnect() {
      if (m_transport){
        m_transport->close();
        m_transport = nullptr;
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

    void device_trezor::call_ping_unsafe(){
      auto pingMsg = std::make_shared<messages::management::Ping>();
      pingMsg->set_message("PING");

      auto success = this->client_exchange<messages::common::Success>(pingMsg);  // messages::MessageType_Success
      MDEBUG("Ping response " << success->message());
      (void)success;
    }

    void device_trezor::test_ping(){
      require_connected();

      try {
        this->call_ping_unsafe();

      } catch(exc::TrezorException & e){
        LOG_PRINT_L2(std::string("Trezor does not respond: ") + e.what());
        throw exc::DeviceNotResponsiveException(std::string("Trezor not responding: ") + e.what());
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

      try {
        this->call_ping_unsafe();
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
      test_ping();

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
      test_ping();

      auto req = std::make_shared<messages::monero::MoneroGetWatchKey>();
      this->set_msg_addr<messages::monero::MoneroGetWatchKey>(req.get(), path, network_type);

      auto response = this->client_exchange<messages::monero::MoneroWatchKey>(req);
      MDEBUG("Get watch key response received");
      return response;
    }

    void device_trezor::ki_sync(wallet_shim * wallet,
                                const std::vector<tools::wallet2::transfer_details> & transfers,
                                hw::device_cold::exported_key_image & ski)
    {
      AUTO_LOCK_CMD();
      require_connected();
      test_ping();

      std::shared_ptr<messages::monero::MoneroKeyImageExportInitRequest> req;

      std::vector<protocol::MoneroTransferDetails> mtds;
      std::vector<protocol::MoneroExportedKeyImage> kis;
      protocol::ki::key_image_data(wallet, transfers, mtds);

      bool res = protocol::ki::generate_commitment(mtds, transfers, req);
      this->set_msg_addr<messages::monero::MoneroKeyImageExportInitRequest>(req.get());

      auto env = std::make_shared<messages::monero::MoneroKeyImageSyncRequest>();
      env->mutable_init()->CopyFrom(*req);
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
        env->mutable_step()->CopyFrom(*step_req);

        auto step_ack = this->client_exchange<messages::monero::MoneroKeyImageSyncStepAck>(env);
        auto kis_size = step_ack->kis_size();
        for(int i = 0; i < kis_size; ++i){
          auto ckis = step_ack->kis(i);
          kis.push_back(ckis);
        }
      }

      auto final_req = std::make_shared<messages::monero::MoneroKeyImageSyncFinalRequest>();
      env = std::make_shared<messages::monero::MoneroKeyImageSyncRequest>();
      env->mutable_final_msg()->CopyFrom(*final_req);
      auto final_ack = this->client_exchange<messages::monero::MoneroKeyImageSyncFinalAck>(env);

      for(auto & sub : kis){
        char buff[32*3];
        protocol::crypto::chacha::decrypt(sub.blob().data(), sub.blob().size(),
                                          reinterpret_cast<const uint8_t *>(final_ack->enc_key().data()),
                                          reinterpret_cast<const uint8_t *>(sub.iv().data()), buff);

        ::crypto::signature sig{};
        ::crypto::key_image ki;
        memcpy(ki.data, buff, 32);
        memcpy(sig.c.data, buff + 32, 32);
        memcpy(sig.r.data, buff + 64, 32);
        ski.push_back(std::make_pair(ki, sig));
      }
    }


    void device_trezor::tx_sign(wallet_shim * wallet,
                                const tools::wallet2::unsigned_tx_set & unsigned_tx,
                                tools::wallet2::signed_tx_set & signed_tx,
                                std::vector<std::string> & aux_info)
    {
      size_t num_tx = unsigned_tx.txes.size();
      signed_tx.key_images.clear();
      signed_tx.key_images.resize(unsigned_tx.transfers.size());

      for(size_t tx_idx = 0; tx_idx < num_tx; ++tx_idx) {
        std::shared_ptr<protocol::tx::Signer> signer;
        tx_sign(wallet, unsigned_tx, tx_idx, signer);

        auto & cdata = signer->tdata();
        auto aux_info_cur = signer->store_tx_aux_info();
        aux_info.emplace_back(aux_info_cur);

        // Pending tx reconstruction
        signed_tx.ptx.emplace_back();
        auto & cpend = signed_tx.ptx.back();
        cpend.tx = cdata.tx;
        cpend.dust = 0;
        cpend.fee = 0;
        cpend.dust_added_to_fee = false;
        cpend.change_dts = cdata.tx_data.change_dts;
        cpend.selected_transfers = cdata.tx_data.selected_transfers;
        cpend.key_images = "";
        cpend.dests = cdata.tx_data.dests;
        cpend.construction_data = cdata.tx_data;

        std::string key_images;
        bool all_are_txin_to_key = std::all_of(cdata.tx.vin.begin(), cdata.tx.vin.end(), [&](const cryptonote::txin_v& s_e) -> bool
        {
          CHECKED_GET_SPECIFIC_VARIANT(s_e, const cryptonote::txin_to_key, in, false);
          key_images += boost::to_string(in.k_image) + " ";
          return true;
        });
        if(!all_are_txin_to_key) {
          throw std::invalid_argument("Not all are txin_to_key");
        }
        cpend.key_images = key_images;

        // KI sync
        size_t num_sources = cdata.tx_data.sources.size();
        for(size_t src_idx = 0; src_idx < num_sources; ++src_idx){
          size_t idx_mapped = cdata.source_permutation[src_idx];
          size_t idx_map_src = cdata.tx_data.selected_transfers[idx_mapped];
          auto vini = boost::get<cryptonote::txin_to_key>(cdata.tx.vin[src_idx]);
          signed_tx.key_images[idx_map_src] = vini.k_image;
        }
      }
    }

    void device_trezor::tx_sign(wallet_shim * wallet,
                   const tools::wallet2::unsigned_tx_set & unsigned_tx,
                   size_t idx,
                   std::shared_ptr<protocol::tx::Signer> & signer)
    {
      AUTO_LOCK_CMD();
      require_connected();
      test_ping();

      signer = std::make_shared<protocol::tx::Signer>(wallet, std::addressof(unsigned_tx), idx);
      auto & cur_tx = unsigned_tx.txes[idx];
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

      // Step: sort
      auto perm_req = signer->step_permutation();
      if (perm_req){
        req_msg = std::make_shared<messages::monero::MoneroTransactionSignRequest>();
        req_msg->mutable_input_permutation()->CopyFrom(*perm_req);

        auto perm_ack = this->client_exchange<messages::monero::MoneroTransactionInputsPermutationAck>(req_msg);
        signer->step_permutation_ack(perm_ack);
      }

      // Step: input_vini
      if (!signer->in_memory()){
        for(size_t cur_src = 0; cur_src < num_sources; ++cur_src){
          auto src = signer->step_set_vini_input(cur_src);
          auto req = std::make_shared<messages::monero::MoneroTransactionSignRequest>();
          req->mutable_input_vini()->CopyFrom(*src);

          auto ack = this->client_exchange<messages::monero::MoneroTransactionInputViniAck>(req);
          signer->step_set_vini_input_ack(ack);
        }
      }

      // Step: outputs
      for(size_t cur_dst = 0; cur_dst < num_outputs; ++cur_dst){
        auto src = signer->step_set_output(cur_dst);
        auto req = std::make_shared<messages::monero::MoneroTransactionSignRequest>();
        req->mutable_set_output()->CopyFrom(*src);

        auto ack = this->client_exchange<messages::monero::MoneroTransactionSetOutputAck>(req);
        signer->step_set_output_ack(ack);
      }

      // Step: all outs set
      auto all_out_set = signer->step_all_outs_set();
      req_msg = std::make_shared<messages::monero::MoneroTransactionSignRequest>();
      req_msg->mutable_all_out_set()->CopyFrom(*all_out_set);

      auto ack_all_out_set = this->client_exchange<messages::monero::MoneroTransactionAllOutSetAck>(req_msg);
      signer->step_all_outs_set_ack(ack_all_out_set);

      // Step: MlsagDone
      auto pre_mlsag_done = signer->step_pre_mlsag_done();
      req_msg = std::make_shared<messages::monero::MoneroTransactionSignRequest>();
      req_msg->mutable_mlsag_done()->CopyFrom(*pre_mlsag_done);

      auto ack_pre_mlsag_done = this->client_exchange<messages::monero::MoneroTransactionMlsagDoneAck>(req_msg);
      signer->step_pre_mlsag_done_ack(ack_pre_mlsag_done, *this);

      // Step: sign each input
      for(size_t cur_src = 0; cur_src < num_sources; ++cur_src){
        auto src = signer->step_sign_input(cur_src);
        auto req = std::make_shared<messages::monero::MoneroTransactionSignRequest>();
        req->mutable_sign_input()->CopyFrom(*src);

        auto ack_sign = this->client_exchange<messages::monero::MoneroTransactionSignInputAck>(req);
        signer->step_sign_input_ack(ack_sign);
      }

      // Step: final
      auto final_msg = signer->step_final();
      req_msg = std::make_shared<messages::monero::MoneroTransactionSignRequest>();
      req_msg->mutable_final_msg()->CopyFrom(*final_msg);

      auto ack_final = this->client_exchange<messages::monero::MoneroTransactionFinalAck>(req_msg);
      signer->step_final_ack(ack_final);
    }

#else //WITH_DEVICE_TREZOR

    void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
    }

    void register_all() {
    }

#endif //WITH_DEVICE_TREZOR
}}