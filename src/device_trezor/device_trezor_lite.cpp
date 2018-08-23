#include <utility>

//
// Created by Dusan Klinec on 01/08/2018.
//

#include "device_trezor_lite.hpp"
#include "device/device_ledger.hpp"

namespace hw {
namespace trezor {

#if WITH_DEVICE_TREZOR

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor"

#define INS_NONE                            0x00
#define INS_RESET                           0x02

#define INS_GET_KEY                         0x20
#define INS_PUT_KEY                         0x22
#define INS_GET_CHACHA8_PREKEY              0x24
#define INS_VERIFY_KEY                      0x26

#define INS_SECRET_KEY_TO_PUBLIC_KEY        0x30
#define INS_GEN_KEY_DERIVATION              0x32
#define INS_DERIVATION_TO_SCALAR            0x34
#define INS_DERIVE_PUBLIC_KEY               0x36
#define INS_DERIVE_SECRET_KEY               0x38
#define INS_GEN_KEY_IMAGE                   0x3A
#define INS_SECRET_KEY_ADD                  0x3C
#define INS_SECRET_KEY_SUB                  0x3E
#define INS_GENERATE_KEYPAIR                0x40
#define INS_SECRET_SCAL_MUL_KEY             0x42
#define INS_SECRET_SCAL_MUL_BASE            0x44

#define INS_DERIVE_SUBADDRESS_PUBLIC_KEY    0x46
#define INS_GET_SUBADDRESS                  0x48
#define INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY 0x4A
#define INS_GET_SUBADDRESS_SECRET_KEY       0x4C

#define INS_OPEN_TX                         0x70
#define INS_SET_SIGNATURE_MODE              0x72
#define INS_GET_ADDITIONAL_KEY              0x74
#define INS_STEALTH                         0x76
#define INS_BLIND                           0x78
#define INS_UNBLIND                         0x7A
#define INS_VALIDATE                        0x7C
#define INS_MLSAG                           0x7E
#define INS_CLOSE_TX                        0x80

#define INS_GET_RESPONSE                    0xc0


#define ASSERT_X(exp,msg)    CHECK_AND_ASSERT_THROW_MES(exp, msg);

    static bool is_fake_view_key(const crypto::secret_key &sec) {
      return sec == crypto::null_skey;
    }

    bool operator==(const crypto::key_derivation &d0, const crypto::key_derivation &d1) {
      return !memcmp(&d0, &d1, sizeof(d0));
    }

    device_trezor_lite::device_trezor_lite() {
      this->mode = NONE;
      this->has_view_key = false;
      this->m_lite_initialized = false;
      this->m_lite_sec_keys_loaded = false;
    }

    device_trezor_lite::~device_trezor_lite() {
      try {
        disconnect();
        release();
      } catch(std::exception & e){
        LOG_PRINT_L1(std::string("Could not disconnect and release: ") + e.what());
      }
    }

    void device_trezor_lite::init_lite(
        boost::optional<std::vector<uint32_t>> path,
        boost::optional<cryptonote::network_type> network_type){

      auto req = std::make_shared<messages::monero::MoneroLiteInitRequest>();
      this->set_msg_addr(req.get(), std::move(path), std::move(network_type));

      auto ack = this->client_exchange<messages::monero::MoneroLiteInitAck>(req);
      m_lite_initialized = true;
    }

    void device_trezor_lite::init_load_keys(){
      crypto::secret_key vkey;
      crypto::secret_key skey;
      m_lite_sec_keys_loaded = true;
      try {
        this->get_secret_keys(vkey, skey);

      } catch(std::exception & e){
        m_lite_sec_keys_loaded = false;
        throw e;
      }
    }

    void device_trezor_lite::exchange_lite(){
      if (!m_lite_initialized){
        this->init_lite();
      }

      auto req = comm.build_request();
      auto ack = this->client_exchange<messages::monero::MoneroLiteAck>(req);

      if (ack->sw() != 0x9000){
        throw exc::ProtocolException(std::string("Card returned error: ") + std::to_string(ack->sw())
        + " for ins: " + std::to_string(comm.get_ins()));
      }

      comm.on_msg_received(ack.get());
    }

    void device_trezor_lite::send_simple(uint8_t ins, uint8_t p1, uint8_t p2){
      comm.set_header(ins, p1, p2);
      this->exchange_lite();
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


    /* ======================================================================= */
    /*  LITE                                                                   */
    /* ======================================================================= */

    bool  device_trezor_lite::set_mode(device_mode mode) {
      AUTO_LOCK_CMD();
      switch(mode) {
        case TRANSACTION_CREATE_REAL:
        case TRANSACTION_CREATE_FAKE:
          comm.set_header(INS_SET_SIGNATURE_MODE, 1);

          //account
          comm.insert_u8(mode);
          this->exchange_lite();
          this->mode = mode;
          break;

        case TRANSACTION_PARSE:
        case NONE:
          this->mode = mode;
          break;
        default:
          CHECK_AND_ASSERT_THROW_MES(false, " device_trezor_lite::set_mode(unsigned int mode): invalid mode: "<<mode);
      }
      MDEBUG("Switch to mode: " <<mode);
      return true;
    }


    /* ======================================================================= */
    /*                             WALLET & ADDRESS                            */
    /* ======================================================================= */

    bool device_trezor_lite::get_public_address(cryptonote::account_public_address &pubkey){
      AUTO_LOCK_CMD();

      send_simple(INS_GET_KEY, 1);
      comm.fetch(pubkey.m_view_public_key.data);
      comm.fetch(pubkey.m_spend_public_key.data);

      return true;
    }

    bool  device_trezor_lite::get_secret_keys(crypto::secret_key &vkey , crypto::secret_key &skey) {
      AUTO_LOCK_CMD();

      //secret key are represented as fake key on the wallet side
      memset(vkey.data, 0x00, 32);
      memset(skey.data, 0xFF, 32);

      //spcialkey, normal conf handled in decrypt
      send_simple(INS_GET_KEY, 0x02);

      //View key is retrievied, if allowed, to speed up blockchain parsing
      comm.fetch(this->viewkey.data);
      m_lite_sec_keys_loaded = true;

      if (is_fake_view_key(this->viewkey)) {
        MDEBUG("Have Not view key");
        this->has_view_key = false;
      } else {
        MDEBUG("Have view key");
        this->has_view_key = true;
      }

      return true;
    }

    bool  device_trezor_lite::generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key, uint64_t kdf_rounds) {
      AUTO_LOCK_CMD();

      send_simple(INS_GET_CHACHA8_PREKEY);

      char prekey[200];
      comm.fetch(prekey, 200);
      crypto::generate_chacha_key_prehashed(&prekey[0], sizeof(prekey), key, kdf_rounds);

      return true;
    }

    /* ======================================================================= */
    /*                               SUB ADDRESS                               */
    /* ======================================================================= */

    bool device_trezor_lite::derive_subaddress_public_key(const crypto::public_key &pub, const crypto::key_derivation &derivation, const std::size_t output_index, crypto::public_key &derived_pub){
      AUTO_LOCK_CMD();

      if ((this->mode == TRANSACTION_PARSE) && has_view_key) {
        //If we are in TRANSACTION_PARSE, the given derivation has been retrieved uncrypted (wihtout the help
        //of the device), so continue that way.
        MDEBUG( "derive_subaddress_public_key  : PARSE mode with known viewkey");
        crypto::derive_subaddress_public_key(pub, derivation, output_index, derived_pub);
      } else {

        comm.set_header(INS_DERIVE_SUBADDRESS_PUBLIC_KEY);
        comm.insert(pub.data);
        comm.insert(derivation.data);
        comm.insert_u32((uint32_t) output_index);
        this->exchange_lite();

        comm.fetch(derived_pub.data);
      }

      return true;
    }

    crypto::public_key device_trezor_lite::get_subaddress_spend_public_key(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) {
      AUTO_LOCK_CMD();
      crypto::public_key D;

      if (index.is_zero()) {
        D = keys.m_account_address.m_spend_public_key;

      } else {
        comm.set_header(INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY);

        static_assert(sizeof(cryptonote::subaddress_index) == 8, "cryptonote::subaddress_index shall be 8 bytes length");
        comm.insert(&index, sizeof(cryptonote::subaddress_index));
        this->exchange_lite();

        comm.fetch(D.data);
      }

      return D;
    }

    std::vector<crypto::public_key>  device_trezor_lite::get_subaddress_spend_public_keys(const cryptonote::account_keys &keys, uint32_t account, uint32_t begin, uint32_t end) {
      std::vector<crypto::public_key> pkeys;
      cryptonote::subaddress_index index = {account, begin};
      crypto::public_key D;
      for (uint32_t idx = begin; idx < end; ++idx) {
        index.minor = idx;
        D = this->get_subaddress_spend_public_key(keys, index);
        pkeys.push_back(D);
      }
      return pkeys;
    }

    cryptonote::account_public_address device_trezor_lite::get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) {
      AUTO_LOCK_CMD();
      cryptonote::account_public_address address{};

      if (index.is_zero()) {
        address = keys.m_account_address;
      } else {
        comm.set_header(INS_GET_SUBADDRESS);

        static_assert(sizeof(cryptonote::subaddress_index) == 8, "cryptonote::subaddress_index shall be 8 bytes length");
        comm.insert(&index, sizeof(cryptonote::subaddress_index));
        this->exchange_lite();

        comm.fetch(address.m_view_public_key.data);
        comm.fetch(address.m_spend_public_key.data);
      }

      return address;
    }

    crypto::secret_key  device_trezor_lite::get_subaddress_secret_key(const crypto::secret_key &sec, const cryptonote::subaddress_index &index) {
      AUTO_LOCK_CMD();
      crypto::secret_key sub_sec;

      comm.set_header(INS_GET_SUBADDRESS_SECRET_KEY);
      comm.insert(sec.data);

      static_assert(sizeof(cryptonote::subaddress_index) == 8, "cryptonote::subaddress_index shall be 8 bytes length");
      comm.insert(&index, sizeof(cryptonote::subaddress_index));
      this->exchange_lite();

      comm.fetch(sub_sec.data);
      return sub_sec;
    }

    /* ======================================================================= */
    /*                            DERIVATION & KEY                             */
    /* ======================================================================= */

    bool  device_trezor_lite::verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) {
      AUTO_LOCK_CMD();

      comm.set_header(INS_VERIFY_KEY);
      comm.insert(secret_key.data);
      comm.insert(public_key.data);
      this->exchange_lite();

      uint32_t verified = comm.fetch_u32();
      return verified == 1;
    }

    bool device_trezor_lite::scalarmultKey(rct::key & aP, const rct::key &P, const rct::key &a) {
      AUTO_LOCK_CMD();

      comm.set_header(INS_SECRET_SCAL_MUL_KEY);
      comm.insert(P.bytes);
      comm.insert(a.bytes);
      this->exchange_lite();

      comm.fetch(aP.bytes);
      return true;
    }

    bool device_trezor_lite::scalarmultBase(rct::key &aG, const rct::key &a) {
      AUTO_LOCK_CMD();

      comm.set_header(INS_SECRET_SCAL_MUL_BASE);
      comm.insert(a.bytes);
      this->exchange_lite();

      comm.fetch(aG.bytes);
      return true;
    }

    bool device_trezor_lite::sc_secret_add( crypto::secret_key &r, const crypto::secret_key &a, const crypto::secret_key &b) {
      AUTO_LOCK_CMD();

      comm.set_header(INS_SECRET_KEY_ADD);
      comm.insert(a.data);
      comm.insert(b.data);
      this->exchange_lite();

      //pub key
      comm.fetch(r.data);
      return true;
    }

    crypto::secret_key  device_trezor_lite::generate_keys(crypto::public_key &pub, crypto::secret_key &sec, const crypto::secret_key& recovery_key, bool recover) {
      AUTO_LOCK_CMD();
      if (recover) {
        throw std::runtime_error("device generate key does not support recover");
      }

      send_simple(INS_GENERATE_KEYPAIR);
      comm.fetch(pub.data);
      comm.fetch(sec.data);
      return sec;
    }

    bool device_trezor_lite::generate_key_derivation(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_derivation &derivation) {
      AUTO_LOCK_CMD();
      bool r = false;

      if ((this->mode == TRANSACTION_PARSE)  && has_view_key) {
        //A derivation is resquested in PASRE mode and we have the view key,
        //so do that wihtout the device and return the derivation unencrypted.
        MDEBUG( "generate_key_derivation  : PARSE mode with known viewkey");
        //Note derivation in PARSE mode can only happen with viewkey, so assert it!
        assert(is_fake_view_key(sec));
        r = crypto::generate_key_derivation(pub, this->viewkey, derivation);
        
      } else {
        comm.set_header(INS_GEN_KEY_DERIVATION);
        comm.insert(pub.data);
        comm.insert(sec.data);
        this->exchange_lite();

        //derivattion data
        comm.fetch(derivation.data);
        r = true;
      }
      return r;
    }

    bool device_trezor_lite::conceal_derivation(crypto::key_derivation &derivation, const crypto::public_key &tx_pub_key, const std::vector<crypto::public_key> &additional_tx_pub_keys, const crypto::key_derivation &main_derivation, const std::vector<crypto::key_derivation> &additional_derivations) {
      const crypto::public_key *pkey = nullptr;
      if (derivation == main_derivation) {
        pkey = &tx_pub_key;
        MDEBUG("conceal derivation with main tx pub key");

      } else {
        for(size_t n=0; n < additional_derivations.size();++n) {
          if(derivation == additional_derivations[n]) {
            pkey = &additional_tx_pub_keys[n];
            MDEBUG("conceal derivation with additionnal tx pub key");
            break;
          }
        }
      }

      ASSERT_X(pkey, "Mismatched derivation on scan info");
      return this->generate_key_derivation(*pkey,  crypto::null_skey, derivation);
    }

    bool device_trezor_lite::derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res) {
      AUTO_LOCK_CMD();

      comm.set_header(INS_DERIVATION_TO_SCALAR);
      comm.insert(derivation.data);
      comm.insert_u32((uint32_t) output_index);
      this->exchange_lite();

      //derivattion data
      comm.fetch(res.data);
      return true;
    }

    bool device_trezor_lite::derive_secret_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &sec, crypto::secret_key &derived_sec) {
      AUTO_LOCK_CMD();

      comm.set_header(INS_DERIVE_SECRET_KEY);
      comm.insert(derivation.data);
      comm.insert_u32((uint32_t) output_index);
      comm.insert(sec.data);
      this->exchange_lite();

      //pub key
      comm.fetch(derived_sec.data);
      return true;
    }

    bool device_trezor_lite::derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &pub, crypto::public_key &derived_pub){
      AUTO_LOCK_CMD();

      comm.set_header(INS_DERIVE_PUBLIC_KEY);
      comm.insert(derivation.data);
      comm.insert_u32((uint32_t) output_index);
      comm.insert(pub.data);
      this->exchange_lite();

      //pub key
      comm.fetch(derived_pub.data);
      return true;
    }

    bool device_trezor_lite::secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub) {
      AUTO_LOCK_CMD();

      comm.set_header(INS_SECRET_KEY_TO_PUBLIC_KEY);
      comm.insert(sec.data);
      this->exchange_lite();

      comm.fetch(pub.data);
      return true;
    }

    bool device_trezor_lite::generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image){
      AUTO_LOCK_CMD();

      comm.set_header(INS_GEN_KEY_IMAGE);
      comm.insert(pub.data);
      comm.insert(sec.data);
      this->exchange_lite();

      //pub key
      comm.fetch(image.data);
      return true;
    }

    /* ======================================================================= */
    /*                               TRANSACTION                               */
    /* ======================================================================= */

    bool device_trezor_lite::open_tx(crypto::secret_key &tx_key) {
      AUTO_LOCK_CMD();

      key_map.clear();
      comm.set_header(INS_OPEN_TX, 0x01);

      //account
      comm.insert_u32(0);
      this->exchange_lite();

      comm.read_skip(32);
      comm.fetch(tx_key.data);
      return true;
    }

    bool device_trezor_lite::encrypt_payment_id(crypto::hash8 &payment_id, const crypto::public_key &public_key, const crypto::secret_key &secret_key) {
      AUTO_LOCK_CMD();

      comm.set_header(INS_STEALTH);
      comm.insert(public_key.data);
      comm.insert(secret_key.data);
      comm.insert(payment_id.data, 8);
      this->exchange_lite();

      comm.fetch(payment_id.data, 8);
      return true;
    }

    bool device_trezor_lite::add_output_key_mapping(const crypto::public_key &Aout, const crypto::public_key &Bout, const bool is_subaddress, const size_t real_output_index,
                                               const rct::key &amount_key,  const crypto::public_key &out_eph_public_key)  {
      AUTO_LOCK_CMD();
      key_map.add(hw::ledger::ABPkeys(rct::pk2rct(Aout),rct::pk2rct(Bout), is_subaddress, real_output_index, rct::pk2rct(out_eph_public_key), amount_key));
      return true;
    }

    bool  device_trezor_lite::ecdhEncode(rct::ecdhTuple & unmasked, const rct::key & AKout) {
      AUTO_LOCK_CMD();

      comm.set_header(INS_BLIND);
      comm.insert(AKout.bytes);
      comm.insert(unmasked.mask.bytes);
      comm.insert(unmasked.amount.bytes);
      this->exchange_lite();

      comm.fetch(unmasked.amount.bytes);
      comm.fetch(unmasked.mask.bytes);
      return true;
    }

    bool  device_trezor_lite::ecdhDecode(rct::ecdhTuple & masked, const rct::key & AKout) {
      AUTO_LOCK_CMD();

      comm.set_header(INS_UNBLIND);
      comm.insert(AKout.bytes);
      comm.insert(masked.mask.bytes);
      comm.insert(masked.amount.bytes);
      this->exchange_lite();

      comm.fetch(masked.amount.bytes);
      comm.fetch(masked.mask.bytes);
      return true;
    }

    bool device_trezor_lite::mlsag_prehash(const std::string &blob, size_t inputs_size, size_t outputs_size,
                                      const rct::keyV &hashes, const rct::ctkeyV &outPk,
                                      rct::key &prehash) {
      AUTO_LOCK_CMD();
      unsigned int  data_offset, C_offset, kv_offset, i;
      const char *data;
      
      data = blob.data();

      // ======  u8 type, varint txnfee ======
      comm.set_header(INS_VALIDATE, 0x01, 0x01);
      comm.insert_u8(static_cast<uint8_t>((inputs_size == 0) ? 0x00 : 0x80));  // options
      
      //type
      uint8_t type = (uint8_t) data[0];
      comm.insert_u8(type);
      
      //txnfee
      data_offset = 1;
      while (data[data_offset] & 0x80) {
        comm.insert(&data[data_offset]);
        data_offset += 1;
      }
      comm.insert(&data[data_offset]);
      data_offset += 1;
      this->exchange_lite();

      //pseudoOuts
      if ((type == rct::RCTTypeSimple) || (type == rct::RCTTypeSimpleBulletproof)) {
        for ( i = 0; i < inputs_size; i++) {
          comm.set_header(INS_VALIDATE, 0x01, static_cast<uint8_t>(i + 2));
          comm.insert_u8(static_cast<uint8_t>((i == inputs_size - 1) ? 0x00 : 0x80));
          comm.insert(data+data_offset);
          data_offset += 32;
          this->exchange_lite();
        }
      }

      // ======  Aout, Bout, AKout, C, v, k ======
      kv_offset = data_offset;
      C_offset = static_cast<unsigned int>(kv_offset + (32 * 2) * outputs_size);
      for ( i = 0; i < outputs_size; i++) {
        hw::ledger::ABPkeys outKeys;
        bool found;

        found = this->key_map.find(outPk[i].dest, outKeys);
        if (!found) {
          // log_hexbuffer("Pout not found", (char*)outPk[i].dest.bytes, 32);
          CHECK_AND_ASSERT_THROW_MES(found, "Pout not found");
        }

        comm.set_header(INS_VALIDATE, 0x02, static_cast<uint8_t>(i + 1));
        comm.insert_u8(static_cast<uint8_t>((i == outputs_size - 1) ? 0x00 : 0x80));

        if (found) {
          comm.insert_u8(outKeys.is_subaddress);
          comm.insert(outKeys.Aout.bytes);
          comm.insert(outKeys.Bout.bytes);
          comm.insert(outKeys.AKout.bytes);
        } else {
          // dummy: is_subaddress Aout Bout AKout
          comm.insert_skip(1+32*3);
        }

        //C
        comm.insert(data+C_offset);
        C_offset += 32;

        //k
        comm.insert(data+kv_offset);
        kv_offset += 32;

        //v
        comm.insert(data+kv_offset);
        kv_offset += 32;
        this->exchange_lite();
      }

      // ======   C[], message, proof======
      C_offset = kv_offset;
      for (i = 0; i < outputs_size; i++) {
        comm.set_header(INS_VALIDATE, 0x03, static_cast<uint8_t>(i + 1));
        comm.insert_u8(0x80);
        comm.insert(data+C_offset);
        C_offset += 32;
        this->exchange_lite();
      }

      comm.set_header(INS_VALIDATE, 0x03, static_cast<uint8_t>(i + 1));
      comm.insert(hashes[0].bytes);
      comm.insert(hashes[2].bytes);
      this->exchange_lite();

      comm.fetch(prehash.bytes);
      return true;
    }


    bool device_trezor_lite::mlsag_prepare(const rct::key &H, const rct::key &xx,
                                      rct::key &a, rct::key &aG, rct::key &aHP, rct::key &II) {
      AUTO_LOCK_CMD();

      comm.set_header(INS_MLSAG, 0x01);
      comm.insert(H.bytes);
      comm.insert(xx.bytes);
      this->exchange_lite();

      comm.fetch(a.bytes);
      comm.fetch(aG.bytes);
      comm.fetch(aHP.bytes);
      comm.fetch(II.bytes);
      return true;
    }

    bool device_trezor_lite::mlsag_prepare(rct::key &a, rct::key &aG) {
      AUTO_LOCK_CMD();

      send_simple(INS_MLSAG, 0x01);
      comm.fetch(a.bytes);
      comm.fetch(aG.bytes);
      return true;
    }

    bool device_trezor_lite::mlsag_hash(const rct::keyV &long_message, rct::key &c) {
      AUTO_LOCK_CMD();
      size_t cnt;

      cnt = long_message.size();
      for (size_t i = 0; i<cnt; i++) {
        comm.set_header(INS_MLSAG, 0x02, i+1);
        comm.insert_u8((i==(cnt-1))?0x00:0x80); // options, last
        comm.insert(long_message[i].bytes);
        this->exchange_lite();
      }

      comm.fetch(c.bytes);
      return true;
    }

    bool device_trezor_lite::mlsag_sign(const rct::key &c, const rct::keyV &xx, const rct::keyV &alpha, const size_t rows, const size_t dsRows, rct::keyV &ss) {
      AUTO_LOCK_CMD();

      CHECK_AND_ASSERT_THROW_MES(dsRows<=rows, "dsRows greater than rows");
      CHECK_AND_ASSERT_THROW_MES(xx.size() == rows, "xx size does not match rows");
      CHECK_AND_ASSERT_THROW_MES(alpha.size() == rows, "alpha size does not match rows");
      CHECK_AND_ASSERT_THROW_MES(ss.size() == rows, "ss size does not match rows");

      for (size_t j = 0; j < dsRows; j++) {
        comm.set_header(INS_MLSAG, 0x03, static_cast<uint8_t>(j + 1));
        comm.insert_u8(static_cast<uint8_t>(j == (dsRows - 1) ? 0x80 : 0x00));
        comm.insert(xx[j].bytes);
        comm.insert(alpha[j].bytes);
        this->exchange_lite();

        comm.fetch(ss[j].bytes);
      }

      for (size_t j = dsRows; j < rows; j++) {
        sc_mulsub(ss[j].bytes, c.bytes, xx[j].bytes, alpha[j].bytes);
      }

      return true;
    }

    bool device_trezor_lite::close_tx() {
      AUTO_LOCK_CMD();
      send_simple(INS_CLOSE_TX);
      return true;
    }

    bool device_trezor_lite::connect(void) {
      bool r = device_trezor_base::connect();
      this->init_load_keys();
      return r;
    }

    bool device_trezor_lite::disconnect() {
      bool r = device_trezor_base::disconnect();
      return r;
    }

    /* ======================================================================= */
    /*                              TREZOR PROTOCOL                            */
    /* ======================================================================= */


#endif //WITH_DEVICE_TREZOR
}}
