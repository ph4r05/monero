//
// Created by Dusan Klinec on 06/08/2018.
//

#ifndef MONERO_PROTOCOL_H
#define MONERO_PROTOCOL_H

#include "messages_map.h"
#include "transport.h"
#include "wallet/wallet2.h"

namespace hw{
namespace trezor{
namespace protocol{

  using MoneroTransferDetails = messages::monero::MoneroKeyImageSyncStepRequest_MoneroTransferDetails;
  using MoneroSubAddressIndicesList = messages::monero::MoneroKeyImageExportInitRequest_MoneroSubAddressIndicesList;
  using MoneroExportedKeyImage = messages::monero::MoneroKeyImageSyncStepAck_MoneroExportedKeyImage;

  using exported_key_image = std::vector<std::pair<crypto::key_image, crypto::signature>>;

  std::string key_to_string(const ::crypto::ec_point & key);
  std::string key_to_string(const ::crypto::ec_scalar & key);
  std::string key_to_string(const ::crypto::hash & key);
  std::string key_to_string(const ::rct::key & key);

  void string_to_key(::crypto::ec_scalar & key, const std::string & str);
  void string_to_key(::crypto::ec_point & key, const std::string & str);
  void string_to_key(::rct::key & key, const std::string & str);

  template<class sub_t, class InputIterator>
  void assign_to_repeatable(::google::protobuf::RepeatedField<sub_t> * dst, const InputIterator begin, const InputIterator end){
    for (InputIterator it = begin; it != end; it++) {
      auto s = dst->Add();
      *s = *it;
    }
  }

  template<class sub_t, class InputIterator>
  void assign_from_repeatable(std::vector<sub_t> * dst, const InputIterator begin, const InputIterator end){
    for (InputIterator it = begin; it != end; it++) {
      dst->push_back(*it);
    }
  };

  template<typename T>
  bool cn_deserialize(const void * buff, size_t len, T & dst){
    std::stringstream ss;
    ss.write(static_cast<const char *>(buff), len);  //ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, dst);
    return r;
  }

  template<typename T>
  bool cn_deserialize(const std::string & str, T & dst){
    return cn_deserialize(str.data(), str.size(), dst);
  }

// Crypto / encryption
namespace crypto {
  /**
   * Constant time comparison.
   * @param a
   * @param b
   * @param len
   * @return
   */
  int ct_equal(const char *a, const char *b, size_t len);

namespace chacha {

  /**
   * Chacha20Poly1305 decryption with tag verification.
   * @param data
   * @param length
   * @param key
   * @param iv
   * @param cipher
   */
  void decrypt(const void* data, size_t length, const uint8_t* key, const uint8_t* iv, char* cipher);

}
}


// Key image sync
namespace ki {

  /**
   * Converts transfer details to the MoneroTransferDetails required for KI sync
   * @param wallet
   * @param transfers
   * @param res
   * @return
   */
  bool key_image_data(tools::wallet2 * wallet,
                      const std::vector<tools::wallet2::transfer_details> & transfers,
                      std::vector<MoneroTransferDetails> & res);

  /**
   * Computes a hash over MoneroTransferDetails. Commitment used in the KI sync.
   * @param rr
   * @return
   */
  std::string compute_hash(const MoneroTransferDetails & rr);

  /**
   * Generates KI sync request with commitments computed.
   * @param mtds
   * @param transfers
   * @param req
   * @return
   */
  bool generate_commitment(std::vector<MoneroTransferDetails> & mtds,
                           const std::vector<tools::wallet2::transfer_details> & transfers,
                           std::shared_ptr<messages::monero::MoneroKeyImageExportInitRequest> & req);

}

namespace tx {
  using TsxData = messages::monero::MoneroTransactionInitRequest_MoneroTransactionData;
  using MoneroTransactionDestinationEntry = messages::monero::MoneroTransactionInitRequest_MoneroTransactionData_MoneroTransactionDestinationEntry;
  using MoneroAccountPublicAddress = messages::monero::MoneroTransactionInitRequest_MoneroTransactionData_MoneroTransactionDestinationEntry_MoneroAccountPublicAddress;

  using tx_construction_data = tools::wallet2::tx_construction_data;
  using unsigned_tx_set = tools::wallet2::unsigned_tx_set;

  typedef std::string hmac_t;

  void translate_address(MoneroAccountPublicAddress * dst, const cryptonote::account_public_address * src);
  void translate_dst_entry(MoneroTransactionDestinationEntry * dst, const cryptonote::tx_destination_entry * src);

  class TData {
  public:
    TsxData tsx_data;
    tx_construction_data tx_data;
    cryptonote::transaction tx;
    bool in_memory;
    size_t cur_input_idx;
    size_t cur_output_idx;

    std::vector<hmac_t> tx_in_hmacs;
    std::vector<hmac_t> tx_out_entr_hmacs;
    std::vector<hmac_t> tx_out_hmacs;
    std::vector<rct::rangeSig> tx_out_rsigs;
    std::vector<rct::ctkey> tx_out_pk;
    std::vector<rct::ecdhTuple> tx_out_ecdh;
    std::vector<size_t> source_permutation;
    std::vector<std::string> alphas;
    std::vector<std::string> spend_encs;
    std::vector<std::string> pseudo_outs;
    std::vector<std::string> pseudo_outs_hmac;
    std::vector<std::string> couts;
    std::vector<std::string> couts_dec;
    std::string tx_prefix_hash;
    std::string enc_salt1;
    std::string enc_salt2;
    std::vector<std::string> enc_keys;

    std::shared_ptr<rct::rctSig> rv;
  };

  class Signer {
  private:
    TData m_ct;
    tools::wallet2 * m_wallet2;

    size_t m_tx_idx;
    std::shared_ptr<const unsigned_tx_set> m_unsigned_tx;

    bool m_multisig;

    const tx_construction_data & cur_tx(){
      return m_unsigned_tx->txes[m_tx_idx];
    }

    void extract_payment_id();

  public:
    Signer(tools::wallet2 * wallet2, std::shared_ptr<const unsigned_tx_set> unsigned_tx, size_t tx_idx = 0);

    std::shared_ptr<messages::monero::MoneroTransactionInitRequest> step_init();
    void step_init_ack(std::shared_ptr<const messages::monero::MoneroTransactionInitAck> ack);

    std::shared_ptr<messages::monero::MoneroTransactionSetInputRequest> step_set_input(size_t idx);
    void step_set_input_ack(std::shared_ptr<const messages::monero::MoneroTransactionSetInputAck> ack);

    void sort_ki();
    std::shared_ptr<messages::monero::MoneroTransactionInputsPermutationRequest> step_permutation();
    void step_permutation_ack(std::shared_ptr<const messages::monero::MoneroTransactionInputsPermutationAck> ack);

    std::shared_ptr<messages::monero::MoneroTransactionInputViniRequest> step_set_vini_input(size_t idx);
    void step_set_vini_input_ack(std::shared_ptr<const messages::monero::MoneroTransactionInputViniAck> ack);

    std::shared_ptr<messages::monero::MoneroTransactionSetOutputRequest> step_set_output(size_t idx);
    void step_set_output_ack(std::shared_ptr<const messages::monero::MoneroTransactionSetOutputAck> ack);

    std::shared_ptr<messages::monero::MoneroTransactionAllOutSetRequest> step_all_outs_set();
    void step_all_outs_set_ack(std::shared_ptr<const messages::monero::MoneroTransactionAllOutSetAck> ack);

    std::shared_ptr<messages::monero::MoneroTransactionMlsagDoneRequest> step_pre_mlsag_done();
    void step_pre_mlsag_done_ack(std::shared_ptr<const messages::monero::MoneroTransactionMlsagDoneAck> ack, hw::device &hwdev);

    std::shared_ptr<messages::monero::MoneroTransactionSignInputRequest> step_sign_input(size_t idx);
    void step_sign_input_ack(std::shared_ptr<const messages::monero::MoneroTransactionSignInputAck> ack);

    std::shared_ptr<messages::monero::MoneroTransactionFinalRequest> step_final(size_t idx);
    void step_final_ack(std::shared_ptr<const messages::monero::MoneroTransactionFinalAck> ack);

    bool in_memory(){
      return m_ct.in_memory;
    }

    bool is_simple(){
      if (!m_ct.rv){
        throw new std::invalid_argument("RV not initialized");
      }
      auto tp = m_ct.rv->type;
      return tp == rct::RCTTypeSimple || tp == rct::RCTTypeSimpleBulletproof;
    }

    bool is_bulletproof(){
      if (!m_ct.rv){
        throw new std::invalid_argument("RV not initialized");
      }
      auto tp = m_ct.rv->type;
      return tp == rct::RCTTypeSimpleBulletproof || tp == rct::RCTTypeFullBulletproof;
    }

  };

}

}
}
}


#endif //MONERO_PROTOCOL_H
