//
// Created by Dusan Klinec on 06/08/2018.
//

#include "protocol.h"
#include "crypto/poly1305.h"
#include <unordered_map>
#include <set>
#include <utility>
#include <boost/endian/conversion.hpp>
#include <common/apply_permutation.h>
#include <ringct/rctSigs.h>

namespace hw{
namespace trezor{
namespace protocol{

  std::string key_to_string(const ::crypto::ec_point & key){
    return std::string(key.data, 32);
  }

  std::string key_to_string(const ::crypto::ec_scalar & key){
    return std::string(key.data, 32);
  }

  std::string key_to_string(const ::crypto::hash & key){
    return std::string(key.data, 32);
  }

  std::string key_to_string(const ::rct::key & key){
    return std::string(reinterpret_cast<const char*>(key.bytes), 32);
  }

  void string_to_key(::crypto::ec_scalar & key, const std::string & str){
    if (str.size() != 32){
      throw std::invalid_argument("Key has to have 32 B");
    }
    memcpy(key.data, str.data(), 32);
  }

  void string_to_key(::crypto::ec_point & key, const std::string & str){
    if (str.size() != 32){
      throw std::invalid_argument("Key has to have 32 B");
    }
    memcpy(key.data, str.data(), 32);
  }

  void string_to_key(::rct::key & key, const std::string & str){
    if (str.size() != 32){
      throw std::invalid_argument("Key has to have 32 B");
    }
    memcpy(key.bytes, str.data(), 32);
  }

namespace crypto {

    int ct_equal(const char *a, const char *b, size_t len) {
    size_t i;
    unsigned int dif = 0;
    for (i = 0; i < len; i++)
      dif |= (a[i] ^ b[i]);
    dif = (dif - 1) >> ((sizeof(unsigned int) * 8) - 1);
    return (dif & 1);
  }

namespace chacha {

  static void poly1305_key(const uint8_t* key, const uint8_t* iv, char* poly_key){
    uint8_t zeros[32] = {0};
    ::crypto::chacha20(zeros, 32, key, iv, poly_key);
  }

  void decrypt(const void* data, size_t length, const uint8_t* key, const uint8_t* iv, char* cipher){
    if (length < 16){
      throw std::invalid_argument("Ciphertext lentgh too small");
    }

    auto cip_data = reinterpret_cast<const char*>(data);
    unsigned char zeros[32] = {0};
    const char * tag = cip_data + (length - 16);
    char expected_tag[16] = {0};
    length -= 16;

    // generate poly key
    char poly_key[32];
    poly1305_key(key, iv, poly_key);
    ::crypto::poly1305_context poly_ctx;
    ::crypto::poly1305_init(&poly_ctx, reinterpret_cast<const unsigned char *>(poly_key));
    ::crypto::poly1305_update(&poly_ctx, reinterpret_cast<const unsigned char *>(cip_data), length);
    if (length % 16 != 0){
      ::crypto::poly1305_update(&poly_ctx, zeros, 16 - (length % 16));
    }

    uint64_t len_ciphertext_small = boost::endian::native_to_little(static_cast<uint64_t>(length));
    ::crypto::poly1305_update(&poly_ctx, zeros, 8);  // authenticated data length
    ::crypto::poly1305_update(&poly_ctx, reinterpret_cast<const unsigned char *>(&len_ciphertext_small), 8);
    ::crypto::poly1305_finish(&poly_ctx, reinterpret_cast<unsigned char *>(expected_tag));

    memset(&poly_ctx, 0, sizeof(::crypto::poly1305_context));
    memset(poly_key, 0, 32);
    if (!::crypto::poly1305_verify(reinterpret_cast<const unsigned char *>(tag),
                                   reinterpret_cast<const unsigned char *>(expected_tag))){
      throw exc::Poly1305TagInvalid();
    }

    ::crypto::chacha20(cip_data, length, key, iv, cipher);
  }

}
}


// Key image sync
namespace ki {

  bool key_image_data(tools::wallet2 * wallet,
                      const std::vector<tools::wallet2::transfer_details> & transfers,
                      std::vector<MoneroTransferDetails> & res)
  {
    for(auto & td : transfers){
      if (td.m_tx.vout.empty()){
        throw std::invalid_argument("Tx with no outputs");
      }

      ::crypto::public_key tx_pub_key = wallet->get_tx_pub_key_from_received_outs(td);
      const std::vector<::crypto::public_key> additional_tx_pub_keys = cryptonote::get_additional_tx_pub_keys_from_extra(td.m_tx);

      res.emplace_back();
      auto & cres = res.back();

      cres.set_out_key(key_to_string(boost::get<cryptonote::txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key));
      cres.set_tx_pub_key(key_to_string(tx_pub_key));
      cres.set_internal_output_index(td.m_internal_output_index);
      for(auto & aux : additional_tx_pub_keys){
        cres.add_additional_tx_pub_keys(key_to_string(aux));
      }
    }

    return true;
  }

  std::string compute_hash(const MoneroTransferDetails & rr){
    KECCAK_CTX kck;
    uint8_t md[32];

    keccak_init(&kck);
    keccak_update(&kck, reinterpret_cast<const uint8_t *>(rr.out_key().data()), 32);
    keccak_update(&kck, reinterpret_cast<const uint8_t *>(rr.tx_pub_key().data()), 32);
    for (const auto &aux : rr.additional_tx_pub_keys()){
      keccak_update(&kck, reinterpret_cast<const uint8_t *>(aux.data()), 32);
    }

    auto index_serialized = tools::get_varint_data(rr.internal_output_index());
    keccak_update(&kck, reinterpret_cast<const uint8_t *>(index_serialized.data()), index_serialized.size());
    keccak_finish(&kck, md);
    return std::string(reinterpret_cast<const char*>(md), 32);
  }

  bool generate_commitment(std::vector<MoneroTransferDetails> & mtds,
                           const std::vector<tools::wallet2::transfer_details> & transfers,
                           std::shared_ptr<messages::monero::MoneroKeyImageExportInitRequest> & req)
  {
    req = std::make_shared<messages::monero::MoneroKeyImageExportInitRequest>();

    KECCAK_CTX kck;
    uint8_t final_hash[32];
    keccak_init(&kck);

    for(auto &cur : mtds){
      auto hash = compute_hash(cur);
      keccak_update(&kck, reinterpret_cast<const uint8_t *>(hash.data()), hash.size());
    }
    keccak_finish(&kck, final_hash);

    req = std::make_shared<messages::monero::MoneroKeyImageExportInitRequest>();
    req->set_hash(std::string(reinterpret_cast<const char*>(final_hash), 32));

    std::unordered_map<uint32_t, std::set<uint32_t>> sub_indices;
    for (auto &cur : transfers){
      auto search = sub_indices.emplace(cur.m_subaddr_index.major, std::set<uint32_t>());
      auto & st = search.first->second;
      st.insert(cur.m_subaddr_index.minor);
    }

    for (auto& x: sub_indices){
      auto subs = req->add_subs();
      subs->set_account(x.first);
      for(auto minor : x.second){
        subs->add_minor_indices(minor);
      }
    }

    return true;
  }

}

// Transaction signing
namespace tx {

  void translate_address(MoneroAccountPublicAddress * dst, const cryptonote::account_public_address * src){
    dst->set_view_public_key(key_to_string(src->m_view_public_key));
    dst->set_spend_public_key(key_to_string(src->m_spend_public_key));
  }

  void translate_dst_entry(MoneroTransactionDestinationEntry * dst, const cryptonote::tx_destination_entry * src){
    dst->set_amount(src->amount);
    dst->set_is_subaddress(src->is_subaddress);
    translate_address(dst->mutable_addr(), std::addressof(src->addr));
  }

  Signer::Signer(tools::wallet2 *wallet2, std::shared_ptr<const unsigned_tx_set> unsigned_tx, size_t tx_idx) {
    m_wallet2 = wallet2;
    m_unsigned_tx = std::move(unsigned_tx);
    m_tx_idx = tx_idx;
    m_ct.tx_data = cur_tx();
    m_multisig = false;
  }

  void Signer::extract_payment_id(){
    const std::vector<uint8_t>& tx_extra = cur_tx().extra;
    m_ct.tsx_data.clear_payment_id();

    std::vector<cryptonote::tx_extra_field> tx_extra_fields;
    cryptonote::parse_tx_extra(tx_extra, tx_extra_fields); // ok if partially parsed
    cryptonote::tx_extra_nonce extra_nonce;

    ::crypto::hash payment_id{};
    if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
    {
      ::crypto::hash8 payment_id8{};
      if(cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
      {
        m_ct.tsx_data.set_payment_id(std::string(payment_id8.data, 8));
      }
      else if (cryptonote::get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
      {
        m_ct.tsx_data.set_payment_id(std::string(payment_id.data, 32));
      }
    }
  }

  std::shared_ptr<messages::monero::MoneroTransactionInitRequest> Signer::step_init(){
    // extract payment ID from construction data
    auto & tsx_data = m_ct.tsx_data;
    auto & tx = cur_tx();

    m_ct.tx.version = 2;
    m_ct.tx.unlock_time = tx.unlock_time;

    tsx_data.set_version(1);
    tsx_data.set_unlock_time(tx.unlock_time);
    tsx_data.set_num_inputs(static_cast<google::protobuf::uint32>(tx.sources.size()));
    tsx_data.set_mixin(static_cast<google::protobuf::uint32>(tx.sources[0].outputs.size()));
    tsx_data.set_account(tx.subaddr_account);
    assign_to_repeatable(tsx_data.mutable_minor_indices(), tx.subaddr_indices.begin(), tx.subaddr_indices.end());
    tsx_data.set_is_bulletproof(false);
    tsx_data.set_is_multisig(false);

    translate_dst_entry(tsx_data.mutable_change_dts(), std::addressof(tx.change_dts));
    for(auto & cur : tx.splitted_dsts){
      auto dst = tsx_data.mutable_outputs()->Add();
      translate_dst_entry(dst, std::addressof(cur));
    }

    int64_t fee = 0;
    for(auto & cur_in : tx.sources){
      fee += cur_in.amount;
    }
    for(auto & cur_out : tx.splitted_dsts){
      fee -= cur_out.amount;
    }
    if (fee < 0){
      throw std::invalid_argument("Fee cannot be negative");
    }

    tsx_data.set_fee(static_cast<google::protobuf::uint64>(fee));
    this->extract_payment_id();

    auto init_req = std::make_shared<messages::monero::MoneroTransactionInitRequest>();
    init_req->set_version(0);
    init_req->mutable_tsx_data()->CopyFrom(tsx_data);
    return init_req;
  }

  void Signer::step_init_ack(std::shared_ptr<const messages::monero::MoneroTransactionInitAck> ack){
    m_ct.in_memory = ack->in_memory();
    assign_from_repeatable(std::addressof(m_ct.tx_out_entr_hmacs), ack->hmacs().begin(), ack->hmacs().end());
  }

  std::shared_ptr<messages::monero::MoneroTransactionSetInputRequest> Signer::step_set_input(size_t idx){
    m_ct.cur_input_idx = idx;
    auto res = std::make_shared<messages::monero::MoneroTransactionSetInputRequest>();
    auto src_bin = cryptonote::t_serializable_object_to_blob(cur_tx().sources[idx]);
    res->set_src_entr(src_bin);
    return res;
  }

  void Signer::step_set_input_ack(std::shared_ptr<const messages::monero::MoneroTransactionSetInputAck> ack){
    auto & vini_str = ack->vini();

    cryptonote::txin_to_key vini;
    if (!cn_deserialize(vini_str.data(), vini_str.size(), vini)){
      throw exc::ProtocolException("Cannot deserialize vin[i]");
    }

    m_ct.tx.vin.emplace_back(vini);
    m_ct.tx_in_hmacs.push_back(ack->vini_hmac());
    m_ct.pseudo_outs.push_back(ack->pseudo_out());
    m_ct.pseudo_outs_hmac.push_back(ack->pseudo_out_hmac());
    m_ct.alphas.push_back(ack->alpha_enc());
    m_ct.spend_encs.push_back(ack->spend_enc());
  }

  void Signer::sort_ki(){
    m_ct.source_permutation.clear();
    for (size_t n = 0; n < cur_tx().sources.size(); ++n){
      m_ct.source_permutation.push_back(n);
    }

    std::sort(m_ct.source_permutation.begin(), m_ct.source_permutation.end(), [&](const size_t i0, const size_t i1) {
      const cryptonote::txin_to_key &tk0 = boost::get<cryptonote::txin_to_key>(m_ct.tx.vin[i0]);
      const cryptonote::txin_to_key &tk1 = boost::get<cryptonote::txin_to_key>(m_ct.tx.vin[i1]);
      return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
    });

    tools::apply_permutation(m_ct.source_permutation, [&](size_t i0, size_t i1){
      std::swap(m_ct.tx.vin[i0], m_ct.tx.vin[i1]);
      std::swap(m_ct.tx_in_hmacs[i0], m_ct.tx_in_hmacs[i1]);
      std::swap(m_ct.pseudo_outs[i0], m_ct.pseudo_outs[i1]);
      std::swap(m_ct.pseudo_outs_hmac[i0], m_ct.pseudo_outs_hmac[i1]);
      std::swap(m_ct.alphas[i0], m_ct.alphas[i1]);
      std::swap(m_ct.spend_encs[i0], m_ct.spend_encs[i1]);
      std::swap(m_ct.tx_data.sources[i0], m_ct.tx_data.sources[i1]);
    });
  }

  std::shared_ptr<messages::monero::MoneroTransactionInputsPermutationRequest> Signer::step_permutation(){
    sort_ki();

    if (!in_memory()){
      return nullptr;
    }

    auto res = std::make_shared<messages::monero::MoneroTransactionInputsPermutationRequest>();
    assign_to_repeatable(res->mutable_perm(), m_ct.source_permutation.begin(), m_ct.source_permutation.end());

    return res;
  }

  void Signer::step_permutation_ack(std::shared_ptr<const messages::monero::MoneroTransactionInputsPermutationAck> ack){
    if (!in_memory()){
      return;
    }
  }

  std::shared_ptr<messages::monero::MoneroTransactionInputViniRequest> Signer::step_set_vini_input(size_t idx){
    if (!in_memory()){
      return nullptr;
    }

    m_ct.cur_input_idx = idx;
    auto tx = m_ct.tx_data;
    auto res = std::make_shared<messages::monero::MoneroTransactionInputViniRequest>();
    res->set_src_entr(cryptonote::t_serializable_object_to_blob(tx.sources[idx]));
    res->set_vini(cryptonote::t_serializable_object_to_blob(m_ct.tx.vin[idx]));
    res->set_vini_hmac(m_ct.tx_in_hmacs[idx]);
    if (!in_memory()) {
      res->set_pseudo_out(m_ct.pseudo_outs[idx]);
      res->set_pseudo_out_hmac(m_ct.pseudo_outs_hmac[idx]);
    }

    return res;
  }

  void Signer::step_set_vini_input_ack(std::shared_ptr<const messages::monero::MoneroTransactionInputViniAck> ack){
    if (!in_memory()){
      return;
    }
  }


  std::shared_ptr<messages::monero::MoneroTransactionSetOutputRequest> Signer::step_set_output(size_t idx){
    m_ct.cur_output_idx = idx;
    auto res = std::make_shared<messages::monero::MoneroTransactionSetOutputRequest>();
    res->set_dst_entr(cryptonote::t_serializable_object_to_blob(m_ct.tx_data.splitted_dsts[idx]));
    res->set_dst_entr_hmac(m_ct.tx_out_entr_hmacs[idx]);
    return res;
  }

  void Signer::step_set_output_ack(std::shared_ptr<const messages::monero::MoneroTransactionSetOutputAck> ack){
    cryptonote::tx_out tx_out;
    rct::rangeSig range_sig;
    rct::ctkey out_pk;
    rct::ecdhTuple ecdh;

    if (!cn_deserialize(ack->tx_out(), tx_out)){
      throw exc::ProtocolException("Cannot deserialize vout[i]");
    }

    if (!cn_deserialize(ack->rsig(), range_sig)){
      throw exc::ProtocolException("Cannot deserialize rangesig");
    }

    if (!cn_deserialize(ack->out_pk(), out_pk)){ // TODO: may be problem, does not have ser?
      throw exc::ProtocolException("Cannot deserialize out_pk");
    }

    if (!cn_deserialize(ack->ecdh_info(), ecdh)){
      throw exc::ProtocolException("Cannot deserialize ecdhtuple");
    }

    m_ct.tx.vout.emplace_back(tx_out);
    m_ct.tx_out_hmacs.push_back(ack->vouti_hmac());
    m_ct.tx_out_rsigs.emplace_back(range_sig);
    m_ct.tx_out_pk.emplace_back(out_pk);
    m_ct.tx_out_ecdh.emplace_back(ecdh);

    if (!rct::verRange(out_pk.mask, m_ct.tx_out_rsigs.back())){
      throw exc::ProtocolException("Returned range signature is invalid");
    }
  }

  std::shared_ptr<messages::monero::MoneroTransactionAllOutSetRequest> Signer::step_all_outs_set(){
    return std::make_shared<messages::monero::MoneroTransactionAllOutSetRequest>();
  }

  void Signer::step_all_outs_set_ack(std::shared_ptr<const messages::monero::MoneroTransactionAllOutSetAck> ack){
    m_ct.rv = std::make_shared<rct::rctSig>();
    m_ct.rv->txnFee = ack->rv().txn_fee();
    m_ct.rv->type = static_cast<uint8_t>(ack->rv().rv_type());
    string_to_key(m_ct.rv->message, ack->rv().message());

    // Extra copy
    m_ct.tx.extra.clear();
    auto extra = ack->extra();
    auto extra_data = extra.data();
    for(size_t i = 0; i < extra.size(); ++i){
      m_ct.tx.extra.push_back(static_cast<uint8_t>(extra_data[i]));
    }

    ::crypto::hash tx_prefix_hash;
    cryptonote::get_transaction_prefix_hash(m_ct.tx, tx_prefix_hash);
    m_ct.tx_prefix_hash = key_to_string(tx_prefix_hash);
    if (!crypto::ct_equal(tx_prefix_hash.data, ack->tx_prefix_hash().data(), 32)){
      throw exc::proto::SecurityException("Transaction prefix has does not match to the computed value");
    }

    // RctSig
    if (is_simple()){
      auto dst = m_ct.rv->pseudoOuts;
      if (is_bulletproof()){
        dst = m_ct.rv->p.pseudoOuts;
      }

      dst.clear();
      for(size_t i = 0; i < m_ct.pseudo_outs.size(); ++i){
        dst.emplace_back();
        string_to_key(dst.back(), m_ct.pseudo_outs[i]);
      }
    }

    // Range proof
    for(size_t i = 0; i < m_ct.tx_out_rsigs.size(); ++i){
      m_ct.rv->p.rangeSigs.push_back(m_ct.tx_out_rsigs[i]);
      m_ct.rv->outPk.push_back(m_ct.tx_out_pk[i]);
      m_ct.rv->ecdhInfo.push_back(m_ct.tx_out_ecdh[i]);
    }
  }

  std::shared_ptr<messages::monero::MoneroTransactionMlsagDoneRequest> Signer::step_pre_mlsag_done(){
    return std::make_shared<messages::monero::MoneroTransactionMlsagDoneRequest>();
  }

  void Signer::step_pre_mlsag_done_ack(std::shared_ptr<const messages::monero::MoneroTransactionMlsagDoneAck> ack, hw::device &hwdev){
    rct::key hash_computed = rct::get_pre_mlsag_hash(*(m_ct.rv), hwdev);
    auto & hash = ack->full_message_hash();

    if (hash.size() != 32){
      throw exc::ProtocolException("Returned mlsag hash has invalid size");
    }

    if (!crypto::ct_equal(reinterpret_cast<const char *>(hash_computed.bytes), hash.data(), 32)){
      throw exc::proto::SecurityException("Computed MLSAG does not match");
    }
  }

  std::shared_ptr<messages::monero::MoneroTransactionSignInputRequest> Signer::step_sign_input(size_t idx){
    m_ct.cur_input_idx = idx;

    auto res = std::make_shared<messages::monero::MoneroTransactionSignInputRequest>();
    res->set_src_entr(cryptonote::t_serializable_object_to_blob(m_ct.tx_data.sources[idx]));
    res->set_vini(cryptonote::t_serializable_object_to_blob(m_ct.tx.vin[idx]));
    res->set_vini_hmac(m_ct.tx_in_hmacs[idx]);
    res->set_alpha_enc(m_ct.alphas[idx]);
    res->set_spend_enc(m_ct.spend_encs[idx]);
    if (!in_memory()){
      res->set_pseudo_out(m_ct.pseudo_outs[idx]);
      res->set_pseudo_out_hmac(m_ct.pseudo_outs_hmac[idx]);
    }
    return res;
  }

  void Signer::step_sign_input_ack(std::shared_ptr<const messages::monero::MoneroTransactionSignInputAck> ack){
    rct::mgSig mg;
    if (!cn_deserialize(ack->signature(), mg)){
      throw exc::ProtocolException("Cannot deserialize mg[i]");
    }

    m_ct.rv->p.MGs.push_back(mg);
    m_ct.couts.push_back(ack->cout());
  }

  std::shared_ptr<messages::monero::MoneroTransactionFinalRequest> Signer::step_final(size_t idx){
    m_ct.tx.rct_signatures = *(m_ct.rv);
    return std::make_shared<messages::monero::MoneroTransactionFinalRequest>();
  }

  void Signer::step_final_ack(std::shared_ptr<const messages::monero::MoneroTransactionFinalAck> ack){
    if (m_multisig){
      auto & cout_key = ack->cout_key();
      for(auto & cur : m_ct.couts){
        if (cur.size() != 12 + 32){
          throw std::invalid_argument("Encrypted cout has invalid length");
        }

        char buff[32];
        auto data = cur.data();

        crypto::chacha::decrypt(data + 12, 32, reinterpret_cast<const uint8_t *>(cout_key.data()), reinterpret_cast<const uint8_t *>(data), buff);
        m_ct.couts_dec.emplace_back(buff, 32);
      }
    }

    m_ct.enc_salt1 = ack->salt();
    m_ct.enc_salt2 = ack->rand_mult();

    m_ct.enc_keys.clear();
    auto & enc_keys = ack->tx_enc_keys();
    auto enc_keys_data = enc_keys.data();
    size_t num_keys = enc_keys.size() / 32;

    for(size_t idx = 0; idx < num_keys; ++idx){
      m_ct.enc_keys.emplace_back(enc_keys_data + (idx*32), 32);
    }
  }


}



}
}
}
