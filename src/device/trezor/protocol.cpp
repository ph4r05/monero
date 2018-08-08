//
// Created by Dusan Klinec on 06/08/2018.
//

#include "protocol.h"
#include "crypto/poly1305.h"
#include <unordered_map>
#include <set>
#include <boost/endian/conversion.hpp>
#include <utility>

namespace hw{
namespace trezor{
namespace protocol{

  std::string key_to_string(const ::crypto::ec_point & key){
    return std::string(key.data, 32);
  }

  std::string key_to_string(const ::crypto::ec_scalar & key){
    return std::string(key.data, 32);
  }

namespace crypto {
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
  }

  void Signer::extract_payment_id(){
    const std::vector<uint8_t>& tx_extra = cur_tx().extra;
    m_ct.tsx_data.clear_payment_id();

    std::vector<cryptonote::tx_extra_field> tx_extra_fields;
    cryptonote::parse_tx_extra(tx_extra, tx_extra_fields); // ok if partially parsed
    cryptonote::tx_extra_nonce extra_nonce;

    ::crypto::hash payment_id;
    if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
    {
      ::crypto::hash8 payment_id8;
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

    m_ct.tx.vin.push_back(vini);
    m_ct.tx_in_hmacs.push_back(ack->vini_hmac());
    m_ct.pseudo_outs.push_back(ack->pseudo_out());
    m_ct.pseudo_outs_hmac.push_back(ack->pseudo_out_hmac());
    m_ct.alphas.push_back(ack->alpha_enc());
    m_ct.spend_encs.push_back(ack->spend_enc());
  }

  void Signer::sign(){
    this->step_init();

  }

}



}
}
}
