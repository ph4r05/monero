//
// Created by Dusan Klinec on 06/08/2018.
//

#include "protocol.h"
#include "crypto/poly1305.h"
#include <unordered_map>
#include <set>
#include <boost/endian/conversion.hpp>

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

  Signer::Signer(tools::wallet2 *wallet2, std::shared_ptr<const unsigned_tx_set> unsigned_tx) {
    m_wallet2 = wallet2;
    m_unsigned_tx = unsigned_tx;
  }

  void Signer::sign(){

  }

}



}
}
}
