//
// Created by Dusan Klinec on 06/08/2018.
//

#include "protocol.h"
#include <unordered_map>
#include <set>

namespace hw{
namespace trezor{
namespace protocol{

  std::string key_to_string(const crypto::ec_point & key){
    return std::string(key.data, 32);
  }

  std::string key_to_string(const crypto::ec_scalar & key){
    return std::string(key.data, 32);
  }

// Key image sync
namespace ki {

  bool key_image_data(tools::wallet2 * wallet,
                      const std::vector<tools::wallet2::transfer_details> & transfers,
                      std::vector<MoneroTransferDetails> & res)
  {
    using MoneroTransferDetails = messages::monero::MoneroKeyImageSyncStepRequest_MoneroTransferDetails;

    for(auto & td : transfers){
      if (td.m_tx.vout.empty()){
        throw std::invalid_argument("Tx with no outputs");
      }

      crypto::public_key tx_pub_key = wallet->get_tx_pub_key_from_received_outs(td);
      const std::vector<crypto::public_key> additional_tx_pub_keys = cryptonote::get_additional_tx_pub_keys_from_extra(td.m_tx);

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

}
}
}