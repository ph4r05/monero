//
// Created by Dusan Klinec on 06/08/2018.
//

#include "protocol.hpp"
#include <unordered_map>
#include <set>
#include <utility>
#include <boost/endian/conversion.hpp>
#include <common/apply_permutation.h>
#include <ringct/rctSigs.h>
#include <ringct/bulletproofs.h>
#include "sodium.h"
#include "sodium/crypto_aead_chacha20poly1305.h"

namespace hw{
namespace trezor{
namespace protocol{

#define BULLETPROOF_MAX_OUTPUTS 16

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

  void decrypt(const void* data, size_t length, const uint8_t* key, const uint8_t* iv, char* cipher){
    if (length < 16){
      throw std::invalid_argument("Ciphertext lentgh too small");
    }

    auto cip_data = reinterpret_cast<const char*>(data);
    unsigned long long int cip_len = length;
    auto r = crypto_aead_chacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char *>(cipher), &cip_len, nullptr,
        static_cast<const unsigned char *>(data), length, nullptr, 0, iv, key);

    if (r != 0){
      throw exc::Poly1305TagInvalid();
    }
  }

}
}


// Cold Key image sync
namespace ki {

  bool key_image_data(wallet_shim * wallet,
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
    req->set_num(transfers.size());

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

// Cold transaction signing
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

  void translate_src_entry(MoneroTransactionSourceEntry * dst, const cryptonote::tx_source_entry * src){
    for(auto & cur : src->outputs){
      auto out = dst->add_outputs();
      out->set_idx(cur.first);
      translate_rct_key(out->mutable_key(), std::addressof(cur.second));
    }

    dst->set_real_output(src->real_output);
    dst->set_real_out_tx_key(key_to_string(src->real_out_tx_key));
    for(auto & cur : src->real_out_additional_tx_keys){
      dst->add_real_out_additional_tx_keys(key_to_string(cur));
    }

    dst->set_real_output_in_tx_index(src->real_output_in_tx_index);
    dst->set_amount(src->amount);
    dst->set_rct(src->rct);
    dst->set_mask(key_to_string(src->mask));
    translate_klrki(dst->mutable_multisig_klrki(), std::addressof(src->multisig_kLRki));
  }

  void translate_klrki(MoneroMultisigKLRki * dst, const rct::multisig_kLRki * src){
    dst->set_k(key_to_string(src->k));
    dst->set_l(key_to_string(src->L));
    dst->set_r(key_to_string(src->R));
    dst->set_ki(key_to_string(src->ki));
  }

  void translate_rct_key(MoneroRctKey * dst, const rct::ctkey * src){
    dst->set_dest(key_to_string(src->dest));
    dst->set_mask(key_to_string(src->mask));
  }

  bool addr_eq(const MoneroAccountPublicAddress * a, const MoneroAccountPublicAddress * b){
    if (a == nullptr && b == nullptr)
      return true;
    if (a == nullptr || b == nullptr)
      return false;
    return a->spend_public_key() == b->spend_public_key() && a->view_public_key() == b->view_public_key();
  }

  std::string hash_addr(const MoneroAccountPublicAddress * addr, boost::optional<uint64_t> amount, boost::optional<bool> is_subaddr){
    return hash_addr(addr->spend_public_key(), addr->view_public_key(), amount, is_subaddr);
  }

  std::string hash_addr(const std::string & spend_key, const std::string & view_key, boost::optional<uint64_t> amount, boost::optional<bool> is_subaddr){
    ::crypto::public_key spend{}, view{};
    if (spend_key.size() != 32 || view_key.size() != 32){
      throw std::invalid_argument("Public keys have invalid sizes");
    }

    memcpy(spend.data, spend_key.data(), 32);
    memcpy(view.data, view_key.data(), 32);
    return hash_addr(&spend, &view, amount, is_subaddr);
  }

  std::string hash_addr(const ::crypto::public_key * spend_key, const ::crypto::public_key * view_key, boost::optional<uint64_t> amount, boost::optional<bool> is_subaddr){
    char buff[64+8+1];
    size_t offset = 0;

    memcpy(buff + offset, spend_key->data, 32); offset += 32;
    memcpy(buff + offset, view_key->data, 32); offset += 32;

    if (amount){
      memcpy(buff + offset, (uint8_t*) &(amount.get()), sizeof(amount.get())); offset += sizeof(amount.get());
    }

    if (is_subaddr){
      buff[offset] = is_subaddr.get();
      offset += 1;
    }

    return std::string(buff, offset);
  }

  TData::TData() {
    in_memory = false;
    rsig_type = 0;
    cur_input_idx = 0;
    cur_output_idx = 0;
    cur_batch_idx = 0;
    cur_output_in_batch_idx = 0;
  }

  Signer::Signer(wallet_shim *wallet2, const unsigned_tx_set * unsigned_tx, size_t tx_idx, hw::tx_aux_data * aux_data) {
    m_wallet2 = wallet2;
    m_unsigned_tx = unsigned_tx;
    m_aux_data = aux_data;
    m_tx_idx = tx_idx;
    m_ct.tx_data = cur_tx();
    m_multisig = false;
  }

  void Signer::extract_payment_id(){
    const std::vector<uint8_t>& tx_extra = cur_tx().extra;
    m_ct.tsx_data.set_payment_id("");

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

  static unsigned get_rsig_type(bool use_bulletproof, size_t num_outputs){
    if (!use_bulletproof){
      return 0;  // Borromean
    } else if (num_outputs > 16){
      return 2;  // Multioutputs
    } else {
      return 3;  // Padded
    }
  }

  static void generate_rsig_batch_sizes(std::vector<uint64_t> &batches, unsigned rsig_type, size_t num_outputs){
    size_t amount_batched = 0;

    while(amount_batched < num_outputs){
      if (rsig_type == 0 || rsig_type == 1) {  // Borromean, BP per output
        batches.push_back(1);
        amount_batched += 1;

      } else if (rsig_type == 3){  // BP padded
        if (num_outputs > 16){
          throw std::invalid_argument("BP padded can support only BULLETPROOF_MAX_OUTPUTS statements");
        }
        batches.push_back(num_outputs);
        amount_batched += num_outputs;

      } else if (rsig_type == 2){  // Multi output
        size_t batch_size = 1;
        while (batch_size * 2 + amount_batched <= num_outputs && batch_size * 2 <= BULLETPROOF_MAX_OUTPUTS){
          batch_size *= 2;
        }
        batch_size = std::min(batch_size, num_outputs - amount_batched);
        batches.push_back(batch_size);
        amount_batched += batch_size;

      } else {
        throw std::invalid_argument("Unknown rsig type");
      }
    }
  }

  void Signer::compute_integrated_indices(TsxData * tsx_data){
    if (m_aux_data == nullptr || m_aux_data->tx_recipients.empty()){
      return;
    }

    auto & chg = tsx_data->change_dts();
    std::string change_hash = hash_addr(&chg.addr(), chg.amount(), chg.is_subaddress());

    std::vector<uint32_t> integrated_indices;
    std::set<std::string> integrated_hashes;
    for (auto & cur : m_aux_data->tx_recipients){
      if (!cur.has_payment_id){
        continue;
      }
      integrated_hashes.emplace(hash_addr(&cur.address.m_spend_public_key, &cur.address.m_view_public_key));
    }

    ssize_t idx = -1;
    for (auto & cur : tsx_data->outputs()){
      idx += 1;

      std::string c_hash = hash_addr(&cur.addr(), cur.amount(), cur.is_subaddress());
      if (c_hash == change_hash || cur.is_subaddress()){
        continue;
      }

      c_hash = hash_addr(&cur.addr());
      if (integrated_hashes.find(c_hash) != integrated_hashes.end()){
        integrated_indices.push_back((uint32_t)idx);
      }
    }

    if (!integrated_indices.empty()){
      assign_to_repeatable(tsx_data->mutable_integrated_indices(), integrated_indices.begin(), integrated_indices.end());
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
    tsx_data.set_is_multisig(false);
    tsx_data.set_exp_tx_prefix_hash("");

    // Rsig decision
    auto rsig_data = tsx_data.mutable_rsig_data();
    m_ct.rsig_type = get_rsig_type(tx.use_bulletproofs, tx.splitted_dsts.size());
    rsig_data->set_rsig_type(m_ct.rsig_type);

    generate_rsig_batch_sizes(m_ct.grouping_vct, m_ct.rsig_type, tx.splitted_dsts.size());
    assign_to_repeatable(rsig_data->mutable_grouping(), m_ct.grouping_vct.begin(), m_ct.grouping_vct.end());

    translate_dst_entry(tsx_data.mutable_change_dts(), std::addressof(tx.change_dts));
    for(auto & cur : tx.splitted_dsts){
      auto dst = tsx_data.mutable_outputs()->Add();
      translate_dst_entry(dst, std::addressof(cur));
    }

    compute_integrated_indices(std::addressof(tsx_data));

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
    if (ack->has_rsig_data()){
      m_ct.rsig_param = std::make_shared<MoneroRsigData>(ack->rsig_data());
    }

    assign_from_repeatable(std::addressof(m_ct.tx_out_entr_hmacs), ack->hmacs().begin(), ack->hmacs().end());
  }

  std::shared_ptr<messages::monero::MoneroTransactionSetInputRequest> Signer::step_set_input(size_t idx){
    m_ct.cur_input_idx = idx;
    auto res = std::make_shared<messages::monero::MoneroTransactionSetInputRequest>();
    translate_src_entry(res->mutable_src_entr(), std::addressof(cur_tx().sources[idx]));
    return res;
  }

  void Signer::step_set_input_ack(std::shared_ptr<const messages::monero::MoneroTransactionSetInputAck> ack){
    auto & vini_str = ack->vini();

    cryptonote::txin_v vini;
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

    if (in_memory()){
      return nullptr;
    }

    auto res = std::make_shared<messages::monero::MoneroTransactionInputsPermutationRequest>();
    assign_to_repeatable(res->mutable_perm(), m_ct.source_permutation.begin(), m_ct.source_permutation.end());

    return res;
  }

  void Signer::step_permutation_ack(std::shared_ptr<const messages::monero::MoneroTransactionInputsPermutationAck> ack){
    if (in_memory()){
      return;
    }
  }

  std::shared_ptr<messages::monero::MoneroTransactionInputViniRequest> Signer::step_set_vini_input(size_t idx){
    if (in_memory()){
      return nullptr;
    }

    m_ct.cur_input_idx = idx;
    auto tx = m_ct.tx_data;
    auto res = std::make_shared<messages::monero::MoneroTransactionInputViniRequest>();
    auto & vini = m_ct.tx.vin[idx];
    translate_src_entry(res->mutable_src_entr(), std::addressof(tx.sources[idx]));
    res->set_vini(cryptonote::t_serializable_object_to_blob(vini));
    res->set_vini_hmac(m_ct.tx_in_hmacs[idx]);
    if (!in_memory()) {
      res->set_pseudo_out(m_ct.pseudo_outs[idx]);
      res->set_pseudo_out_hmac(m_ct.pseudo_outs_hmac[idx]);
    }

    return res;
  }

  void Signer::step_set_vini_input_ack(std::shared_ptr<const messages::monero::MoneroTransactionInputViniAck> ack){
    if (in_memory()){
      return;
    }
  }

  std::shared_ptr<messages::monero::MoneroTransactionAllInputsSetRequest> Signer::step_all_inputs_set(){
    return std::make_shared<messages::monero::MoneroTransactionAllInputsSetRequest>();
  }

  void Signer::step_all_inputs_set_ack(std::shared_ptr<const messages::monero::MoneroTransactionAllInputsSetAck> ack){
    if (is_offloading()){
      // If offloading, expect rsig configuration.
      if (!ack->has_rsig_data()){
        throw exc::ProtocolException("Rsig offloading requires rsig param");
      }

      auto & rsig_data = ack->rsig_data();
      if (!rsig_data.has_mask()){
        throw exc::ProtocolException("Gamma masks not present in offloaded version");
      }

      auto & mask = rsig_data.mask();
      if (mask.size() != 32 * num_outputs()){
        throw exc::ProtocolException("Invalid number of gamma masks");
      }

      for(size_t idx=0, c=0; idx < mask.size(); idx += 32, ++c){
        auto sub = mask.substr(idx, idx + 32);
        rct::key mask{};
        memcpy(mask.bytes, sub.data(), 32);
        m_ct.rsig_gamma.emplace_back(mask);
      }
    }
  }

  std::shared_ptr<messages::monero::MoneroTransactionSetOutputRequest> Signer::step_set_output(size_t idx){
    m_ct.cur_output_idx = idx;
    m_ct.cur_output_in_batch_idx += 1;   // assumes sequential call to step_set_output()

    auto res = std::make_shared<messages::monero::MoneroTransactionSetOutputRequest>();
    auto & cur_dst = m_ct.tx_data.splitted_dsts[idx];
    translate_dst_entry(res->mutable_dst_entr(), std::addressof(cur_dst));
    res->set_dst_entr_hmac(m_ct.tx_out_entr_hmacs[idx]);

    // Range sig offloading to the host
    if (!is_offloading()) {
      return res;
    }

    if (m_ct.grouping_vct[m_ct.cur_batch_idx] > m_ct.cur_output_in_batch_idx) {
      return res;
    }

    auto rsig_data = res->mutable_rsig_data();
    auto batch_size = m_ct.grouping_vct[m_ct.cur_batch_idx];

    if (!is_req_bulletproof()){
      if (batch_size > 1){
        throw std::invalid_argument("Borromean cannot batch outputs");
      }

      rct::key C{}, mask = m_ct.rsig_gamma[idx];
      auto genRsig = rct::proveRange(C, mask, cur_dst.amount);  // TODO: rsig with given mask
      auto serRsig = cn_serialize(genRsig);
      m_ct.tx_out_rsigs.emplace_back(genRsig);
      rsig_data->set_rsig(serRsig);

    } else {
      std::vector<uint64_t> amounts;
      rct::keyV masks;
      for(size_t i = 0; i < batch_size; ++i){
        amounts.push_back(m_ct.tx_data.splitted_dsts[1 + idx - batch_size + i].amount);
        masks.push_back(m_ct.rsig_gamma[1 + idx - batch_size + i]);
      }

      auto bp = bulletproof_PROVE(amounts, masks);
      auto serRsig = cn_serialize(bp);
      m_ct.tx_out_rsigs.emplace_back(bp);
      rsig_data->set_rsig(serRsig);
    }

    return res;
  }

  void Signer::step_set_output_ack(std::shared_ptr<const messages::monero::MoneroTransactionSetOutputAck> ack){
    cryptonote::tx_out tx_out;
    rct::rangeSig range_sig{};
    rct::Bulletproof bproof{};
    rct::ctkey out_pk{};
    rct::ecdhTuple ecdh{};

    bool has_rsig = false;
    std::string rsig_buff;

    if (ack->has_rsig_data()){
      auto & rsig_data = ack->rsig_data();

      if (rsig_data.has_rsig() && !rsig_data.rsig().empty()){
        has_rsig = true;
        rsig_buff = rsig_data.rsig();

      } else if (rsig_data.rsig_parts_size() > 0){
        has_rsig = true;
        for (const auto &it : rsig_data.rsig_parts()) {
          rsig_buff += it;
        }
      }
    }

    if (!cn_deserialize(ack->tx_out(), tx_out)){
      throw exc::ProtocolException("Cannot deserialize vout[i]");
    }

    if (!cn_deserialize(ack->out_pk(), out_pk)){
      throw exc::ProtocolException("Cannot deserialize out_pk");
    }

    if (!cn_deserialize(ack->ecdh_info(), ecdh)){
      throw exc::ProtocolException("Cannot deserialize ecdhtuple");
    }

    if (has_rsig && !is_req_bulletproof() && !cn_deserialize(rsig_buff, range_sig)){
      throw exc::ProtocolException("Cannot deserialize rangesig");
    }

    if (has_rsig && is_req_bulletproof() && !cn_deserialize(rsig_buff, bproof)){
      throw exc::ProtocolException("Cannot deserialize bulletproof rangesig");
    }

    m_ct.tx.vout.emplace_back(tx_out);
    m_ct.tx_out_hmacs.push_back(ack->vouti_hmac());
    m_ct.tx_out_pk.emplace_back(out_pk);
    m_ct.tx_out_ecdh.emplace_back(ecdh);

    if (!has_rsig){
      return;
    }

    if (is_req_bulletproof()){
      auto batch_size = m_ct.grouping_vct[m_ct.cur_batch_idx];
      for (size_t i = 0; i < batch_size; ++i){
        rct::key commitment = m_ct.tx_out_pk[1 + m_ct.cur_output_idx - batch_size + i].mask;
        commitment = rct::scalarmultKey(commitment, rct::INV_EIGHT);
        bproof.V.push_back(commitment);
      }

      m_ct.tx_out_rsigs.emplace_back(bproof);
      if (!rct::verBulletproof(boost::get<rct::Bulletproof>(m_ct.tx_out_rsigs.back()))) {
        throw exc::ProtocolException("Returned range signature is invalid");
      }

    } else {
      m_ct.tx_out_rsigs.emplace_back(range_sig);

      if (!rct::verRange(out_pk.mask, boost::get<rct::rangeSig>(m_ct.tx_out_rsigs.back()))) {
        throw exc::ProtocolException("Returned range signature is invalid");
      }
    }

    m_ct.cur_batch_idx += 1;
    m_ct.cur_output_in_batch_idx = 0;
  }

  std::shared_ptr<messages::monero::MoneroTransactionRangeSigRequest> Signer::step_rsig(){
    throw exc::ProtocolException("Not implemented");
  }

  void Signer::step_rsig_ack(std::shared_ptr<const messages::monero::MoneroTransactionRangeSigAck> ack){
    throw exc::ProtocolException("Not implemented");
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

    ::crypto::hash tx_prefix_hash{};
    cryptonote::get_transaction_prefix_hash(m_ct.tx, tx_prefix_hash);
    m_ct.tx_prefix_hash = key_to_string(tx_prefix_hash);
    if (!crypto::ct_equal(tx_prefix_hash.data, ack->tx_prefix_hash().data(), 32)){
      throw exc::proto::SecurityException("Transaction prefix has does not match to the computed value");
    }

    // RctSig
    auto num_sources = m_ct.tx_data.sources.size();
    if (is_simple() || is_req_bulletproof()){
      auto & dst = m_ct.rv->pseudoOuts;
      if (is_bulletproof()){
        dst = m_ct.rv->p.pseudoOuts;
      }

      dst.clear();
      for (const auto &pseudo_out : m_ct.pseudo_outs) {
        dst.emplace_back();
        string_to_key(dst.back(), pseudo_out);
      }

      m_ct.rv->mixRing.resize(num_sources);
    } else {
      m_ct.rv->mixRing.resize(m_ct.tsx_data.mixin());
      m_ct.rv->mixRing[0].resize(num_sources);
    }

    for(size_t i = 0; i < m_ct.tx_out_ecdh.size(); ++i){
      m_ct.rv->outPk.push_back(m_ct.tx_out_pk[i]);
      m_ct.rv->ecdhInfo.push_back(m_ct.tx_out_ecdh[i]);
    }

    for(size_t i = 0; i < m_ct.tx_out_rsigs.size(); ++i){
      if (is_bulletproof()){
        m_ct.rv->p.bulletproofs.push_back(boost::get<rct::Bulletproof>(m_ct.tx_out_rsigs[i]));
      } else {
        m_ct.rv->p.rangeSigs.push_back(boost::get<rct::rangeSig>(m_ct.tx_out_rsigs[i]));
      }
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
    translate_src_entry(res->mutable_src_entr(), std::addressof(m_ct.tx_data.sources[idx]));
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

  std::shared_ptr<messages::monero::MoneroTransactionFinalRequest> Signer::step_final(){
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
    m_ct.enc_keys = ack->tx_enc_keys();
  }

  std::string Signer::store_tx_aux_info(){
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    rapidjson::Document json;
    json.SetObject();

    rapidjson::Value valueS(rapidjson::kStringType);
    rapidjson::Value valueI(rapidjson::kNumberType);

    valueI.SetInt(1);
    json.AddMember("version", valueI, json.GetAllocator());

    valueS.SetString(m_ct.enc_salt1.c_str(), m_ct.enc_salt1.size());
    json.AddMember("salt1", valueS, json.GetAllocator());

    valueS.SetString(m_ct.enc_salt2.c_str(), m_ct.enc_salt2.size());
    json.AddMember("salt2", valueS, json.GetAllocator());

    valueS.SetString(m_ct.enc_keys.c_str(), m_ct.enc_keys.size());
    json.AddMember("enc_keys", valueS, json.GetAllocator());

    json.Accept(writer);
    return sb.GetString();
  }


}

// Lite protocol
namespace lite {

  LiteComm::LiteComm(){

  }

  LiteComm::~LiteComm(){

  }

  uint8_t LiteComm::get_ins() const {
    return m_ins;
  }

  LiteComm * LiteComm::set_ins(uint8_t m_ins) {
    LiteComm::m_ins = m_ins;
    return this;
  }

  uint8_t LiteComm::get_p1() const {
    return m_p1;
  }

  LiteComm * LiteComm::set_p1(uint8_t m_p1) {
    LiteComm::m_p1 = m_p1;
    return this;
  }

  uint8_t LiteComm::get_p2() const {
    return m_p2;
  }

  LiteComm * LiteComm::set_p2(uint8_t m_p2) {
    LiteComm::m_p2 = m_p2;
    return this;
  }

  LiteComm * LiteComm::set_header(uint8_t ins, uint8_t p1, uint8_t p2) {
    set_ins(ins);
    set_p1(p1);
    set_p2(p2);
    m_r_len = 0;
    return this;
  }

  LiteComm * LiteComm::set_header_noopt(uint8_t ins, uint8_t p1, uint8_t p2){
    set_header(ins, p1, p2);
    insert_u8(0);  // options
    return this;
  }

  LiteComm * LiteComm::on_msg_received(const messages::monero::MoneroLiteAck *res) {
    m_c_sw = res->sw();
    m_c_offset = 0;

    if (!res->has_data()){
      m_c_len = 0;

    } else {
      auto & data = res->data();
      if (data.size() > sizeof(m_r_buff)){
        throw exc::CommunicationException("Response too big");
      }

      m_c_len = data.size();
      memcpy(m_c_msg, data.data(), m_c_len);
    }

    // Reset response
    m_ins = 0;
    m_p1 = 0;
    m_p2 = 0;

    return this;
  }

  std::shared_ptr<messages::monero::MoneroLiteRequest> LiteComm::build_request() {
    auto res = std::make_shared<messages::monero::MoneroLiteRequest>();
    res->set_ins(m_ins);
    res->set_p1(m_p1);
    res->set_p2(m_p2);
    res->set_data(m_r_buff, m_r_len);

    // Reset output buffer
    m_r_len = 0;
    return res;
  }

  void LiteComm::assert_enough_read_data(size_t nbytes){
    if (m_c_offset + nbytes > m_c_len){
      throw std::invalid_argument("Read buffer to small");
    }
  }

  void LiteComm::assert_enough_write_buff(size_t nbytes){
    if (m_r_len + nbytes > sizeof(m_r_buff)){
      throw std::invalid_argument("Write buffer to small");
    }
  }

  LiteComm * LiteComm::read_skip(size_t nbytes){
    assert_enough_read_data(nbytes);
    m_c_offset += nbytes;
    return this;
  }

  LiteComm * LiteComm::fetch(void * dst, size_t nbytes){
    assert_enough_read_data(nbytes);
    memmove(dst, m_c_msg + m_c_offset, nbytes);
    m_c_offset += nbytes;
    return this;
  }

  uint8_t LiteComm::fetch_u8(uint8_t * dst){
    uint8_t res;
    fetch(&res, 1);
    if (dst != nullptr){
      *dst = res;
    }
    return res;
  }

  uint16_t LiteComm::fetch_u16(uint16_t * dst){
    uint8_t l0, l1;
    uint16_t res;

    fetch(&l0, 1);
    fetch(&l1, 1);

    res = l0 << 8 | l1;
    if (dst != nullptr){
      *dst = res;
    }
    return res;
  }

  uint32_t LiteComm::fetch_u32(uint32_t * dst){
    uint8_t l0, l1, l2, l3;
    uint16_t res;

    fetch(&l0, 1);
    fetch(&l1, 1);
    fetch(&l2, 1);
    fetch(&l3, 1);

    res = l0 << 24 | l1 << 16 | l2 << 8 | l3;
    if (dst != nullptr){
      *dst = res;
    }
    return res;
  }

  LiteComm * LiteComm::insert_zero(size_t nbytes){
    assert_enough_write_buff(nbytes);
    if (nbytes > 0) {
      memset(m_r_buff + m_r_len, 0, nbytes);
      m_r_len += nbytes;
    }
    return this;
  }

  LiteComm * LiteComm::insert(const void * src, size_t nbytes){
    assert_enough_write_buff(nbytes);
    if (nbytes == 0){
      return this;
    }

    memmove(m_r_buff + m_r_len, src, nbytes);
    m_r_len += nbytes;
    return this;
  }

  LiteComm * LiteComm::insert_u8(uint8_t x){
    return insert(&x, 1);
  }

  LiteComm * LiteComm::insert_u16(uint16_t x){
    insert_u8((x >> 8) & 0xff);
    insert_u8(x & 0xff);
    return this;
  }

  LiteComm * LiteComm::insert_u32(uint32_t x){
    insert_u8((x >> 24) & 0xff);
    insert_u8((x >> 16) & 0xff);
    insert_u8((x >> 8) & 0xff);
    insert_u8(x & 0xff);
    return this;
  }






}

}
}
}
