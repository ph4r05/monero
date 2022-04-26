// Copyright (c) 2014-2020, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "ringct/rctSigs.h"
#include "ringct/bulletproofs_plus.h"
#include "chaingen.h"
#include "bulletproof_plus.h"
#include "device/device.hpp"

using namespace epee;
using namespace crypto;
using namespace cryptonote;

//----------------------------------------------------------------------------------------------------------------------
// Tests

bool gen_bpp_tx_validation_base::generate_with(std::vector<test_event_entry>& events,
    size_t mixin, size_t n_txes, const uint64_t *amounts_paid, bool valid, const rct::RCTConfig *rct_config, uint8_t hf_version,
    const std::function<bool(std::vector<tx_source_entry> &sources, std::vector<tx_destination_entry> &destinations, size_t tx_idx)> &pre_tx,
    const std::function<bool(transaction &tx, size_t tx_idx)> &post_tx) const
{
  uint64_t ts_start = 1338224400;

  GENERATE_ACCOUNT(miner_account);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);

  // create 12 miner accounts, and have them mine the next 12 blocks
  cryptonote::account_base miner_accounts[12];
  const cryptonote::block *prev_block = &blk_0;
  cryptonote::block blocks[12 + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW];
  for (size_t n = 0; n < 12; ++n) {
    miner_accounts[n].generate();
    CHECK_AND_ASSERT_MES(generator.construct_block_manually(blocks[n], *prev_block, miner_accounts[n],
        test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version,
        2, 2, prev_block->timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
          crypto::hash(), 0, transaction(), std::vector<crypto::hash>(), 0, 0, 2),
        false, "Failed to generate block");
    events.push_back(blocks[n]);
    prev_block = blocks + n;
  }

  // rewind
  cryptonote::block blk_r, blk_last;
  {
    blk_last = blocks[11];
    for (size_t i = 0; i < CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; ++i)
    {
      CHECK_AND_ASSERT_MES(generator.construct_block_manually(blocks[12+i], blk_last, miner_account,
          test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version,
          2, 2, blk_last.timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
          crypto::hash(), 0, transaction(), std::vector<crypto::hash>(), 0, 0, 2),
          false, "Failed to generate block");
      events.push_back(blocks[12+i]);
      blk_last = blocks[12+i];
    }
    blk_r = blk_last;
  }

  // create 4 txes from these miners in another block, to generate some rct outputs
  std::vector<transaction> rct_txes;
  cryptonote::block blk_txes;
  std::vector<crypto::hash> starting_rct_tx_hashes;
  uint64_t fees = 0;
  static const uint64_t input_amounts_available[] = {5000000000000, 30000000000000, 100000000000, 80000000000};
  for (size_t n = 0; n < n_txes; ++n)
  {
    std::vector<tx_source_entry> sources;

    sources.resize(1);
    tx_source_entry& src = sources.back();

    const uint64_t needed_amount = input_amounts_available[n];
    src.amount = input_amounts_available[n];
    size_t real_index_in_tx = 0;
    for (size_t m = 0; m <= mixin; ++m) {
      size_t index_in_tx = 0;
      for (size_t i = 0; i < blocks[m].miner_tx.vout.size(); ++i)
        if (blocks[m].miner_tx.vout[i].amount == needed_amount)
          index_in_tx = i;
      CHECK_AND_ASSERT_MES(blocks[m].miner_tx.vout[index_in_tx].amount == needed_amount, false, "Expected amount not found");
      src.push_output(m, boost::get<txout_to_key>(blocks[m].miner_tx.vout[index_in_tx].target).key, src.amount);
      if (m == n)
        real_index_in_tx = index_in_tx;
    }
    src.real_out_tx_key = cryptonote::get_tx_pub_key_from_extra(blocks[n].miner_tx);
    src.real_output = n;
    src.real_output_in_tx_index = real_index_in_tx;
    src.mask = rct::identity();
    src.rct = false;

    //fill outputs entry
    tx_destination_entry td;
    td.addr = miner_accounts[n].get_keys().m_account_address;
    std::vector<tx_destination_entry> destinations;
    for (int o = 0; amounts_paid[o] != (uint64_t)-1; ++o)
    {
      td.amount = amounts_paid[o];
      destinations.push_back(td);
    }

    if (pre_tx && !pre_tx(sources, destinations, n))
    {
      MDEBUG("pre_tx returned failure");
      return false;
    }

    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
    subaddresses[miner_accounts[n].get_keys().m_account_address.m_spend_public_key] = {0,0};
    rct_txes.resize(rct_txes.size() + 1);
    bool r = construct_tx_and_get_tx_key(miner_accounts[n].get_keys(), subaddresses, sources, destinations, cryptonote::account_public_address{}, std::vector<uint8_t>(), rct_txes.back(), 0, tx_key, additional_tx_keys, true, rct_config[n]);
    CHECK_AND_ASSERT_MES(r, false, "failed to construct transaction");

    if (post_tx && !post_tx(rct_txes.back(), n))
    {
      MDEBUG("post_tx returned failure");
      return false;
    }

    //events.push_back(rct_txes.back());
    starting_rct_tx_hashes.push_back(get_transaction_hash(rct_txes.back()));
    LOG_PRINT_L0("Test tx: " << obj_to_json_str(rct_txes.back()));

    for (int o = 0; amounts_paid[o] != (uint64_t)-1; ++o)
    {
      crypto::key_derivation derivation;
      bool r = crypto::generate_key_derivation(destinations[o].addr.m_view_public_key, tx_key, derivation);
      CHECK_AND_ASSERT_MES(r, false, "Failed to generate key derivation");
      crypto::secret_key amount_key;
      crypto::derivation_to_scalar(derivation, o, amount_key);
      rct::key rct_tx_mask;
      const uint8_t type = rct_txes.back().rct_signatures.type;
      if (rct::is_rct_simple(type))
        rct::decodeRctSimple(rct_txes.back().rct_signatures, rct::sk2rct(amount_key), o, rct_tx_mask, hw::get_device("default"));
      else
        rct::decodeRct(rct_txes.back().rct_signatures, rct::sk2rct(amount_key), o, rct_tx_mask, hw::get_device("default"));
    }

    while (amounts_paid[0] != (size_t)-1)
      ++amounts_paid;
    ++amounts_paid;

    uint64_t fee = 0;
    get_tx_fee(rct_txes.back(), fee);
    fees += fee;
  }
  if (!valid)
    DO_CALLBACK(events, "mark_invalid_tx");
  events.push_back(rct_txes);

  CHECK_AND_ASSERT_MES(generator.construct_block_manually(blk_txes, blk_last, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_tx_hashes | test_generator::bf_hf_version | test_generator::bf_max_outs | test_generator::bf_tx_fees,
      hf_version, hf_version, blk_last.timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
      crypto::hash(), 0, transaction(), starting_rct_tx_hashes, 0, 6, hf_version, fees),
      false, "Failed to generate block");
  if (!valid)
    DO_CALLBACK(events, "mark_invalid_block");
  events.push_back(blk_txes);
  blk_last = blk_txes;

  return true;
}

bool gen_bpp_tx_validation_base::check_bpp(const cryptonote::transaction &tx, size_t tx_idx, const size_t *sizes, const char *context) const
{
  DEFINE_TESTS_ERROR_CONTEXT(context);
  CHECK_TEST_CONDITION(tx.version >= 2);
  CHECK_TEST_CONDITION(rct::is_rct_bulletproof_plus(tx.rct_signatures.type));
  size_t n_sizes = 0, n_amounts = 0;
  for (size_t n = 0; n < tx_idx; ++n)
  {
    while (sizes[0] != (size_t)-1)
      ++sizes;
    ++sizes;
  }
  while (sizes[n_sizes] != (size_t)-1)
    n_amounts += sizes[n_sizes++];
  CHECK_TEST_CONDITION(tx.rct_signatures.p.bulletproofs_plus.size() == n_sizes);
  CHECK_TEST_CONDITION(rct::n_bulletproof_plus_max_amounts(tx.rct_signatures.p.bulletproofs_plus) == n_amounts);
  for (size_t n = 0; n < n_sizes; ++n)
    CHECK_TEST_CONDITION(rct::n_bulletproof_plus_max_amounts(tx.rct_signatures.p.bulletproofs_plus[n]) == sizes[n]);
  return true;
}

bool gen_bpp_tx_invalid_before_fork::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {5000, 5000, (uint64_t)-1};
  const size_t bp_sizes[] = {2, (size_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofPaddedBulletproof, 4 } };
  return generate_with(events, mixin, 1, amounts_paid, false, rct_config, HF_VERSION_BULLETPROOF_PLUS - 1, NULL, [&](const cryptonote::transaction &tx, size_t tx_idx){ return check_bpp(tx, tx_idx, bp_sizes, "gen_bpp_tx_invalid_before_fork"); });
}

bool gen_bpp_tx_valid_at_fork::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {5000, 5000, (uint64_t)-1};
  const size_t bp_sizes[] = {2, (size_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofPaddedBulletproof, 4 } };
  return generate_with(events, mixin, 1, amounts_paid, true, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, [&](const cryptonote::transaction &tx, size_t tx_idx){ return check_bpp(tx, tx_idx, bp_sizes, "gen_bpp_tx_valid_at_fork"); });
}

bool gen_bpp_tx_invalid_1_1::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {5000, 5000, (uint64_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofBulletproof , 4 } };
  return generate_with(events, mixin, 1, amounts_paid, false, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, NULL);
}

bool gen_bpp_tx_valid_2::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {5000, 5000, (uint64_t)-1};
  const size_t bp_sizes[] = {2, (size_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofPaddedBulletproof, 4 } };

  const rct::BulletproofPlus ppp = {
      {{{0xe0, 0xda, 0xe6, 0x10, 0x95, 0xac, 0x72, 0x8a, 0x15, 0xd4, 0xd9, 0x75, 0x4f, 0x1f, 0x9f, 0x95, 0x6c, 0x22, 0xd4, 0xfa, 0x2d, 0xee, 0xe2, 0xc0, 0xff, 0x1d, 0xef, 0x03, 0x1b, 0x08, 0x3e, 0x02}},
      {{0x5b, 0x42, 0x4e, 0xcb, 0x1f, 0x8e, 0xa0, 0x23, 0x51, 0xd3, 0x24, 0x29, 0x6a, 0x34, 0xa0, 0x60, 0x8e, 0xcc, 0x10, 0x46, 0x10, 0xfe, 0xaa, 0xd0, 0x6e, 0x60, 0x02, 0xf6, 0x19, 0x92, 0xbf, 0xe1}}},
  {{0x6a, 0xe6, 0xf1, 0x6a, 0x6b, 0x01, 0xcf, 0x49, 0x4f, 0xb2, 0xcf, 0x36, 0x85, 0x73, 0x36, 0x52, 0x93, 0xf7, 0x6c, 0x62, 0x4c, 0xfc, 0x11, 0x15, 0x2d, 0x64, 0x84, 0x79, 0x23, 0x8e, 0x93, 0x19}},
  {{0x33, 0xad, 0x31, 0x8a, 0x44, 0xdf, 0x6f, 0x14, 0xa9, 0x45, 0xe6, 0xd0, 0x51, 0x91, 0x1a, 0xb9, 0xa2, 0x48, 0x41, 0x45, 0x7d, 0x15, 0xd6, 0x2b, 0xd1, 0x43, 0x6f, 0xb3, 0xed, 0xc8, 0xa1, 0x93}},
  {{0x5f, 0x56, 0x53, 0x1c, 0xb8, 0xe7, 0x8d, 0xbb, 0x34, 0x50, 0xf1, 0xd5, 0x99, 0xa6, 0xd4, 0xc7, 0xf5, 0xe4, 0xc0, 0x4e, 0xe3, 0xe7, 0x01, 0x56, 0x43, 0xc1, 0x9a, 0x52, 0x8b, 0xcb, 0xb1, 0x09}},
  {{0x40, 0xad, 0x8a, 0x9c, 0x6b, 0x3b, 0xdd, 0x95, 0xc7, 0xfb, 0x86, 0x05, 0xe5, 0x01, 0x35, 0x05, 0x0e, 0x64, 0xf1, 0xce, 0x29, 0xd1, 0xc4, 0xb3, 0x7b, 0x12, 0x71, 0xe6, 0x58, 0x35, 0x45, 0x00}},
  {{0xae, 0xd9, 0x59, 0xc7, 0x70, 0x49, 0x91, 0x34, 0xaa, 0xa7, 0xe0, 0x99, 0xf5, 0x66, 0xda, 0xc5, 0x6e, 0xe1, 0x29, 0x59, 0xd7, 0x97, 0xb6, 0x2a, 0x3d, 0x8d, 0x10, 0x37, 0xb7, 0x90, 0xb8, 0x06}},
  {{0x39, 0x5a, 0x1e, 0x8d, 0x3d, 0xf8, 0xe9, 0x0e, 0x71, 0x6f, 0xde, 0xaa, 0x49, 0x30, 0x90, 0x78, 0x2c, 0x8d, 0xb9, 0x22, 0x33, 0x7d, 0x09, 0xa3, 0x6b, 0x50, 0xc1, 0xf0, 0x2c, 0xd8, 0xe1, 0x00}},
  {{{0xed, 0x2d, 0x76, 0x8b, 0xb9, 0xc8, 0xb5, 0xa9, 0xfa, 0x24, 0xc9, 0x0b, 0x58, 0x31, 0xd3, 0xcc, 0xeb, 0x3e, 0x78, 0xce, 0xf4, 0x5e, 0xba, 0x90, 0xe5, 0x2f, 0x89, 0xa2, 0xb3, 0xc8, 0x59, 0xd2}},
    {{0x7f, 0x25, 0xcc, 0x8e, 0x21, 0x17, 0x83, 0xe9, 0xc1, 0xb8, 0x0d, 0xd1, 0x3e, 0xe2, 0x86, 0x94, 0x3d, 0xa0, 0xec, 0x07, 0xbd, 0x33, 0x29, 0x15, 0x36, 0x63, 0x94, 0x32, 0x75, 0x8f, 0x69, 0x27}},
    {{0x7b, 0xae, 0x3d, 0x31, 0xf4, 0xe2, 0xa6, 0xd7, 0x8d, 0x74, 0xd2, 0xbc, 0xb6, 0xd0, 0x65, 0x6e, 0x42, 0x22, 0x16, 0x14, 0x23, 0xd6, 0x35, 0xf7, 0xce, 0x08, 0x80, 0x5e, 0x96, 0xce, 0xc8, 0x3e}},
    {{0xc8, 0x7f, 0x94, 0x9f, 0x70, 0xcf, 0x56, 0x9c, 0x4b, 0xaa, 0x33, 0x26, 0x12, 0x30, 0x57, 0x33, 0xfd, 0x19, 0xa2, 0x26, 0x24, 0x90, 0xc5, 0x5e, 0xc8, 0x8c, 0x16, 0xa6, 0x8d, 0x7b, 0x5e, 0x7d}},
    {{0x34, 0xd0, 0x6c, 0xaf, 0x0d, 0x02, 0x12, 0x9e, 0xbc, 0xc8, 0xbf, 0x31, 0x8d, 0xa8, 0xf6, 0xa0, 0xdd, 0xfa, 0xf2, 0xc7, 0xcb, 0x85, 0xf4, 0x14, 0x47, 0x26, 0x56, 0x1c, 0xef, 0xc8, 0x6d, 0xcd}},
    {{0xab, 0x3e, 0xff, 0xd3, 0xa2, 0x70, 0x65, 0x91, 0x77, 0x4e, 0x01, 0x3c, 0x76, 0xf5, 0xb8, 0xec, 0xe9, 0xe5, 0x8a, 0xbf, 0x7e, 0xfc, 0x0a, 0x11, 0xb4, 0x79, 0xf9, 0xd2, 0xa8, 0x9d, 0x0c, 0x55}},
    {{0xeb, 0xf8, 0xd3, 0x4e, 0x66, 0x43, 0x53, 0x3b, 0xf7, 0x3b, 0x13, 0xd2, 0xdd, 0x56, 0xae, 0xaf, 0x21, 0x13, 0xfb, 0x30, 0x17, 0xd3, 0x9b, 0xc6, 0xdb, 0x6a, 0x2f, 0x71, 0xbc, 0x1d, 0x53, 0xf1}}},
  {{{0x27, 0xe1, 0x46, 0xe6, 0x1e, 0x88, 0x94, 0x42, 0x46, 0xdc, 0xd9, 0x0d, 0xdb, 0x42, 0x84, 0x92, 0x3c, 0x7f, 0xdc, 0x6f, 0xd6, 0xa1, 0x87, 0xed, 0x2e, 0xfa, 0x3d, 0xcb, 0x8c, 0x38, 0x03, 0x46}},
    {{0xfa, 0xb9, 0x91, 0x52, 0xd4, 0x8d, 0x83, 0x5b, 0x9a, 0x01, 0xcd, 0xbe, 0xc4, 0x63, 0x01, 0xdb, 0x0f, 0x57, 0xca, 0x09, 0x1f, 0x6c, 0xba, 0xa0, 0xb4, 0x5c, 0x84, 0x98, 0xf1, 0x8b, 0xab, 0xe1}},
    {{0x84, 0x67, 0xf8, 0x7a, 0xcd, 0x7b, 0xe0, 0x26, 0xa2, 0x7e, 0xd7, 0x98, 0xcc, 0xa6, 0xcc, 0x15, 0x26, 0xb0, 0xf8, 0x05, 0xac, 0x53, 0x4a, 0x9c, 0x51, 0x62, 0xa9, 0xcd, 0x75, 0x46, 0x00, 0x11}},
    {{0xf4, 0x21, 0xfa, 0x4b, 0xda, 0x1d, 0xba, 0x04, 0x2c, 0xa5, 0x6c, 0x6b, 0xdc, 0xe3, 0x13, 0xdc, 0x8d, 0x18, 0xce, 0xe0, 0x84, 0xd7, 0x22, 0xaf, 0x47, 0x44, 0x7c, 0xe5, 0x4b, 0x6f, 0xf8, 0xdf}},
    {{0x8d, 0xd5, 0xda, 0xbc, 0x0a, 0xd6, 0x7c, 0x83, 0xf4, 0x26, 0x68, 0xe9, 0x6b, 0xf5, 0xee, 0x67, 0x41, 0xbc, 0xd8, 0xe6, 0x61, 0xed, 0xa1, 0xe8, 0xce, 0x6a, 0x23, 0xd8, 0x4c, 0xf0, 0xb5, 0xb5}},
    {{0xfc, 0xf2, 0x0a, 0x77, 0x75, 0x69, 0x9b, 0x04, 0x56, 0x54, 0x29, 0x30, 0xb2, 0x37, 0x4b, 0x23, 0x3f, 0xb3, 0xf8, 0xf7, 0x9e, 0x19, 0x11, 0x42, 0x81, 0x57, 0x63, 0x1a, 0x20, 0xb3, 0xc3, 0xad}},
    {{0x66, 0xe4, 0x77, 0xbd, 0x93, 0xda, 0xbb, 0x18, 0x4e, 0x27, 0x38, 0x82, 0x93, 0x20, 0xbf, 0x8e, 0x60, 0xf6, 0xb4, 0xb4, 0x76, 0xca, 0x0f, 0xbc, 0x10, 0x13, 0xaf, 0x28, 0xe8, 0xde, 0x34, 0xc1}}}
  };

  rct::bulletproof_plus_VERIFY(ppp);


  rct::bulletproof_plus_PROVE({123, 768}, {
      {{0xc8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
      {{0x85, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
  });

  return 0;
  //return generate_with(events, mixin, 1, amounts_paid, true, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, [&](const cryptonote::transaction &tx, size_t tx_idx){ return check_bpp(tx, tx_idx, bp_sizes, "gen_bpp_tx_valid_2"); });
}

bool gen_bpp_tx_valid_3::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {5000, 5000, 5000, (uint64_t)-1};
  const size_t bp_sizes[] = {4, (size_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofPaddedBulletproof , 4 } };
  return generate_with(events, mixin, 1, amounts_paid, true, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, [&](const cryptonote::transaction &tx, size_t tx_idx){ return check_bpp(tx, tx_idx, bp_sizes, "gen_bpp_tx_valid_3"); });
}

bool gen_bpp_tx_valid_16::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500, (uint64_t)-1};
  const size_t bp_sizes[] = {16, (size_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofPaddedBulletproof , 4 } };
  return generate_with(events, mixin, 1, amounts_paid, true, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, [&](const cryptonote::transaction &tx, size_t tx_idx){ return check_bpp(tx, tx_idx, bp_sizes, "gen_bpp_tx_valid_16"); });
}

bool gen_bpp_tx_invalid_4_2_1::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {1000, 1000, 1000, 1000, 1000, 1000, 1000, (uint64_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofMultiOutputBulletproof , 4 } };
  return generate_with(events, mixin, 1, amounts_paid, false, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, NULL);
}

bool gen_bpp_tx_invalid_16_16::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, (uint64_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofMultiOutputBulletproof , 4 } };
  return generate_with(events, mixin, 1, amounts_paid, false, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, NULL);
}

bool gen_bpp_txs_valid_2_and_2::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {1000, 1000, (size_t)-1, 1000, 1000, (uint64_t)-1};
  const size_t bp_sizes[] = {2, (size_t)-1, 2, (size_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofPaddedBulletproof, 4 }, {rct::RangeProofPaddedBulletproof, 4 } };
  return generate_with(events, mixin, 2, amounts_paid, true, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, [&](const cryptonote::transaction &tx, size_t tx_idx){ return check_bpp(tx, tx_idx, bp_sizes, "gen_bpp_txs_valid_2_and_2"); });
}

bool gen_bpp_txs_invalid_2_and_8_2_and_16_16_1::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {1000, 1000, (uint64_t)-1, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, (uint64_t)-1, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, (uint64_t)-1};
  const rct::RCTConfig rct_config[] = {{rct::RangeProofMultiOutputBulletproof, 4}, {rct::RangeProofMultiOutputBulletproof, 4}, {rct::RangeProofMultiOutputBulletproof, 4}};
  return generate_with(events, mixin, 3, amounts_paid, false, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, NULL);
}

bool gen_bpp_txs_valid_2_and_3_and_2_and_4::generate(std::vector<test_event_entry>& events) const
{
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {11111115000, 11111115000, (uint64_t)-1, 11111115000, 11111115000, 11111115001, (uint64_t)-1, 11111115000, 11111115002, (uint64_t)-1, 11111115000, 11111115000, 11111115000, 11111115003, (uint64_t)-1};
  const rct::RCTConfig rct_config[] = {{rct::RangeProofPaddedBulletproof, 4}, {rct::RangeProofPaddedBulletproof, 4}, {rct::RangeProofPaddedBulletproof, 4}, {rct::RangeProofPaddedBulletproof, 4}};
  const size_t bp_sizes[] = {2, (size_t)-1, 4, (size_t)-1, 2, (size_t)-1, 4, (size_t)-1};
  return generate_with(events, mixin, 4, amounts_paid, true, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, [&](const cryptonote::transaction &tx, size_t tx_idx) { return check_bpp(tx, tx_idx, bp_sizes, "gen_bpp_txs_valid_2_and_3_and_2_and_4"); });
}

bool gen_bpp_tx_invalid_not_enough_proofs::generate(std::vector<test_event_entry>& events) const
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_bpp_tx_invalid_not_enough_proofs");
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {5000, 5000, (uint64_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofBulletproof, 4 } };
  return generate_with(events, mixin, 1, amounts_paid, false, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, [&](cryptonote::transaction &tx, size_t idx){
    CHECK_TEST_CONDITION(tx.rct_signatures.type == rct::RCTTypeBulletproofPlus);
    CHECK_TEST_CONDITION(!tx.rct_signatures.p.bulletproofs_plus.empty());
    tx.rct_signatures.p.bulletproofs_plus.pop_back();
    CHECK_TEST_CONDITION(!tx.rct_signatures.p.bulletproofs_plus.empty());
    return true;
  });
}

bool gen_bpp_tx_invalid_empty_proofs::generate(std::vector<test_event_entry>& events) const
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_bpp_tx_invalid_empty_proofs");
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {50000, 50000, (uint64_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofBulletproof, 4 } };
  return generate_with(events, mixin, 1, amounts_paid, false, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, [&](cryptonote::transaction &tx, size_t idx){
    CHECK_TEST_CONDITION(tx.rct_signatures.type == rct::RCTTypeBulletproofPlus);
    tx.rct_signatures.p.bulletproofs_plus.clear();
    return true;
  });
}

bool gen_bpp_tx_invalid_too_many_proofs::generate(std::vector<test_event_entry>& events) const
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_bpp_tx_invalid_too_many_proofs");
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {10000, (uint64_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofBulletproof, 4 } };
  return generate_with(events, mixin, 1, amounts_paid, false, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, [&](cryptonote::transaction &tx, size_t idx){
    CHECK_TEST_CONDITION(tx.rct_signatures.type == rct::RCTTypeBulletproofPlus);
    CHECK_TEST_CONDITION(!tx.rct_signatures.p.bulletproofs_plus.empty());
    tx.rct_signatures.p.bulletproofs_plus.push_back(tx.rct_signatures.p.bulletproofs_plus.back());
    return true;
  });
}

bool gen_bpp_tx_invalid_wrong_amount::generate(std::vector<test_event_entry>& events) const
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_bpp_tx_invalid_wrong_amount");
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {10000, (uint64_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofBulletproof, 4 } };
  return generate_with(events, mixin, 1, amounts_paid, false, rct_config, HF_VERSION_BULLETPROOF_PLUS, NULL, [&](cryptonote::transaction &tx, size_t idx){
    CHECK_TEST_CONDITION(tx.rct_signatures.type == rct::RCTTypeBulletproofPlus);
    CHECK_TEST_CONDITION(!tx.rct_signatures.p.bulletproofs_plus.empty());
    tx.rct_signatures.p.bulletproofs_plus.back() = rct::bulletproof_plus_PROVE(1000, rct::skGen());
    return true;
  });
}

bool gen_bpp_tx_invalid_clsag_type::generate(std::vector<test_event_entry>& events) const
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_bpp_tx_invalid_clsag_type");
  const size_t mixin = 10;
  const uint64_t amounts_paid[] = {5000, 5000, (uint64_t)-1};
  const rct::RCTConfig rct_config[] = { { rct::RangeProofPaddedBulletproof, 3 } };
  return generate_with(events, mixin, 1, amounts_paid, false, rct_config, HF_VERSION_BULLETPROOF_PLUS + 1, NULL, [&](cryptonote::transaction &tx, size_t tx_idx){
    return true;
  });
}
