// Copyright (c) 2014-2018, The Monero Project
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

#include <boost/regex.hpp>

#include "common/util.h"
#include "common/command_line.h"
#include "performance_tests.h"
#include "performance_utils.h"

// tests
#include "construct_tx.h"
#include "check_tx_signature.h"
#include "cn_slow_hash.h"
#include "derive_public_key.h"
#include "derive_secret_key.h"
#include "ge_frombytes_vartime.h"
#include "generate_key_derivation.h"
#include "generate_key_image.h"
#include "generate_key_image_helper.h"
#include "generate_keypair.h"
#include "signature.h"
#include "is_out_to_acc.h"
#include "subaddress_expand.h"
#include "sc_reduce32.h"
#include "sc_check.h"
#include "cn_fast_hash.h"
#include "rct_mlsag.h"
#include "range_proof.h"
#include "rct_mlsag.h"
#include "bulletproof.h"
#include "crypto_ops.h"
#include "multiexp.h"

namespace po = boost::program_options;

int main(int argc, char** argv)
{
  TRY_ENTRY();
  tools::on_startup();
  set_process_affinity(1);
  set_thread_high_priority();

  mlog_configure(mlog_get_default_log_path("performance_tests.log"), true);

  po::options_description desc_options("Command line options");
  const command_line::arg_descriptor<std::string> arg_filter = { "filter", "Regular expression filter for which tests to run" };
  const command_line::arg_descriptor<bool> arg_verbose = { "verbose", "Verbose output", false };
  const command_line::arg_descriptor<bool> arg_stats = { "stats", "Including statistics (min/median)", false };
  const command_line::arg_descriptor<unsigned> arg_loop_multiplier = { "loop-multiplier", "Run for that many times more loops", 1 };
  command_line::add_arg(desc_options, arg_filter, "");
  command_line::add_arg(desc_options, arg_verbose, "");
  command_line::add_arg(desc_options, arg_stats, "");
  command_line::add_arg(desc_options, arg_loop_multiplier, "");

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_options), vm);
    po::notify(vm);
    return true;
  });
  if (!r)
    return 1;

  const std::string filter = tools::glob_to_regex(command_line::get_arg(vm, arg_filter));
  Params p;
  p.verbose = command_line::get_arg(vm, arg_verbose);
  p.stats = command_line::get_arg(vm, arg_stats);
  p.loop_multiplier = command_line::get_arg(vm, arg_loop_multiplier);

  performance_timer timer;
  timer.start();

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 1, 1, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 1, 2, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 1, 10, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 1, 100, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 1, 1000, false);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 1, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 2, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 10, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 100, false);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 1, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 2, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 10, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 100, false);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 1, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 2, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 10, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 100, false);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 1, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 2, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 10, true);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 1, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 2, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 10, true);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 1, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 2, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 10, true);

  TEST_PERFORMANCE4(filter, p, test_construct_tx, 2, 1, true, rct::RangeProofPaddedBulletproof);
  TEST_PERFORMANCE4(filter, p, test_construct_tx, 2, 2, true, rct::RangeProofPaddedBulletproof);
  TEST_PERFORMANCE4(filter, p, test_construct_tx, 2, 10, true, rct::RangeProofPaddedBulletproof);

  TEST_PERFORMANCE4(filter, p, test_construct_tx, 10, 1, true, rct::RangeProofPaddedBulletproof);
  TEST_PERFORMANCE4(filter, p, test_construct_tx, 10, 2, true, rct::RangeProofPaddedBulletproof);
  TEST_PERFORMANCE4(filter, p, test_construct_tx, 10, 10, true, rct::RangeProofPaddedBulletproof);

  TEST_PERFORMANCE4(filter, p, test_construct_tx, 100, 1, true, rct::RangeProofPaddedBulletproof);
  TEST_PERFORMANCE4(filter, p, test_construct_tx, 100, 2, true, rct::RangeProofPaddedBulletproof);
  TEST_PERFORMANCE4(filter, p, test_construct_tx, 100, 10, true, rct::RangeProofPaddedBulletproof);

  TEST_PERFORMANCE3(filter, p, test_check_tx_signature, 1, 2, false);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature, 2, 2, false);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature, 10, 2, false);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature, 100, 2, false);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature, 2, 10, false);

  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 2, 2, true, rct::RangeProofBorromean);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 10, 2, true, rct::RangeProofBorromean);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 100, 2, true, rct::RangeProofBorromean);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 2, 10, true, rct::RangeProofBorromean);

  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 2, 2, true, rct::RangeProofPaddedBulletproof);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 2, 2, true, rct::RangeProofMultiOutputBulletproof);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 10, 2, true, rct::RangeProofPaddedBulletproof);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 10, 2, true, rct::RangeProofMultiOutputBulletproof);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 100, 2, true, rct::RangeProofPaddedBulletproof);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 100, 2, true, rct::RangeProofMultiOutputBulletproof);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 2, 10, true, rct::RangeProofPaddedBulletproof);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 2, 10, true, rct::RangeProofMultiOutputBulletproof);

  TEST_PERFORMANCE3(filter, p, test_check_tx_signature_aggregated_bulletproofs, 2, 2, 64);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature_aggregated_bulletproofs, 10, 2, 64);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature_aggregated_bulletproofs, 100, 2, 64);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature_aggregated_bulletproofs, 2, 10, 64);

  TEST_PERFORMANCE4(filter, p, test_check_tx_signature_aggregated_bulletproofs, 2, 2, 62, 4);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature_aggregated_bulletproofs, 10, 2, 62, 4);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature_aggregated_bulletproofs, 2, 2, 56, 16);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature_aggregated_bulletproofs, 10, 2, 56, 16);

  TEST_PERFORMANCE0(filter, p, test_is_out_to_acc);
  TEST_PERFORMANCE0(filter, p, test_is_out_to_acc_precomp);
  TEST_PERFORMANCE0(filter, p, test_generate_key_image_helper);
  TEST_PERFORMANCE0(filter, p, test_generate_key_derivation);
  TEST_PERFORMANCE0(filter, p, test_generate_key_image);
  TEST_PERFORMANCE0(filter, p, test_derive_public_key);
  TEST_PERFORMANCE0(filter, p, test_derive_secret_key);
  TEST_PERFORMANCE0(filter, p, test_ge_frombytes_vartime);
  TEST_PERFORMANCE0(filter, p, test_generate_keypair);
  TEST_PERFORMANCE0(filter, p, test_sc_reduce32);
  TEST_PERFORMANCE0(filter, p, test_sc_check);
  TEST_PERFORMANCE1(filter, p, test_signature, false);
  TEST_PERFORMANCE1(filter, p, test_signature, true);

  TEST_PERFORMANCE2(filter, p, test_wallet2_expand_subaddresses, 50, 200);

  TEST_PERFORMANCE0(filter, p, test_cn_slow_hash);
  TEST_PERFORMANCE1(filter, p, test_cn_fast_hash, 32);
  TEST_PERFORMANCE1(filter, p, test_cn_fast_hash, 16384);

  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 3, false);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 5, false);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 10, false);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 100, false);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 3, true);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 5, true);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 10, true);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 100, true);

  TEST_PERFORMANCE1(filter, p, test_range_proof, true);
  TEST_PERFORMANCE1(filter, p, test_range_proof, false);

  TEST_PERFORMANCE2(filter, p, test_bulletproof, true, 1); // 1 bulletproof with 1 amount
  TEST_PERFORMANCE2(filter, p, test_bulletproof, false, 1);

  TEST_PERFORMANCE2(filter, p, test_bulletproof, true, 2); // 1 bulletproof with 2 amounts
  TEST_PERFORMANCE2(filter, p, test_bulletproof, false, 2);

  TEST_PERFORMANCE2(filter, p, test_bulletproof, true, 15); // 1 bulletproof with 15 amounts
  TEST_PERFORMANCE2(filter, p, test_bulletproof, false, 15);

  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, false, 2, 1, 1, 0, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 2, 1, 1, 0, 4); // 4 proofs, each with 2 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, false, 8, 1, 1, 0, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 8, 1, 1, 0, 4); // 4 proofs, each with 8 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, false, 1, 1, 2, 0, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 1, 1, 2, 0, 4); // 4 proofs with 1, 2, 4, 8 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, false, 1, 8, 1, 1, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 1, 8, 1, 1, 4); // 32 proofs, with 1, 2, 3, 4 amounts, 8 of each
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, false, 2, 1, 1, 0, 64);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 2, 1, 1, 0, 64); // 64 proof, each with 2 amounts

  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 3, false);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 5, false);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 10, false);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 100, false);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 3, true);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 5, true);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 10, true);
  TEST_PERFORMANCE3(filter, p, test_ringct_mlsag, 1, 100, true);

  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_sc_add);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_sc_sub);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_sc_mul);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_add_raw);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_add_p3_p3);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_addKeys);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_scalarmultBase);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_scalarmultKey);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_scalarmultH);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_scalarmult8);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_dsm_precomp);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_double_scalarmult_base_vartime);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_double_scalarmult_precomp_vartime);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_double_scalarmult_precomp_vartime2);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_addKeys2);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_addKeys3);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_addKeys3_2);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_isInMainSubgroup);

#if 0
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 2);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 4);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 8);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 16);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 32);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 64);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 128);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 256);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 512);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 1024);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 2048);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 4096);

  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 8);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 16);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 32);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 64);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 128);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 256);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 512);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1024);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2048);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4096);

  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 8);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 16);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 32);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 64);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 128);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 256);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 512);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1024);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2048);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4096);
#endif

// pippenger
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 200, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 220, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 240, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 260, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 280, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 300, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 350, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 400, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 450, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 500, 5);

  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 200, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 220, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 240, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 260, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 280, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 300, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 350, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 400, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 450, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 500, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 550, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 600, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 650, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 700, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 750, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 800, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 850, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 900, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 950, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1000, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1050, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1100, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1150, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1200, 6);

  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 300, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 350, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 400, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 450, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 500, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 550, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 600, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 650, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 700, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 750, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 800, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 850, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 900, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 950, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1000, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1050, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1100, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1150, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1200, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1250, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1300, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1350, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1400, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1450, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1500, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1550, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1600, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1650, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1700, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1750, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1800, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1850, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1900, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1950, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2000, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2050, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2100, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2150, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2200, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2250, 7);

  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1000, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1050, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1100, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1150, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1200, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1250, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1300, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1350, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1400, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1450, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1500, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1550, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1600, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1650, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1700, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1750, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1800, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1850, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1900, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1950, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2000, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2050, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2100, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2150, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2200, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2250, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2300, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2350, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2400, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2450, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2500, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2550, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2600, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2650, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2700, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2750, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2800, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2850, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2900, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2950, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3000, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3050, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3100, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3150, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3200, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3250, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3300, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3350, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3400, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3450, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3500, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3450, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3600, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3650, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3700, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3750, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3800, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3850, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3900, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3950, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4000, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4050, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4100, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4150, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4200, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4250, 8);

  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1800, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1850, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1900, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1950, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2000, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2050, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2100, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2150, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2200, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2250, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2300, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2350, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2400, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2450, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2500, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2550, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2600, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2650, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2700, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2750, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2800, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2850, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2900, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2950, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3000, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3050, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3100, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3150, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3200, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3250, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3300, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3350, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3400, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3450, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3500, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3450, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3600, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3650, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3700, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3750, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3800, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3850, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3900, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 3950, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4000, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4050, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4100, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4150, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4200, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4250, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4300, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4350, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4400, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4450, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4500, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4550, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4600, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4650, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4700, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4750, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4800, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4850, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4900, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4950, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5000, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5050, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5100, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5150, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5200, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5250, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5300, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5350, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5400, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5450, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5500, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5550, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 5600, 9);

// pippenger cached
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 200, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 220, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 240, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 260, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 280, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 300, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 350, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 400, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 450, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 500, 5);

  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 200, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 220, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 240, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 260, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 280, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 300, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 350, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 400, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 450, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 500, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 550, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 600, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 650, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 700, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 750, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 800, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 850, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 900, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 950, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1000, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1050, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1100, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1150, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1200, 6);

  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 300, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 350, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 400, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 450, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 500, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 550, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 600, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 650, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 700, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 750, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 800, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 850, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 900, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 950, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1000, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1050, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1100, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1150, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1200, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1250, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1300, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1350, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1400, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1450, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1500, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1550, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1600, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1650, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1700, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1750, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1800, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1850, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1900, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1950, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2000, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2050, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2100, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2150, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2200, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2250, 7);

  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1000, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1050, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1100, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1150, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1200, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1250, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1300, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1350, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1400, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1450, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1500, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1550, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1600, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1650, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1700, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1750, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1800, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1850, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1900, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1950, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2000, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2050, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2100, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2150, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2200, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2250, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2300, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2350, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2400, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2450, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2500, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2550, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2600, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2650, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2700, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2750, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2800, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2850, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2900, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2950, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3000, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3050, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3100, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3150, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3200, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3250, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3300, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3350, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3400, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3450, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3500, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3450, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3600, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3650, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3700, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3750, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3800, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3850, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3900, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3950, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4000, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4050, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4100, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4150, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4200, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4250, 8);

  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1800, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1850, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1900, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1950, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2000, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2050, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2100, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2150, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2200, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2250, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2300, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2350, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2400, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2450, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2500, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2550, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2600, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2650, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2700, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2750, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2800, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2850, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2900, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2950, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3000, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3050, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3100, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3150, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3200, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3250, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3300, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3350, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3400, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3450, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3500, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3450, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3600, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3650, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3700, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3750, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3800, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3850, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3900, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 3950, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4000, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4050, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4100, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4150, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4200, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4250, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4300, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4350, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4400, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4450, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4500, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4550, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4600, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4650, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4700, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4750, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4800, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4850, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4900, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4950, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5000, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5050, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5100, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5150, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5200, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5250, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5300, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5350, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5400, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5450, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5500, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5550, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 5600, 9);

// straus
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 220);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 240);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 260);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 280);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 550);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 600);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 650);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 700);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 750);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 800);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 850);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 900);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 950);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1000);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1050);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1100);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1150);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1250);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1550);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1600);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1650);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1700);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1750);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1800);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1850);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1900);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1950);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2000);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2050);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2100);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2150);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2250);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2550);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2600);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2650);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2700);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2750);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2800);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2850);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2900);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2950);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3000);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3050);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3100);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3150);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3250);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3600);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3650);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3700);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3750);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3800);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3850);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3900);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 3950);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4000);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4050);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4100);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4150);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4250);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4550);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4600);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4650);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4700);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4750);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4800);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4850);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4900);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4950);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5000);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5050);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5100);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5150);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5250);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5550);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 5600);

// straus cached
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 220);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 240);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 260);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 280);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 550);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 600);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 650);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 700);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 750);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 800);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 850);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 900);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 950);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1000);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1050);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1100);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1150);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1250);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1550);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1600);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1650);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1700);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1750);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1800);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1850);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1900);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1950);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2000);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2050);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2100);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2150);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2250);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2550);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2600);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2650);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2700);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2750);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2800);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2850);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2900);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2950);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3000);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3050);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3100);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3150);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3250);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3600);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3650);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3700);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3750);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3800);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3850);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3900);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 3950);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4000);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4050);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4100);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4150);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4250);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4550);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4600);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4650);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4700);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4750);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4800);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4850);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4900);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4950);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5000);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5050);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5100);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5150);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5200);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5250);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5300);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5350);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5400);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5450);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5500);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5550);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 5600);

#if 0
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 9);
#elif 0
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 9);

  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 9);
#endif

  std::cout << "Tests finished. Elapsed time: " << timer.elapsed_ms() / 1000 << " sec" << std::endl;

  return 0;
  CATCH_ENTRY_L0("main", 1);
}
