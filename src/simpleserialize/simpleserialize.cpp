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

/*!
 * \file simplewallet.cpp
 * 
 * \brief Source file that defines simple_wallet class.
 */
#include <thread>
#include <iostream>
#include <sstream>
#include <fstream>
#include <ctype.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/regex.hpp>
#include "include_base_utils.h"
#include "common/i18n.h"
#include "common/command_line.h"
#include "common/util.h"
#include "common/dns_utils.h"
#include "common/base58.h"
#include "common/scoped_message_writer.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "simpleserialize.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "storages/http_abstract_invoke.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "crypto/crypto.h"  // for crypto::secret_key definition
#include "mnemonics/electrum-words.h"
#include "rapidjson/document.h"
#include "common/json_util.h"
#include "ringct/rctSigs.h"
#include "multisig/multisig.h"
#include "wallet/wallet_args.h"
#include <stdexcept>

#ifdef HAVE_READLINE
#include "readline_buffer.h"
#endif

using namespace std;
using namespace epee;
using namespace cryptonote;
using boost::lexical_cast;
namespace po = boost::program_options;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.simpleserialize"

namespace
{
//  tools::scoped_message_writer success_msg_writer(bool color = false)
//  {
//    return tools::scoped_message_writer(color ? console_color_green : console_color_default, false, std::string(), el::Level::Info);
//  }
//
//  tools::scoped_message_writer message_writer(epee::console_colors color = epee::console_color_default, bool bright = false)
//  {
//    return tools::scoped_message_writer(color, bright);
//  }
//
//  tools::scoped_message_writer fail_msg_writer()
//  {
//    return tools::scoped_message_writer(console_color_red, true, "Error ", el::Level::Error);
//  }
}

static std::string dump_key(const void * buff, size_t len=32)
{
  std::stringstream os;
  const auto * src = (const uint8_t*)buff;

  os << "bytes([";
  for(size_t i=0; i<len; ++i){
    os << "0x" << setfill('0') << setw(2) << hex << static_cast<unsigned>(src[i] & 0xff);
    if (i+1 < len) os << ", ";
  }
  os << "])";
  return os.str();
}

static std::string dump_key_hex(const void * buff, size_t len=32)
{
  std::stringstream os;
  const auto * src = (const uint8_t*)buff;

  os << "unhexlify(b\"";
  for(size_t i=0; i<len; ++i){
    os << setfill('0') << setw(2) << hex << static_cast<unsigned>(src[i] & 0xff);
  }
  os << "\")";
  return os.str();
}

static void dump_bp(const rct::Bulletproof &proof){
  cout << "Bulletproof(" << endl;
  cout << "    V=[" << endl;
  for (auto & cur : proof.V){
    cout << dump_key_hex(cur.bytes);
    cout << ", " << endl;
  }
  cout << "], " << endl;
  cout << "    A=" << dump_key_hex(proof.A.bytes) << ", " << endl
       << "    S=" << dump_key_hex(proof.S.bytes) << ", " << endl
       << "    T1=" << dump_key_hex(proof.T1.bytes) << ", " << endl
       << "    T2=" << dump_key_hex(proof.T2.bytes) << ", " << endl
       << "    taux=" << dump_key_hex(proof.taux.bytes) << ", " << endl
       << "    mu=" << dump_key_hex(proof.mu.bytes) << ", " << endl
       << "    L=[";
  for (auto & cur : proof.L){
    cout << dump_key_hex(cur.bytes);
    cout << ", " << endl;
  }
  cout << "    ]," << endl
       << "    R=[";
  for (auto & cur : proof.R){
    cout << dump_key_hex(cur.bytes);
    cout << ", " << endl;
  }
  cout << "    ]," << endl
       << "    a=" << dump_key_hex(proof.a.bytes) << ", " << endl
       << "    b=" << dump_key_hex(proof.b.bytes) << ", " << endl
       << "    t=" << dump_key_hex(proof.t.bytes) << "" << endl
       << ")" << endl;
}

static rct::key from_uint(uint64_t v){
  rct::key sv = rct::zero();
  sv.bytes[0] = v & 255;
  sv.bytes[1] = (v >> 8) & 255;
  sv.bytes[2] = (v >> 16) & 255;
  sv.bytes[3] = (v >> 24) & 255;
  sv.bytes[4] = (v >> 32) & 255;
  sv.bytes[5] = (v >> 40) & 255;
  sv.bytes[6] = (v >> 48) & 255;
  sv.bytes[7] = (v >> 56) & 255;
  return sv;
}


//----------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
  std::ostringstream oss;
  boost::archive::portable_binary_oarchive arx(oss);

  size_t num = 0x23;

  txin_gen in;
  in.height = 0x34;
  cryptonote::txin_v txin(in);

//  arx & num;
//  arx & in;
//  arx & txin;


//  tx_destination_entry de;
//  tx_destination_entry de2;
//  account_public_address pub;
//  memset(pub.m_spend_public_key.data, 0, 32);
//  memset(pub.m_view_public_key.data, 0, 32);
//  pub.m_spend_public_key.data[0]=0xcc;
//  pub.m_spend_public_key.data[31]=0xee;
//  pub.m_view_public_key.data[0]=0xaa;
//  pub.m_view_public_key.data[31]=0xdd;
//
//  de.amount = 0x44;
//  de.is_subaddress = true;
//  de.addr = pub;
//  arx & de;
//
//  de2.amount = 0x22;
//  de2.is_subaddress = false;
//  pub.m_spend_public_key.data[0] = 0x11;
//  pub.m_view_public_key.data[0] = 0x33;
//  de2.addr = pub;
//  arx & de2;

  rct::ctkey ct{};
  rct::key key1{};
  memset(key1.bytes, 0, 32);

//  arx & num;
//  arx & ct;
//  arx & key1;

  rct::boroSig bsig;
  bsig.s0[0].bytes[0] = 0x22;
  arx & bsig;

  std::cout << epee::string_tools::buff_to_hex_nodelimer(oss.str()) << std::endl;
  std::cout << oss.str() << std::endl;
}
