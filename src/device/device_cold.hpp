// Copyright (c) 2017-2018, The Monero Project
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

#ifndef MONERO_DEVICE_COLD_H
#define MONERO_DEVICE_COLD_H

#include "wallet/wallet2.h"
#include <boost/optional/optional.hpp>
#include <boost/function.hpp>


namespace hw {

  typedef struct wallet_shim {
    boost::function<crypto::public_key (const tools::wallet2::transfer_details &td)> get_tx_pub_key_from_received_outs;
  } wallet_shim;

  class tx_aux_data {
  public:
    std::vector<std::string> tx_device_aux;  // device generated aux data
    std::vector<cryptonote::address_parse_info> tx_recipients;  // as entered by user
    boost::optional<int> bp_version;  // BP version to use
    boost::optional<unsigned> client_version;  // Signing client version to use (testing)
  };

  class device_cold {
  public:

    using exported_key_image = std::vector<std::pair<crypto::key_image, crypto::signature>>;

    typedef struct {
      std::string salt1;
      std::string salt2;
      std::string tx_enc_keys;
      std::string tx_prefix_hash;
    } tx_key_data_t;

    /**
     * Key image sync with the cold protocol.
     */
    virtual void ki_sync(wallet_shim * wallet,
                 const std::vector<::tools::wallet2::transfer_details> & transfers,
                 exported_key_image & ski) =0;

    /**
     * Signs unsigned transaction with the cold protocol.
     */
    virtual void tx_sign(wallet_shim * wallet,
                 const ::tools::wallet2::unsigned_tx_set & unsigned_tx,
                 ::tools::wallet2::signed_tx_set & signed_tx,
                 tx_aux_data & aux_data) =0;

    /**
     * Get tx key support check.
     */
    bool is_get_tx_key_supported() { return false; }

    /**
     * Loads TX aux data required for tx key.
     */
    virtual void load_tx_key_data(tx_key_data_t & res, const std::string & tx_aux_data) =0;

    /**
     * Decrypts TX keys.
     * If view_public_key is set, derivations are computed instead of the tx private keys.
     */
    virtual void get_tx_key(
        std::vector<::crypto::secret_key> & tx_keys,
        const tx_key_data_t & tx_aux_data,
        const ::crypto::secret_key & view_key_priv,
        const boost::optional<std::string> & view_public_key) =0;
  };
}

#endif //MONERO_DEVICE_COLD_H
