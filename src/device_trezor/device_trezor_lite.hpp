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

#ifndef MONERO_DEVICE_TREZOR_LITE_H
#define MONERO_DEVICE_TREZOR_LITE_H


#include <cstddef>
#include <string>
#include "device/device.hpp"
#include "device/device_default.hpp"
#include <boost/scope_exit.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include "cryptonote_config.h"
#include "trezor.hpp"
#include "device_trezor_base.hpp"

namespace hw {
namespace trezor {

#if WITH_DEVICE_TREZOR and WITH_DEVICE_TREZOR_LITE

    class ABPkeys {
    public:
      rct::key Aout;
      rct::key Bout;
      bool     is_subaddress;
      size_t   index;
      rct::key Pout;
      rct::key AKout;
      ABPkeys(const rct::key& A, const rct::key& B, const bool is_subaddr,  size_t index, const rct::key& P,const rct::key& AK);
      ABPkeys(const ABPkeys& keys) ;
      ABPkeys() {index=0;is_subaddress=false;}
    };

    class Keymap {
    public:
      std::vector<ABPkeys> ABP;

      bool find(const rct::key& P, ABPkeys& keys) const;
      void add(const ABPkeys& keys);
      void clear();
      void log();
    };

  /**
   * Main device
   */
  class device_trezor_lite : public hw::trezor::device_trezor_base {
  protected:
    // hw running mode
    device_mode mode;

    // map public destination key to ephemeral destination key
    Keymap key_map;

    // To speed up blockchain parsing the view key maybe handle here.
    crypto::secret_key viewkey;
    bool has_view_key;

    // communication serializer
    hw::trezor::protocol::lite::LiteComm comm;
    bool m_lite_initialized;
    bool m_lite_sec_keys_loaded;

  public:
    device_trezor_lite();
    ~device_trezor_lite() override;

    device_trezor_lite(const device_trezor_lite &device) = delete ;
    device_trezor_lite& operator=(const device_trezor_lite &device) = delete;

    explicit operator bool() const override {return true;}

    device_protocol_t device_protocol() const override { return PROTOCOL_PROXY; };
    bool  has_ki_cold_sync(void) const override { return false; }
    bool  has_tx_cold_sign(void) const override { return false; }
    void  set_network_type(cryptonote::network_type network_type) override { this->network_type = network_type; }

    bool set_mode(device::device_mode mode) override;

    void init_lite(boost::optional<std::vector<uint32_t>> path = boost::none,
                   boost::optional<cryptonote::network_type> network_type = boost::none);

    void init_load_keys();

    void exchange_lite();
    void send_simple(uint8_t ins = 0, uint8_t p1 = 0, uint8_t p2 = 0);

    bool connect(void) override;
    bool disconnect() override;

    /* ======================================================================= */
    /*                             WALLET & ADDRESS                            */
    /* ======================================================================= */
    bool  get_public_address(cryptonote::account_public_address &pubkey) override;
    bool  get_secret_keys(crypto::secret_key &viewkey , crypto::secret_key &spendkey) override;
    bool  generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key, uint64_t kdf_rounds) override;


    /* ======================================================================= */
    /*                               SUB ADDRESS                               */
    /* ======================================================================= */
    bool  derive_subaddress_public_key(const crypto::public_key &pub, const crypto::key_derivation &derivation, const std::size_t output_index,  crypto::public_key &derived_pub) override;
    crypto::public_key  get_subaddress_spend_public_key(const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index) override;
    std::vector<crypto::public_key>  get_subaddress_spend_public_keys(const cryptonote::account_keys &keys, uint32_t account, uint32_t begin, uint32_t end) override;
    cryptonote::account_public_address  get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) override;
    crypto::secret_key  get_subaddress_secret_key(const crypto::secret_key &sec, const cryptonote::subaddress_index &index) override;

    /* ======================================================================= */
    /*                            DERIVATION & KEY                             */
    /* ======================================================================= */
    bool  verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) override;
    bool  scalarmultKey(rct::key & aP, const rct::key &P, const rct::key &a) override;
    bool  scalarmultBase(rct::key &aG, const rct::key &a) override;
    bool  sc_secret_add(crypto::secret_key &r, const crypto::secret_key &a, const crypto::secret_key &b) override;
    crypto::secret_key  generate_keys(crypto::public_key &pub, crypto::secret_key &sec, const crypto::secret_key& recovery_key = crypto::secret_key(), bool recover = false) override;
    bool  generate_key_derivation(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_derivation &derivation) override;
    bool  conceal_derivation(crypto::key_derivation &derivation, const crypto::public_key &tx_pub_key, const std::vector<crypto::public_key> &additional_tx_pub_keys, const crypto::key_derivation &main_derivation, const std::vector<crypto::key_derivation> &additional_derivations) override;
    bool  derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res) override;
    bool  derive_secret_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &sec,  crypto::secret_key &derived_sec) override;
    bool  derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &pub,  crypto::public_key &derived_pub) override;
    bool  secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub) override;
    bool  generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image) override;

    /* ======================================================================= */
    /*                               TRANSACTION                               */
    /* ======================================================================= */

    bool  open_tx(crypto::secret_key &tx_key) override;

    bool  encrypt_payment_id(crypto::hash8 &payment_id, const crypto::public_key &public_key, const crypto::secret_key &secret_key) override;

    bool  ecdhEncode(rct::ecdhTuple & unmasked, const rct::key & sharedSec) override;
    bool  ecdhDecode(rct::ecdhTuple & masked, const rct::key & sharedSec) override;

    bool  add_output_key_mapping(const crypto::public_key &Aout, const crypto::public_key &Bout, const bool is_subaddress, const size_t real_output_index,
                                 const rct::key &amount_key,  const crypto::public_key &out_eph_public_key) override;


    bool  mlsag_prehash(const std::string &blob, size_t inputs_size, size_t outputs_size, const rct::keyV &hashes, const rct::ctkeyV &outPk, rct::key &prehash) override;
    bool  mlsag_prepare(const rct::key &H, const rct::key &xx, rct::key &a, rct::key &aG, rct::key &aHP, rct::key &rvII) override;
    bool  mlsag_prepare(rct::key &a, rct::key &aG) override;
    bool  mlsag_hash(const rct::keyV &long_message, rct::key &c) override;
    bool  mlsag_sign( const rct::key &c, const rct::keyV &xx, const rct::keyV &alpha, const size_t rows, const size_t dsRows, rct::keyV &ss) override;

    bool  close_tx(void) override;

    /* ======================================================================= */
    /*                              TREZOR PROTOCOL                            */
    /* ======================================================================= */

  };

#endif

}
}
#endif //MONERO_DEVICE_TREZOR_LITE_H
