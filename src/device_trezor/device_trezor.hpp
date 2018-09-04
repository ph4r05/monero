//
// Created by Dusan Klinec on 01/08/2018.
//

#ifndef MONERO_DEVICE_TREZOR_H
#define MONERO_DEVICE_TREZOR_H


#include <cstddef>
#include <string>
#include "device/device.hpp"
#include "device/device_default.hpp"
#include "device/device_cold.hpp"
#include <boost/scope_exit.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include "cryptonote_config.h"
#include "trezor.hpp"
#include "device_trezor_base.hpp"
#include "device_trezor_lite.hpp"

namespace hw {
namespace trezor {

  void register_all();
  void register_all(std::map<std::string, std::unique_ptr<device>> &registry);

#if WITH_DEVICE_TREZOR
  class device_trezor;

  /**
   * Main device
   */
  class device_trezor : public hw::trezor::device_trezor_base, public hw::device_cold {
    protected:
      // To speed up blockchain parsing the view key maybe handle here.
      crypto::secret_key viewkey;
      bool has_view_key;

    public:
      device_trezor();
      ~device_trezor() override;

      device_trezor(const device_trezor &device) = delete ;
      device_trezor& operator=(const device_trezor &device) = delete;

      explicit operator bool() const override {return true;}

      device_protocol_t device_protocol() const override { return PROTOCOL_COLD; };

      bool  has_ki_cold_sync() const override { return true; }
      bool  has_tx_cold_sign() const override { return true; }
      void  set_network_type(cryptonote::network_type network_type) override { this->network_type = network_type; }

      /* ======================================================================= */
      /*                             WALLET & ADDRESS                            */
      /* ======================================================================= */
      bool  get_public_address(cryptonote::account_public_address &pubkey) override;
      bool  get_secret_keys(crypto::secret_key &viewkey , crypto::secret_key &spendkey) override;

      /* ======================================================================= */
      /*                              TREZOR PROTOCOL                            */
      /* ======================================================================= */

      /**
       * Get address. Throws.
       * @param path
       * @param network_type
       * @return
       */
      std::shared_ptr<messages::monero::MoneroAddress> get_address(
          boost::optional<std::vector<uint32_t>> path = boost::none,
          boost::optional<cryptonote::network_type> network_type = boost::none);

      /**
       * Get watch key from device. Throws.
       * @param path
       * @param network_type
       * @return
       */
      std::shared_ptr<messages::monero::MoneroWatchKey> get_watch_key(
          boost::optional<std::vector<uint32_t>> path = boost::none,
          boost::optional<cryptonote::network_type> network_type = boost::none);

      /**
       * Key image sync with the Trezor.
       * @param wallet
       * @param transfers
       * @param ski
       */
      void ki_sync(wallet_shim * wallet,
                   const std::vector<::tools::wallet2::transfer_details> & transfers,
                   hw::device_cold::exported_key_image & ski) override;

      /**
       * Signs particular transaction idx in the unsigned set, keeps state in the signer
       * @param wallet
       * @param unsigned_tx
       * @param idx
       * @param signer
       */
      void tx_sign(wallet_shim * wallet,
                   const ::tools::wallet2::unsigned_tx_set & unsigned_tx,
                   size_t idx,
                   std::shared_ptr<protocol::tx::Signer> & signer);

      /**
       * Signs unsigned transaction with the Trezor.
       * @param wallet
       * @param unsigned_tx
       * @param signed_tx
       * @param aux_data
       */
      void tx_sign(wallet_shim * wallet,
                   const ::tools::wallet2::unsigned_tx_set & unsigned_tx,
                   ::tools::wallet2::signed_tx_set & signed_tx,
                   hw::tx_aux_data & aux_data) override;
    };

#endif

}
}
#endif //MONERO_DEVICE_TREZOR_H
