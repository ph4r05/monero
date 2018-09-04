//
// Created by Dusan Klinec on 10/08/2018.
//

#ifndef MONERO_DEVICE_COLD_H
#define MONERO_DEVICE_COLD_H

#include "wallet/wallet2.h"
#include <boost/function.hpp>


namespace hw {

  typedef struct wallet_shim {
    boost::function<crypto::public_key (const tools::wallet2::transfer_details &td)> get_tx_pub_key_from_received_outs;
  } wallet_shim;

  class tx_aux_data {
  public:
    std::vector<std::string> tx_device_aux;  // device generated aux data
    std::vector<cryptonote::address_parse_info> tx_recipients;  // as entered by user
  };

  class device_cold {
  public:

    using exported_key_image = std::vector<std::pair<crypto::key_image, crypto::signature>>;

    /**
     * Key image sync with the cold protocol.
     * @param wallet
     * @param transfers
     * @param ski
     */
    virtual void ki_sync(wallet_shim * wallet,
                 const std::vector<::tools::wallet2::transfer_details> & transfers,
                 exported_key_image & ski) =0;

    /**
     * Signs unsigned transaction with the cold protocol.
     * @param wallet
     * @param unsigned_tx
     * @param signed_tx
     * @param aux_data
     */
    virtual void tx_sign(wallet_shim * wallet,
                 const ::tools::wallet2::unsigned_tx_set & unsigned_tx,
                 ::tools::wallet2::signed_tx_set & signed_tx,
                 tx_aux_data & aux_data) =0;
  };
}

#endif //MONERO_DEVICE_COLD_H
