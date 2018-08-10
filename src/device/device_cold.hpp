//
// Created by Dusan Klinec on 10/08/2018.
//

#ifndef MONERO_DEVICE_COLD_H
#define MONERO_DEVICE_COLD_H

#include "wallet/wallet2.h"


namespace hw {
  class device_cold {
  public:

    using exported_key_image = std::vector<std::pair<crypto::key_image, crypto::signature>>;

    /**
     * Key image sync with the cold protocol.
     * @param wallet
     * @param transfers
     * @param ski
     */
    virtual void ki_sync(::tools::wallet2 * wallet,
                 const std::vector<::tools::wallet2::transfer_details> & transfers,
                 exported_key_image & ski) =0;

    /**
     * Signs unsigned transaction with the cold protocol.
     * @param wallet
     * @param unsigned_tx
     * @param signed_tx
     */
    virtual void tx_sign(::tools::wallet2 * wallet,
                 const ::tools::wallet2::unsigned_tx_set & unsigned_tx,
                 ::tools::wallet2::signed_tx_set & signed_tx) =0;
  };
}

#endif //MONERO_DEVICE_COLD_H
