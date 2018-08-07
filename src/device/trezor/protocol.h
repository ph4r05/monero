//
// Created by Dusan Klinec on 06/08/2018.
//

#ifndef MONERO_PROTOCOL_H
#define MONERO_PROTOCOL_H

#include "messages_map.h"
#include "transport.h"
#include "wallet/wallet2.h"

namespace hw{
namespace trezor{
namespace protocol{

  using MoneroTransferDetails = messages::monero::MoneroKeyImageSyncStepRequest_MoneroTransferDetails;
  using MoneroSubAddressIndicesList = messages::monero::MoneroKeyImageExportInitRequest_MoneroSubAddressIndicesList;
  using MoneroExportedKeyImage = messages::monero::MoneroKeyImageSyncStepAck_MoneroExportedKeyImage;

  using exported_key_image = std::vector<std::pair<crypto::key_image, crypto::signature>>;

  std::string key_to_string(const ::crypto::ec_point & key);
  std::string key_to_string(const ::crypto::ec_scalar & key);

// Crypto / encryption
namespace crypto {
namespace chacha{

  /**
   * Chacha20Poly1305 decryption with tag verification.
   * @param data
   * @param length
   * @param key
   * @param iv
   * @param cipher
   */
  void decrypt(const void* data, size_t length, const uint8_t* key, const uint8_t* iv, char* cipher);

}
}


// Key image sync
namespace ki {

  /**
   * Converts transfer details to the MoneroTransferDetails required for KI sync
   * @param wallet
   * @param transfers
   * @param res
   * @return
   */
  bool key_image_data(tools::wallet2 * wallet,
                      const std::vector<tools::wallet2::transfer_details> & transfers,
                      std::vector<MoneroTransferDetails> & res);

  /**
   * Computes a hash over MoneroTransferDetails. Commitment used in the KI sync.
   * @param rr
   * @return
   */
  std::string compute_hash(const MoneroTransferDetails & rr);

  /**
   * Generates KI sync request with commitments computed.
   * @param mtds
   * @param transfers
   * @param req
   * @return
   */
  bool generate_commitment(std::vector<MoneroTransferDetails> & mtds,
                           const std::vector<tools::wallet2::transfer_details> & transfers,
                           std::shared_ptr<messages::monero::MoneroKeyImageExportInitRequest> & req);

}

}
}
}


#endif //MONERO_PROTOCOL_H
