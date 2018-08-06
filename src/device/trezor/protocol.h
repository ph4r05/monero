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

  std::string key_to_string(const crypto::ec_point & key);
  std::string key_to_string(const crypto::ec_scalar & key);

// Key image sync
namespace ki {
  bool key_image_data(tools::wallet2 * wallet,
                      const std::vector<tools::wallet2::transfer_details> & transfers,
                      std::vector<MoneroTransferDetails> & res);

  std::string compute_hash(const MoneroTransferDetails & rr);

  bool generate_commitment(std::vector<MoneroTransferDetails> & mtds,
                           const std::vector<tools::wallet2::transfer_details> & transfers,
                           std::shared_ptr<messages::monero::MoneroKeyImageExportInitRequest> & req);

}

}
}
}


#endif //MONERO_PROTOCOL_H
