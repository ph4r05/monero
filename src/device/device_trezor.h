//
// Created by Dusan Klinec on 01/08/2018.
//

#ifndef MONERO_DEVICE_TREZOR_H
#define MONERO_DEVICE_TREZOR_H


#include <cstddef>
#include <string>
#include "device.hpp"
#include "device_default.hpp"
#include <boost/thread/mutex.hpp>
#include <boost/thread/recursive_mutex.hpp>


#if WITH_DEVICE_TREZOR
#include "trezor/transport.h"
#endif

namespace hw {
namespace trezor {

  void register_all(std::map<std::string, std::unique_ptr<device>> &registry);

#if WITH_DEVICE_TREZOR

  class device_trezor : public hw::core::device_default {
    private:
      // Locker for concurrent access
      mutable boost::recursive_mutex   device_locker;
      mutable boost::mutex   command_locker;

      // hw running mode
      device_mode mode;

      // To speed up blockchain parsing the view key maybe handle here.
      crypto::secret_key viewkey;

      bool has_view_key;

    public:
      device_trezor();
      ~device_trezor() override;

      device_trezor(const device_trezor &device) = delete ;
      device_trezor& operator=(const device_trezor &device) = delete;

      explicit operator bool() const override {return true;}

      bool reset(void);

      /* ======================================================================= */
      /*                              SETUP/TEARDOWN                             */
      /* ======================================================================= */
      bool set_name(const std::string &name) override;

      const std::string get_name() const override;
      bool init(void) override;
      bool release() override;
      bool connect(void) override;
      bool disconnect() override;

      bool set_mode(device_mode mode) override;

      /* ======================================================================= */
      /*  LOCKER                                                                 */
      /* ======================================================================= */
      void lock(void)  override;
      void unlock(void) override;
      bool try_lock(void) override;


    };

#endif

}
}
#endif //MONERO_DEVICE_TREZOR_H
