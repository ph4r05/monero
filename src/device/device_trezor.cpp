//
// Created by Dusan Klinec on 01/08/2018.
//

#include "device_trezor.h"

namespace hw {
namespace trezor {

#if WITH_DEVICE_TREZOR

    static device_trezor *trezor_device = NULL;
    void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
      if (!trezor_device) {
        trezor_device = new device_trezor();
        trezor_device->set_name("Trezor");
      }
      registry.insert(std::make_pair("Trezor", std::unique_ptr<device>(trezor_device)));
    }

    device_trezor::device_trezor() {

    }

    device_trezor::~device_trezor() {

    }

    bool device_trezor::reset(void) {
      return false;
    }

    bool device_trezor::set_name(const std::string &name) {
      return false;
    }

    const std::string device_trezor::get_name() const {
      return std::string();
    }

    bool device_trezor::init(void) {
      return false;
    }

    bool device_trezor::release() {
      return false;
    }

    bool device_trezor::connect(void) {
      return false;
    }

    bool device_trezor::disconnect() {
      return false;
    }

    bool device_trezor::set_mode(device::device_mode mode) {
      return false;
    }

    /* ======================================================================= */
    /*  LOCKER                                                                 */
    /* ======================================================================= */

    //automatic lock one more level on device ensuring the current thread is allowed to use it
    #define AUTO_LOCK_CMD() \
      /* lock both mutexes without deadlock*/ \
      boost::lock(device_locker, command_locker); \
      /* make sure both already-locked mutexes are unlocked at the end of scope */ \
      boost::lock_guard<boost::recursive_mutex> lock1(device_locker, boost::adopt_lock); \
      boost::lock_guard<boost::mutex> lock2(command_locker, boost::adopt_lock)

    //lock the device for a long sequence
    void device_trezor::lock(void) {
      MDEBUG( "Ask for LOCKING for device "<<this->name << " in thread ");
      device_locker.lock();
      MDEBUG( "Device "<<this->name << " LOCKed");
    }

    //lock the device for a long sequence
    bool device_trezor::try_lock(void) {
      MDEBUG( "Ask for LOCKING(try) for device "<<this->name << " in thread ");
      bool r = device_locker.try_lock();
      if (r) {
        MDEBUG( "Device "<<this->name << " LOCKed(try)");
      } else {
        MDEBUG( "Device "<<this->name << " not LOCKed(try)");
      }
      return r;
    }

    //lock the device for a long sequence
    void device_trezor::unlock(void) {
      try {
        MDEBUG( "Ask for UNLOCKING for device "<<this->name << " in thread ");
      } catch (...) {
      }
      device_locker.unlock();
      MDEBUG( "Device "<<this->name << " UNLOCKed");
    }

#else //WITH_DEVICE_TREZOR

    void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
    }

#endif //WITH_DEVICE_TREZOR
}}