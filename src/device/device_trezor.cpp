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

    void device_trezor::lock(void) {

    }

    void device_trezor::unlock(void) {

    }

    bool device_trezor::try_lock(void) {
      return false;
    }

#else //WITH_DEVICE_TREZOR

    void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
    }

#endif //WITH_DEVICE_TREZOR
}}