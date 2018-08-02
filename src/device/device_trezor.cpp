//
// Created by Dusan Klinec on 01/08/2018.
//

#include "device_trezor.h"

#if WITH_DEVICE_TREZOR
#include "trezor/messages/messages.pb.h"
#include "trezor/messages/messages-common.pb.h"
#include "trezor/messages/messages-management.pb.h"
#include "trezor/messages/messages-monero.pb.h"
#endif

namespace hw {
namespace trezor {

#if WITH_DEVICE_TREZOR

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor"

    static device_trezor *trezor_device = nullptr;
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

    /* ======================================================================= */
    /*                              SETUP/TEARDOWN                             */
    /* ======================================================================= */

    bool device_trezor::reset(void) {
      return false;
    }

    bool device_trezor::set_name(const std::string & name) {
      this->name = name;
      return true;
    }

    const std::string device_trezor::get_name() const {
      if (this->full_name.empty()) {
        return std::string("<disconnected:").append(this->name).append(">");
      }
      return this->full_name;
    }

    bool device_trezor::init(void) {
      release();
      return true;
    }

    bool device_trezor::release() {
      disconnect();
      return true;
    }

    bool device_trezor::connect(void) {
      disconnect();

      // Enumerate all available devices
      hw::trezor::t_transport_vect trans;
      if (!enumerate(trans)){
        LOG_PRINT_L1("Enumeration failed");
        return false;
      }

      LOG_PRINT_L4("Enumeration yielded " << std::to_string(trans.size()) << " devices");
      for(auto & cur : trans){
        LOG_PRINT_L4(std::string("  device: ") << *(cur.get()));
        std::string cur_path = cur->get_path();
        if (boost::starts_with(cur_path, this->name)){
          MDEBUG("Device Match: " << cur_path);
          m_transport = cur;
          break;
        }
      }

      if (!m_transport){
        return false;
      }

      bool r = m_transport->open();
      return r;
    }

    bool device_trezor::disconnect() {
      if (m_transport){
        m_transport->close();
      }
      return true;
    }

    bool device_trezor::set_mode(device::device_mode mode) {
      this->mode = mode;
      return true;
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

    /* ======================================================================= */
    /*  Helpers                                                                */
    /* ======================================================================= */

    bool device_trezor::ping() {
      AUTO_LOCK_CMD();
      if (!m_transport){
        LOG_PRINT_L2("Ping failed, device not connected");
        return false;
      }

      messages::management::Ping pingMsg;
      std::shared_ptr<messages::common::Success> success;
      pingMsg.set_message("PING");

      try {
        exchange_message<messages::common::Success>(*m_transport, pingMsg, success);  // messages::MessageType_Success
        MDEBUG("Ping response " << success->message());
        return true;

      } catch(std::exception const& e) {
        LOG_PRINT_L1(std::string("Ping failed, exception thrown ") << e.what());
      } catch(...){
        LOG_PRINT_L1(std::string("Ping failed, general exception thrown") << boost::current_exception_diagnostic_information());
      }

      return false;
    }

#else //WITH_DEVICE_TREZOR

    void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
    }

#endif //WITH_DEVICE_TREZOR
}}