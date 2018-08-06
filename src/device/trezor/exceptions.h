//
// Created by Dusan Klinec on 02/08/2018.
//

#ifndef MONERO_EXCEPTIONS_H
#define MONERO_EXCEPTIONS_H

#include <exception>
#include <string>
#include <boost/optional.hpp>

namespace hw {
namespace trezor {
namespace exc {

  class SecurityException : public std::exception {
  protected:
    boost::optional<std::string> reason;

  public:
    SecurityException(): reason("General Security exception"){}
    explicit SecurityException(std::string what): reason(what){}

    virtual const char* what() const throw() {
      return reason.get().c_str();
    }
  };

  class Poly1305TagInvalid: public SecurityException {
  public:
    using SecurityException::SecurityException;
    Poly1305TagInvalid(): SecurityException("Poly1305 authentication tag invalid"){}
  };

  class TrezorException : public std::exception {
  protected:
    boost::optional<std::string> reason;

  public:
    TrezorException(): reason("General Trezor exception"){}
    explicit TrezorException(std::string what): reason(what){}

    virtual const char* what() const throw() {
      return reason.get().c_str();
    }
  };

  class CommunicationException: public TrezorException {
  public:
    using TrezorException::TrezorException;
    CommunicationException(): TrezorException("Trezor communication error"){}
  };

  class EncodingException: public CommunicationException {
  public:
    using CommunicationException::CommunicationException;
    EncodingException(): CommunicationException("Trezor message encoding error"){}
  };

  class NotConnectedException : CommunicationException {
  public:
    using CommunicationException::CommunicationException;
    NotConnectedException(): CommunicationException("Trezor not connected"){}
  };

  class DeviceAcquireException : CommunicationException {
  public:
    using CommunicationException::CommunicationException;
    DeviceAcquireException(): CommunicationException("Trezor could not be acquired"){}
  };

  class SessionException: public CommunicationException {
  public:
    using CommunicationException::CommunicationException;
    SessionException(): CommunicationException("Trezor session expired"){}
  };

  class TimeoutException: public CommunicationException {
  public:
    using CommunicationException::CommunicationException;
    TimeoutException(): CommunicationException("Trezor communication timeout"){}
  };

  class ProtocolException: public CommunicationException {
  public:
    using CommunicationException::CommunicationException;
    ProtocolException(): CommunicationException("Trezor protocol error"){}
  };

  // Communication protocol namespace
  // Separated to distinguish between client and trezor side exceptions.
namespace proto {

  class FailureException : public ProtocolException {
  private:
    boost::optional<uint32_t> code;
    boost::optional<std::string> message;
  public:
    using ProtocolException::ProtocolException;
    FailureException(): ProtocolException("Trezor returned failure"){}
    FailureException(boost::optional<uint32_t> code,
                     boost::optional<std::string> message)
        : code(code), message(message) {
      reason = "Trezor returned failure: code="
               + (code ? std::to_string(code.get()) : "")
               + ", message=" + (message ? message.get() : "");
    };
  };

  class UnexpectedMessageException : public FailureException {
  public:
    using FailureException::FailureException;
    UnexpectedMessageException(): FailureException("Trezor claims unexpected message received"){}
  };

  class CancelledException : public FailureException {
  public:
    using FailureException::FailureException;
    CancelledException(): FailureException("Trezor returned: cancelled operation"){}
  };

  class PinExpectedException : public FailureException {
  public:
    using FailureException::FailureException;
    PinExpectedException(): FailureException("Trezor claims PIN is expected"){}
  };

  class InvalidPinException : public FailureException {
  public:
    using FailureException::FailureException;
    InvalidPinException(): FailureException("Trezor claims PIN is invalid"){}
  };

  class NotEnoughFundsException : public FailureException {
  public:
    using FailureException::FailureException;
    NotEnoughFundsException(): FailureException("Trezor claims not enough funds"){}
  };

  class NotInitializedException : public FailureException {
  public:
    using FailureException::FailureException;
    NotInitializedException(): FailureException("Trezor claims not initialized"){}
  };

  class FirmwareErrorException : public FailureException {
  public:
    using FailureException::FailureException;
    FirmwareErrorException(): FailureException("Trezor returned firmware error"){}
  };

}
}
}
}
#endif //MONERO_EXCEPTIONS_H
