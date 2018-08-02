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

  class TrezorException : public std::exception {
  protected:
    boost::optional<std::string> reason;
  public:
    TrezorException(): reason(boost::none){}
    TrezorException(std::string what): reason(what){}

    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "General Trezor exception";
    }
  };

  class CommunicationException: public TrezorException {
    using TrezorException::TrezorException;
    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "Trezor communication error";
    }
  };

  class EncodingException: public CommunicationException {
    using CommunicationException::CommunicationException;
    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "Trezor message encoding error";
    }
  };

  class NotConnectedException : CommunicationException {
    using CommunicationException::CommunicationException;
    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "Trezor not connected";
    }
  };

  class DeviceAcquireException : CommunicationException {
    using CommunicationException::CommunicationException;
    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "Trezor could not be acquired";
    }
  };

  class SessionException: public CommunicationException {
    using CommunicationException::CommunicationException;
    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "Trezor session expired";
    }
  };

  class TimeoutException: public CommunicationException {
    using CommunicationException::CommunicationException;
    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "Trezor communication timeout";
    }
  };

  class ProtocolException: public CommunicationException {
    using CommunicationException::CommunicationException;
    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "Trezor protocol error";
    }
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

    FailureException(boost::optional<uint32_t> code, boost::optional<std::string> message) : code(code),
                                                                                             message(message) {};

    virtual const char *what() const throw() {
      return reason ? reason.get().c_str() : "Trezor returned failure";
    }
  };

  class UnexpectedMessageException : public FailureException {
    using FailureException::FailureException;

    virtual const char *what() const throw() {
      return reason ? reason.get().c_str() : "Trezor claims unexpected response";
    }
  };

  class CancelledException : public FailureException {
    using FailureException::FailureException;

    virtual const char *what() const throw() {
      return reason ? reason.get().c_str() : "Trezor returned: cancelled operation";
    }
  };

  class PinExpectedException : public FailureException {
    using FailureException::FailureException;

    virtual const char *what() const throw() {
      return reason ? reason.get().c_str() : "Trezor claims PIN is expected";
    }
  };

  class InvalidPinException : public FailureException {
    using FailureException::FailureException;

    virtual const char *what() const throw() {
      return reason ? reason.get().c_str() : "Trezor claims PIN is invalid";
    }
  };

  class NotEnoughFundsException : public FailureException {
    using FailureException::FailureException;

    virtual const char *what() const throw() {
      return reason ? reason.get().c_str() : "Trezor claims not enough funds";
    }
  };

  class NotInitializedException : public FailureException {
    using FailureException::FailureException;

    virtual const char *what() const throw() {
      return reason ? reason.get().c_str() : "Trezor claims not initialized";
    }
  };

  class FirmwareErrorException : public FailureException {
    using FailureException::FailureException;

    virtual const char *what() const throw() {
      return reason ? reason.get().c_str() : "Trezor returned firmware error";
    }
  };

}
}
}
}
#endif //MONERO_EXCEPTIONS_H
