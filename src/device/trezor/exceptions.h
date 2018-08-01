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

  class CancelledException: public ProtocolException {
    using ProtocolException::ProtocolException;
    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "Trezor returned: cancelled operation";
    }
  };

  class FailureException: public ProtocolException {
    using ProtocolException::ProtocolException;
    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "Trezor returned failure";
    }
  };

  class UnexpectedResponseException: public ProtocolException {
    using ProtocolException::ProtocolException;
    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "Trezor returned unexpected response";
    }
  };

  class FirmwareErrorException: public ProtocolException {
    using ProtocolException::ProtocolException;
    virtual const char* what() const throw() {
      return reason ? reason.get().c_str() : "Trezor returned firmware error";
    }
  };

}
}
}
#endif //MONERO_EXCEPTIONS_H
