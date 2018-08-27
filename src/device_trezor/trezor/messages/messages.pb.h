// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: messages.proto

#ifndef PROTOBUF_messages_2eproto__INCLUDED
#define PROTOBUF_messages_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 2006000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 2006001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_enum_reflection.h>
#include "google/protobuf/descriptor.pb.h"
// @@protoc_insertion_point(includes)

namespace hw {
namespace trezor {
namespace messages {

// Internal implementation detail -- do not call these.
void  protobuf_AddDesc_messages_2eproto();
void protobuf_AssignDesc_messages_2eproto();
void protobuf_ShutdownFile_messages_2eproto();


enum MessageType {
  MessageType_Initialize = 0,
  MessageType_Ping = 1,
  MessageType_Success = 2,
  MessageType_Failure = 3,
  MessageType_ChangePin = 4,
  MessageType_WipeDevice = 5,
  MessageType_GetEntropy = 9,
  MessageType_Entropy = 10,
  MessageType_LoadDevice = 13,
  MessageType_ResetDevice = 14,
  MessageType_Features = 17,
  MessageType_PinMatrixRequest = 18,
  MessageType_PinMatrixAck = 19,
  MessageType_Cancel = 20,
  MessageType_ClearSession = 24,
  MessageType_ApplySettings = 25,
  MessageType_ButtonRequest = 26,
  MessageType_ButtonAck = 27,
  MessageType_ApplyFlags = 28,
  MessageType_BackupDevice = 34,
  MessageType_EntropyRequest = 35,
  MessageType_EntropyAck = 36,
  MessageType_PassphraseRequest = 41,
  MessageType_PassphraseAck = 42,
  MessageType_PassphraseStateRequest = 77,
  MessageType_PassphraseStateAck = 78,
  MessageType_RecoveryDevice = 45,
  MessageType_WordRequest = 46,
  MessageType_WordAck = 47,
  MessageType_GetFeatures = 55,
  MessageType_SetU2FCounter = 63,
  MessageType_FirmwareErase = 6,
  MessageType_FirmwareUpload = 7,
  MessageType_FirmwareRequest = 8,
  MessageType_SelfTest = 32,
  MessageType_GetPublicKey = 11,
  MessageType_PublicKey = 12,
  MessageType_SignTx = 15,
  MessageType_TxRequest = 21,
  MessageType_TxAck = 22,
  MessageType_GetAddress = 29,
  MessageType_Address = 30,
  MessageType_SignMessage = 38,
  MessageType_VerifyMessage = 39,
  MessageType_MessageSignature = 40,
  MessageType_CipherKeyValue = 23,
  MessageType_CipheredKeyValue = 48,
  MessageType_SignIdentity = 53,
  MessageType_SignedIdentity = 54,
  MessageType_GetECDHSessionKey = 61,
  MessageType_ECDHSessionKey = 62,
  MessageType_CosiCommit = 71,
  MessageType_CosiCommitment = 72,
  MessageType_CosiSign = 73,
  MessageType_CosiSignature = 74,
  MessageType_DebugLinkDecision = 100,
  MessageType_DebugLinkGetState = 101,
  MessageType_DebugLinkState = 102,
  MessageType_DebugLinkStop = 103,
  MessageType_DebugLinkLog = 104,
  MessageType_DebugLinkMemoryRead = 110,
  MessageType_DebugLinkMemory = 111,
  MessageType_DebugLinkMemoryWrite = 112,
  MessageType_DebugLinkFlashErase = 113,
  MessageType_EthereumGetAddress = 56,
  MessageType_EthereumAddress = 57,
  MessageType_EthereumSignTx = 58,
  MessageType_EthereumTxRequest = 59,
  MessageType_EthereumTxAck = 60,
  MessageType_EthereumSignMessage = 64,
  MessageType_EthereumVerifyMessage = 65,
  MessageType_EthereumMessageSignature = 66,
  MessageType_NEMGetAddress = 67,
  MessageType_NEMAddress = 68,
  MessageType_NEMSignTx = 69,
  MessageType_NEMSignedTx = 70,
  MessageType_NEMDecryptMessage = 75,
  MessageType_NEMDecryptedMessage = 76,
  MessageType_LiskGetAddress = 114,
  MessageType_LiskAddress = 115,
  MessageType_LiskSignTx = 116,
  MessageType_LiskSignedTx = 117,
  MessageType_LiskSignMessage = 118,
  MessageType_LiskMessageSignature = 119,
  MessageType_LiskVerifyMessage = 120,
  MessageType_LiskGetPublicKey = 121,
  MessageType_LiskPublicKey = 122,
  MessageType_TezosGetAddress = 150,
  MessageType_TezosAddress = 151,
  MessageType_TezosSignTx = 152,
  MessageType_TezosSignedTx = 153,
  MessageType_TezosGetPublicKey = 154,
  MessageType_TezosPublicKey = 155,
  MessageType_StellarSignTx = 202,
  MessageType_StellarTxOpRequest = 203,
  MessageType_StellarGetAddress = 207,
  MessageType_StellarAddress = 208,
  MessageType_StellarCreateAccountOp = 210,
  MessageType_StellarPaymentOp = 211,
  MessageType_StellarPathPaymentOp = 212,
  MessageType_StellarManageOfferOp = 213,
  MessageType_StellarCreatePassiveOfferOp = 214,
  MessageType_StellarSetOptionsOp = 215,
  MessageType_StellarChangeTrustOp = 216,
  MessageType_StellarAllowTrustOp = 217,
  MessageType_StellarAccountMergeOp = 218,
  MessageType_StellarManageDataOp = 220,
  MessageType_StellarBumpSequenceOp = 221,
  MessageType_StellarSignedTx = 230,
  MessageType_CardanoSignMessage = 300,
  MessageType_CardanoMessageSignature = 301,
  MessageType_CardanoVerifyMessage = 302,
  MessageType_CardanoSignTx = 303,
  MessageType_CardanoTxRequest = 304,
  MessageType_CardanoGetPublicKey = 305,
  MessageType_CardanoPublicKey = 306,
  MessageType_CardanoGetAddress = 307,
  MessageType_CardanoAddress = 308,
  MessageType_CardanoTxAck = 309,
  MessageType_CardanoSignedTx = 310,
  MessageType_OntologyGetAddress = 350,
  MessageType_OntologyAddress = 351,
  MessageType_OntologyGetPublicKey = 352,
  MessageType_OntologyPublicKey = 353,
  MessageType_OntologySignTransfer = 354,
  MessageType_OntologySignedTransfer = 355,
  MessageType_OntologySignWithdrawOng = 356,
  MessageType_OntologySignedWithdrawOng = 357,
  MessageType_OntologySignOntIdRegister = 358,
  MessageType_OntologySignedOntIdRegister = 359,
  MessageType_OntologySignOntIdAddAttributes = 360,
  MessageType_OntologySignedOntIdAddAttributes = 361,
  MessageType_RippleGetAddress = 400,
  MessageType_RippleAddress = 401,
  MessageType_RippleSignTx = 402,
  MessageType_RippleSignedTx = 403,
  MessageType_MoneroTransactionSignRequest = 501,
  MessageType_MoneroTransactionInitAck = 502,
  MessageType_MoneroTransactionSetInputAck = 503,
  MessageType_MoneroTransactionInputsPermutationAck = 504,
  MessageType_MoneroTransactionInputViniAck = 505,
  MessageType_MoneroTransactionAllInputsSetAck = 513,
  MessageType_MoneroTransactionSetOutputAck = 506,
  MessageType_MoneroTransactionRangeSigAck = 514,
  MessageType_MoneroTransactionAllOutSetAck = 507,
  MessageType_MoneroTransactionMlsagDoneAck = 508,
  MessageType_MoneroTransactionSignInputAck = 509,
  MessageType_MoneroTransactionFinalAck = 510,
  MessageType_MoneroKeyImageSyncRequest = 511,
  MessageType_MoneroKeyImageExportInitAck = 520,
  MessageType_MoneroKeyImageSyncStepAck = 521,
  MessageType_MoneroKeyImageSyncFinalAck = 522,
  MessageType_MoneroGetAddress = 530,
  MessageType_MoneroAddress = 531,
  MessageType_MoneroGetWatchKey = 532,
  MessageType_MoneroWatchKey = 533,
  MessageType_MoneroLiteInitRequest = 540,
  MessageType_MoneroLiteInitAck = 541,
  MessageType_MoneroLiteRequest = 542,
  MessageType_MoneroLiteAck = 543,
  MessageType_DebugMoneroDiagRequest = 536,
  MessageType_DebugMoneroDiagAck = 537
};
bool MessageType_IsValid(int value);
const MessageType MessageType_MIN = MessageType_Initialize;
const MessageType MessageType_MAX = MessageType_MoneroLiteAck;
const int MessageType_ARRAYSIZE = MessageType_MAX + 1;

const ::google::protobuf::EnumDescriptor* MessageType_descriptor();
inline const ::std::string& MessageType_Name(MessageType value) {
  return ::google::protobuf::internal::NameOfEnum(
    MessageType_descriptor(), value);
}
inline bool MessageType_Parse(
    const ::std::string& name, MessageType* value) {
  return ::google::protobuf::internal::ParseNamedEnum<MessageType>(
    MessageType_descriptor(), name, value);
}
// ===================================================================


// ===================================================================

static const int kWireInFieldNumber = 50002;
extern ::google::protobuf::internal::ExtensionIdentifier< ::google::protobuf::EnumValueOptions,
    ::google::protobuf::internal::PrimitiveTypeTraits< bool >, 8, false >
  wire_in;
static const int kWireOutFieldNumber = 50003;
extern ::google::protobuf::internal::ExtensionIdentifier< ::google::protobuf::EnumValueOptions,
    ::google::protobuf::internal::PrimitiveTypeTraits< bool >, 8, false >
  wire_out;
static const int kWireDebugInFieldNumber = 50004;
extern ::google::protobuf::internal::ExtensionIdentifier< ::google::protobuf::EnumValueOptions,
    ::google::protobuf::internal::PrimitiveTypeTraits< bool >, 8, false >
  wire_debug_in;
static const int kWireDebugOutFieldNumber = 50005;
extern ::google::protobuf::internal::ExtensionIdentifier< ::google::protobuf::EnumValueOptions,
    ::google::protobuf::internal::PrimitiveTypeTraits< bool >, 8, false >
  wire_debug_out;
static const int kWireTinyFieldNumber = 50006;
extern ::google::protobuf::internal::ExtensionIdentifier< ::google::protobuf::EnumValueOptions,
    ::google::protobuf::internal::PrimitiveTypeTraits< bool >, 8, false >
  wire_tiny;
static const int kWireBootloaderFieldNumber = 50007;
extern ::google::protobuf::internal::ExtensionIdentifier< ::google::protobuf::EnumValueOptions,
    ::google::protobuf::internal::PrimitiveTypeTraits< bool >, 8, false >
  wire_bootloader;
static const int kWireNoFsmFieldNumber = 50008;
extern ::google::protobuf::internal::ExtensionIdentifier< ::google::protobuf::EnumValueOptions,
    ::google::protobuf::internal::PrimitiveTypeTraits< bool >, 8, false >
  wire_no_fsm;

// ===================================================================


// @@protoc_insertion_point(namespace_scope)

}  // namespace messages
}  // namespace trezor
}  // namespace hw

#ifndef SWIG
namespace google {
namespace protobuf {

template <> struct is_proto_enum< ::hw::trezor::messages::MessageType> : ::google::protobuf::internal::true_type {};
template <>
inline const EnumDescriptor* GetEnumDescriptor< ::hw::trezor::messages::MessageType>() {
  return ::hw::trezor::messages::MessageType_descriptor();
}

}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_messages_2eproto__INCLUDED
