// Copyright (c) 2014 The LibTrace Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//   * Neither the name of the <organization> nor the
//     names of its contributors may be used to endorse or promote products
//     derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "parser/etw/etw_raw_kernel_payload_decoder.h"

#include "base/logging.h"
#include "event/value.h"
#include "parser/decoder.h"
#include "parser/etw/etw_raw_payload_decoder_utils.h"

namespace parser {
namespace etw {

namespace {

using event::CharValue;
using event::IntValue;
using event::LongValue;
using event::ShortValue;
using event::StringValue;
using event::StructValue;
using event::UCharValue;
using event::UIntValue;
using event::ULongValue;
using event::UShortValue;
using event::Value;

// Constants for EventTraceEvent events.
const std::string kEventTraceEventProviderId =
    "68FDD900-4A3E-11D1-84F4-0000F80464E3";
const unsigned char kEventTraceEventHeaderOpcode = 0;
const unsigned char kEventTraceEventExtensionOpcode = 5;
const unsigned char kEventTraceEndExtensionOpcode = 32;

// Constants for Image events.
const std::string kImageProviderId = "2CB15D1D-5FC1-11D2-ABE1-00A0C911F518";
const unsigned char kImageUnloadOpcode = 2;
const unsigned char kImageDCStartOpcode = 3;
const unsigned char kImageDCEndOpcode = 4;
const unsigned char kImageLoadOpcode = 10;
const unsigned char kImageKernelBaseOpcode = 33;

// Constants for PerfInfo events.
const std::string kPerfInfoProviderId = "CE1DBFB4-137E-4DA6-87B0-3F59AA102CBC";
const unsigned char kPerfInfoMarkOpcode = 34;
const unsigned char kPerfInfoSampleProfOpcode = 46;
const unsigned char kPerfInfoPmcCounterProfOpcode = 47;
const unsigned char kPerfInfoPmcCtrConfigOpcode = 48;
const unsigned char kPerfInfoISRMSIOpcode = 50;
const unsigned char kPerfInfoSysClEnterOpcode = 51;
const unsigned char kPerfInfoSysClExitOpcode = 52;
const unsigned char kPerfInfoDebuggerEnabledOpcode = 58;
const unsigned char kPerfInfoThreadedDPCOpcode = 66;
const unsigned char kPerfInfoISROpcode = 67;
const unsigned char kPerfInfoDPCOpcode = 68;
const unsigned char kPerfInfoTimerDPCOpcode = 69;
const unsigned char kPerfInfoIOTimerOpcode = 70;
const unsigned char kPerfInfoCollectionSetIntervalOpcode = 72;
const unsigned char kPerfInfoCollectionStartOpcode = 73;
const unsigned char kPerfInfoCollectionEndOpcode = 74;
const unsigned char kPerfInfoCollectionStartSecondOpcode = 75;
const unsigned char kPerfInfoCollectionEndSecondOpcode = 76;
const unsigned char kPerfInfoUnknown80Opcode = 80;
const unsigned char kPerfInfoUnknown81Opcode = 81;
const unsigned char kPerfInfoUnknown82Opcode = 82;
const unsigned char kPerfInfoUnknown83Opcode = 83;
const unsigned char kPerfInfoUnknown84Opcode = 84;
const unsigned char kPerfInfoUnknown85Opcode = 85;
const unsigned char kPerfInfoISRUnexpectedOpcode = 92;
const unsigned char kPerfInfoIoStartTimerOpcode = 93;
const unsigned char kPerfInfoIoStopTimerOpcode = 94;
const unsigned char kPerfInfoWdfISROpcode = 96;
const unsigned char kPerfInfoWdfPassiveISROpcode = 97;
const unsigned char kPerfInfoWdfDPCOpcode = 98;

// Constants for Thread events.
const std::string kThreadProviderId = "3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C";
const unsigned char kThreadStartOpcode = 1;
const unsigned char kThreadEndOpcode = 2;
const unsigned char kThreadDCStartOpcode = 3;
const unsigned char kThreadDCEndOpcode = 4;
const unsigned char kThreadCSwitchOpcode = 36;
const unsigned char kThreadCompCSOpcode = 37;
const unsigned char kThreadSpinLockOpcode = 41;
const unsigned char kThreadSetPriorityOpcode = 48;
const unsigned char kThreadSetBasePriorityOpcode = 49;
const unsigned char kThreadReadyThreadOpcode = 50;
const unsigned char kThreadSetPagePriorityOpcode = 51;
const unsigned char kThreadSetIoPriorityOpcode = 52;
const unsigned char kThreadAutoBoostSetFloorOpcode = 66;
const unsigned char kThreadAutoBoostClearFloorOpcode = 67;
const unsigned char kThreadAutoBoostEntryExhaustionOpcode = 68;

// Constants for Process events.
const std::string kProcessProviderId = "3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C";
const unsigned char kProcessStartOpcode = 1;
const unsigned char kProcessEndOpcode = 2;
const unsigned char kProcessDCStartOpcode = 3;
const unsigned char kProcessDCEndOpcode = 4;
const unsigned char kProcessTerminateOpcode = 11;
const unsigned char kProcessPerfCtrOpcode = 32;
const unsigned char kProcessPerfCtrRundownOpcode = 33;
const unsigned char kProcessDefunctOpcode = 39;

// Constants for Tcplp events.
const std::string kTcplpProviderId = "9A280AC0-C8E0-11D1-84E2-00C04FB998A2";
const unsigned char kTcplpSendIPV4Opcode = 10;
const unsigned char kTcplpRecvIPV4Opcode = 11;
const unsigned char kTcplpConnectIPV4Opcode = 12;
const unsigned char kTcplpDisconnectIPV4Opcode = 13;
const unsigned char kTcplpRetransmitIPV4Opcode = 14;
const unsigned char kTcplpAcceptIPV4Opcode = 15;
const unsigned char kTcplpReconnectIPV4Opcode = 16;
const unsigned char kTcplpFailIPV4Opcode = 17;
const unsigned char kTcplpTCPCopyIPV4Opcode = 18;
const unsigned char kTcplpARPCopyIPV4Opcode = 19;
const unsigned char kTcplpFullACKIPV4Opcode = 20;
const unsigned char kTcplpPartACKIPV4Opcode = 21;
const unsigned char kTcplpDupACKIPV4Opcode = 22;

// Constants for Registry events.
const std::string kRegistryProviderId = "AE53722E-C863-11D2-8659-00C04FA321A1";
const unsigned char kRegistryCreateOpcode = 10;
const unsigned char kRegistryOpenOpcode = 11;
const unsigned char kRegistryDeleteOpcode = 12;
const unsigned char kRegistryQueryOpcode = 13;
const unsigned char kRegistrySetValueOpcode = 14;
const unsigned char kRegistryDeleteValueOpcode = 15;
const unsigned char kRegistryQueryValueOpcode = 16;
const unsigned char kRegistryEnumerateKeyOpcode = 17;
const unsigned char kRegistryEnumerateValueKeyOpcode = 18;
const unsigned char kRegistryQueryMultipleValueOpcode = 19;
const unsigned char kRegistrySetInformationOpcode = 20;
const unsigned char kRegistryFlushOpcode = 21;
const unsigned char kRegistryKCBCreateOpcode = 22;
const unsigned char kRegistryKCBDeleteOpcode = 23;
const unsigned char kRegistryKCBRundownBeginOpcode = 24;
const unsigned char kRegistryKCBRundownEndOpcode = 25;
const unsigned char kRegistryVirtualizeOpcode = 26;
const unsigned char kRegistryCloseOpcode = 27;
const unsigned char kRegistrySetSecurityOpcode = 28;
const unsigned char kRegistryQuerySecurityOpcode = 29;
const unsigned char kRegistryTxRCommitOpcode = 30;
const unsigned char kRegistryTxRPrepareOpcode = 31;
const unsigned char kRegistryTxRRollbackOpcode = 32;
const unsigned char kRegistryCountersOpcode = 34;
const unsigned char kRegistryConfigOpcode = 35;
const unsigned char kRegistryHiveInitOpcode = 36;
const unsigned char kRegistryHiveDestroyOpcode = 37;
const unsigned char kRegistryHiveLinkOpcode = 38;
const unsigned char kRegistryHiveDCEndOpcode = 39;
const unsigned char kRegistryHiveDirtyOpcode = 40;
const unsigned char kRegistryChangeNotifyOpcode = 48;

// Constants for FileIO events.
const std::string kFileIOProviderId = "90CBDC39-4A3E-11D1-84F4-0000F80464E3";
const unsigned char kFileIOFileCreateOpcode = 32;
const unsigned char kFileIOFileDeleteOpcode = 35;
const unsigned char kFileIOFileRundownOpcode = 36;
const unsigned char kFileIOCreateOpcode = 64;
const unsigned char kFileIOCleanupOpcode = 65;
const unsigned char kFileIOCloseOpcode = 66;
const unsigned char kFileIOReadOpcode = 67;
const unsigned char kFileIOWriteOpcode = 68;
const unsigned char kFileIOSetInfoOpcode = 69;
const unsigned char kFileIODeleteOpcode = 70;
const unsigned char kFileIORenameOpcode = 71;
const unsigned char kFileIODirEnumOpcode = 72;
const unsigned char kFileIOFlushOpcode = 73;
const unsigned char kFileIOQueryInfoOpcode = 74;
const unsigned char kFileIOFSControlOpcode = 75;
const unsigned char kFileIOOperationEndOpcode = 76;
const unsigned char kFileIODirNotifyOpcode = 77;
const unsigned char kFileIOUnknown78Opcode = 78;
const unsigned char kFileIODletePathOpcode = 79;
const unsigned char kFileIORenamePathOpcode = 80;

// Constants for StackWalk events.
const std::string kStackWalkProviderId = "DEF2FE46-7BD6-4B80-BD94-F57FE20D0CE3";
const unsigned char kStackWalkStackOpcode = 32;

// Constants for PageFault events.
const std::string kPageFaultProviderId = "3D6FA8D3-FE05-11D0-9DDA-00C04FD7BA7C";
const unsigned char kPageFaultTransitionFaultOpcode = 10;
const unsigned char kPageFaultDemandZeroFaultOpcode = 11;
const unsigned char kPageFaultCopyOnWriteOpcode = 12;
const unsigned char kPageFaultGuardPageFaultOpcode = 13;
const unsigned char kPageFaultHardPageFaultOpcode = 14;
const unsigned char kPageFaultAccessViolationOpcode = 15;
const unsigned char kPageFaultHardFaultOpcode = 32;
const unsigned char kPageFaultUnknown33Opcode = 33;
const unsigned char kPageFaultUnknown34Opcode = 34;
const unsigned char kPageFaultUnknown35Opcode = 35;
const unsigned char kPageFaultUnknown36Opcode = 36;
const unsigned char kPageFaultUnknown47Opcode = 46;
const unsigned char kPageFaultUnknown73Opcode = 73;
const unsigned char kPageFaultUnknown76Opcode = 76;
const unsigned char kPageFaultVirtualAllocOpcode = 98;
const unsigned char kPageFaultVirtualFreeOpcode = 99;
const unsigned char kPageFaultHRRundownOpcode = 100;
const unsigned char kPageFaultHRCreateOpcode = 101;
const unsigned char kPageFaultHRReserveOpcode = 102;
const unsigned char kPageFaultHRReleaseOpcode = 103;
const unsigned char kPageFaultHRDestroyOpcode = 104;
const unsigned char kPageFaultImageLoadBackedOpcode = 105;
const unsigned char kPageFaultUnknown112Opcode = 112;
const unsigned char kPageFaultVirtualAllocDCStartOpcode = 128;
const unsigned char kPageFaultVirtualAllocDCEndpcode = 129;

bool DecodeEventTraceHeaderPayload(Decoder* decoder,
                                   unsigned char version,
                                   unsigned char opcode,
                                   bool is_64_bit,
                                   std::string* operation,
                                   StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kEventTraceEventHeaderOpcode);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "Header";

  // Decode the payload.
  if (!Decode<UIntValue>("BufferSize", decoder, fields) ||
      !Decode<UIntValue>("Version", decoder, fields) ||
      !Decode<UIntValue>("ProviderVersion", decoder, fields) ||
      !Decode<UIntValue>("NumberOfProcessors", decoder, fields) ||
      !Decode<ULongValue>("EndTime", decoder, fields) ||
      !Decode<UIntValue>("TimerResolution", decoder, fields) ||
      !Decode<UIntValue>("MaxFileSize", decoder, fields) ||
      !Decode<UIntValue>("LogFileMode", decoder, fields) ||
      !Decode<UIntValue>("BuffersWritten", decoder, fields) ||
      !Decode<UIntValue>("StartBuffers", decoder, fields) ||
      !Decode<UIntValue>("PointerSize", decoder, fields) ||
      !Decode<UIntValue>("EventsLost", decoder, fields) ||
      !Decode<UIntValue>("CPUSpeed", decoder, fields) ||
      !DecodeUInteger("LoggerName", is_64_bit, decoder, fields) ||
      !DecodeUInteger("LogFileName", is_64_bit, decoder, fields) ||
      !DecodeTimeZoneInformation("TimeZoneInformation", decoder, fields) ||
      !Decode<UIntValue>("Padding", decoder, fields) ||
      !Decode<ULongValue>("BootTime", decoder, fields) ||
      !Decode<ULongValue>("PerfFreq", decoder, fields) ||
      !Decode<ULongValue>("StartTime", decoder, fields) ||
      !Decode<UIntValue>("ReservedFlags", decoder, fields) ||
      !Decode<UIntValue>("BuffersLost", decoder, fields) ||
      !DecodeW16String("SessionNameString", decoder, fields) ||
      !DecodeW16String("LogFileNameString", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeEventTraceExtensionPayload(Decoder* decoder,
                                      unsigned char version,
                                      unsigned char opcode,
                                      bool /* is_64_bit */,
                                      std::string* operation,
                                      StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kEventTraceEventExtensionOpcode);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version > 2)
    return false;

  // Set the operation name.
  *operation = "Extension";

  // Decode the payload.
  if (!Decode<UIntValue>("GroupMask1", decoder, fields) ||
      !Decode<UIntValue>("GroupMask2", decoder, fields) ||
      !Decode<UIntValue>("GroupMask3", decoder, fields) ||
      !Decode<UIntValue>("GroupMask4", decoder, fields) ||
      !Decode<UIntValue>("GroupMask5", decoder, fields) ||
      !Decode<UIntValue>("GroupMask6", decoder, fields) ||
      !Decode<UIntValue>("GroupMask7", decoder, fields) ||
      !Decode<UIntValue>("GroupMask8", decoder, fields)) {
    return false;
  }

  if (version == 2) {
    if (!Decode<UIntValue>("KernelEventVersion", decoder, fields))
      return false;
  }

  return true;
}

bool DecodeEventTracePayload(Decoder* decoder,
                             unsigned char version,
                             unsigned char opcode,
                             bool is_64_bit,
                             std::string* operation,
                             StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  switch (opcode) {
    case kEventTraceEventHeaderOpcode:
      return DecodeEventTraceHeaderPayload(
          decoder, version, opcode, is_64_bit, operation, fields);
    case kEventTraceEventExtensionOpcode:
      return DecodeEventTraceExtensionPayload(
          decoder, version, opcode, is_64_bit, operation, fields);
    default:
      return false;
  }
}

bool DecodeImagePayload(Decoder* decoder,
                        unsigned char version,
                        unsigned char opcode,
                        bool is_64_bit,
                        std::string* operation,
                        StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version > 3)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kImageLoadOpcode:
      // Image load event. Generated when a DLL or executable file is loaded.
      *operation = "Load";
      break;
    case kImageUnloadOpcode:
      // Image unload event. Generated when a DLL or executable file is
      // unloaded.
      *operation = "Unload";
      break;
    case kImageDCStartOpcode:
      // Data collection start event. Enumerates all loaded images at the
      // beginning of the trace.
      *operation = "DCStart";
      break;
    case kImageDCEndOpcode:
      // Data collection end event. Enumerates all loaded images at the end
      // of the trace.
      *operation = "DCEnd";
      break;
    case kImageKernelBaseOpcode:
      // Kernel load address event.
      *operation = "KernelBase";
      break;
    default:
      return false;
  }

  // Decode the payload.
  if (!DecodeUInteger("BaseAddress", is_64_bit, decoder, fields))
    return false;

  if (opcode == kImageKernelBaseOpcode)
    return true;

  if (version == 0) {
    if (!Decode<UIntValue>("ModuleSize", decoder, fields))
      return false;
  } else {
    if (!DecodeUInteger("ModuleSize", is_64_bit, decoder, fields))
      return false;
  }

  if (version >= 1 &&
      !Decode<UIntValue>("ProcessId", decoder, fields)) {
    return false;
  }

  if (version >= 2 && (
      !Decode<UIntValue>("ImageCheckSum", decoder, fields) ||
      !Decode<UIntValue>("TimeDateStamp", decoder, fields))) {
    return false;
  }

  if (version >= 3) {
    if (!Decode<UCharValue>("SignatureLevel", decoder, fields) ||
        !Decode<UCharValue>("SignatureType", decoder, fields) ||
        !Decode<UShortValue>("Reserved0", decoder, fields)) {
      return false;
    }
  } else if (version >= 2) {
    if (!Decode<UIntValue>("Reserved0", decoder, fields))
      return false;
  }

  if (version >= 2 && (
      !DecodeUInteger("DefaultBase", is_64_bit, decoder, fields) ||
      !Decode<UIntValue>("Reserved1", decoder, fields) ||
      !Decode<UIntValue>("Reserved2", decoder, fields) ||
      !Decode<UIntValue>("Reserved3", decoder, fields) ||
      !Decode<UIntValue>("Reserved4", decoder, fields))) {
    return false;
  }

  if (!DecodeW16String("ImageFileName", decoder, fields))
    return false;

  return true;
}

bool DecodePerfInfoCollectionPayload(Decoder* decoder,
                                     unsigned char version,
                                     unsigned char opcode,
                                     bool /* is_64_bit */,
                                     std::string* operation,
                                     StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version < 2 || version > 3)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kPerfInfoCollectionSetIntervalOpcode:
      *operation = "SetInterval";
      break;

    case kPerfInfoCollectionStartOpcode:
      *operation = "CollectionStart";
      break;

    case kPerfInfoCollectionEndOpcode:
      *operation = "CollectionEnd";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<UIntValue>("Source", decoder, fields) ||
      !Decode<UIntValue>("NewInterval", decoder, fields) ||
      !Decode<UIntValue>("OldInterval", decoder, fields)) {
    return false;
  }

  if (version >= 3 &&
      !DecodeW16String("SourceName", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePerfInfoCollectionSecondPayload(Decoder* decoder,
                                           unsigned char version,
                                           unsigned char opcode,
                                           bool /* is_64_bit */,
                                           std::string* operation,
                                           StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 3)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kPerfInfoCollectionStartSecondOpcode:
      *operation = "CollectionStart";
      break;

    case kPerfInfoCollectionEndSecondOpcode:
      *operation = "CollectionEnd";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<UIntValue>("SpinLockSpinThreshold", decoder, fields) ||
      !Decode<UIntValue>("SpinLockContentionSampleRate", decoder, fields) ||
      !Decode<UIntValue>("SpinLockAcquireSampleRate", decoder, fields) ||
      !Decode<UIntValue>("SpinLockHoldThreshold", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePerfInfoISRPayload(Decoder* decoder,
                              unsigned char version,
                              unsigned char opcode,
                              bool is_64_bit,
                              std::string* operation,
                              StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kPerfInfoISRMSIOpcode:
      *operation = "ISR-MSI";
      break;

    case kPerfInfoISROpcode:
      *operation = "ISR";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<ULongValue>("InitialTime", decoder, fields) ||
      !DecodeUInteger("Routine", is_64_bit, decoder, fields) ||
      !Decode<UCharValue>("ReturnValue", decoder, fields) ||
      !Decode<UShortValue>("Vector", decoder, fields) ||
      !Decode<UCharValue>("Reserved", decoder, fields)) {
    return false;
  }

  if (opcode == kPerfInfoISRMSIOpcode &&
      !Decode<UIntValue>("MessageNumber", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePerfInfoDPCPayload(Decoder* decoder,
                              unsigned char version,
                              unsigned char opcode,
                              bool is_64_bit,
                              std::string* operation,
                              StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kPerfInfoThreadedDPCOpcode:
      *operation = "ThreadedDPC";
      break;

    case kPerfInfoDPCOpcode:
      *operation = "DPC";
      break;

    case kPerfInfoTimerDPCOpcode:
      *operation = "TimerDPC";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<ULongValue>("InitialTime", decoder, fields) ||
      !DecodeUInteger("Routine", is_64_bit, decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePerfInfoSysClEnterPayload(Decoder* decoder,
                                     unsigned char version,
                                     unsigned char opcode,
                                     bool is_64_bit,
                                     std::string* operation,
                                     StructValue* fields) {
  DCHECK(opcode == kPerfInfoSysClEnterOpcode);
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "SysClEnter";

  // Decode the payload.
  if (!DecodeUInteger("SysCallAddress", is_64_bit, decoder, fields))
    return false;

  return true;
}

bool DecodePerfInfoSysClExitPayload(Decoder* decoder,
                                    unsigned char version,
                                    unsigned char opcode,
                                    bool /* is_64_bit */,
                                    std::string* operation,
                                    StructValue* fields) {
  DCHECK(opcode == kPerfInfoSysClExitOpcode);
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "SysClExit";

  // Decode the payload.
  if (!Decode<UIntValue>("SysCallNtStatus", decoder, fields))
    return false;

  return true;
}

bool DecodePerfInfoSampleProfPayload(Decoder* decoder,
                                     unsigned char version,
                                     unsigned char opcode,
                                     bool is_64_bit,
                                     std::string* operation,
                                     StructValue* fields) {
  DCHECK(opcode == kPerfInfoSampleProfOpcode);
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "SampleProf";

  // Decode the payload.
  if (!DecodeUInteger("InstructionPointer", is_64_bit, decoder, fields) ||
      !Decode<UIntValue>("ThreadId", decoder, fields) ||
      !Decode<UShortValue>("Count", decoder, fields) ||
      !Decode<UShortValue>("Reserved", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePerfInfoDebuggerEnabledPayload(Decoder* decoder,
                                          unsigned char version,
                                          unsigned char opcode,
                                          bool /* is_64_bit */,
                                          std::string* operation,
                                          StructValue* fields) {
  DCHECK(opcode == kPerfInfoDebuggerEnabledOpcode);
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "DebuggerEnabled";

  return true;
}

bool DecodePerfInfoPayload(Decoder* decoder,
                           unsigned char version,
                           unsigned char opcode,
                           bool is_64_bit,
                           std::string* operation,
                           StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  switch (opcode) {
    case kPerfInfoCollectionSetIntervalOpcode:
    case kPerfInfoCollectionStartOpcode:
    case kPerfInfoCollectionEndOpcode:
      return DecodePerfInfoCollectionPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kPerfInfoCollectionStartSecondOpcode:
    case kPerfInfoCollectionEndSecondOpcode:
      return DecodePerfInfoCollectionSecondPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kPerfInfoISROpcode:
    case kPerfInfoISRMSIOpcode:
      return DecodePerfInfoISRPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kPerfInfoThreadedDPCOpcode:
    case kPerfInfoDPCOpcode:
    case kPerfInfoTimerDPCOpcode:
      return DecodePerfInfoDPCPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kPerfInfoSysClEnterOpcode:
      return DecodePerfInfoSysClEnterPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kPerfInfoSysClExitOpcode:
      return DecodePerfInfoSysClExitPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kPerfInfoSampleProfOpcode:
      return DecodePerfInfoSampleProfPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kPerfInfoUnknown80Opcode:
    case kPerfInfoUnknown81Opcode:
    case kPerfInfoUnknown82Opcode:
    case kPerfInfoUnknown83Opcode:
    case kPerfInfoUnknown84Opcode:
    case kPerfInfoUnknown85Opcode:
      // TODO(fdoray): Decode these events.
      return true;

    case kPerfInfoDebuggerEnabledOpcode:
      return DecodePerfInfoDebuggerEnabledPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    default:
      return false;
  }
}

bool DecodeThreadAutoBoostPayload(Decoder* decoder,
                                  unsigned char version,
                                  unsigned char opcode,
                                  bool is_64_bit,
                                  std::string* operation,
                                  StructValue* fields) {
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (!is_64_bit) {
    LOG(ERROR) << "Event ThreadAutoBoost unsupported in 32 bit.";
    return false;
  }

  if (version != 2)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kThreadAutoBoostEntryExhaustionOpcode:
      *operation = "AutoBoostEntryExhaustion";
      break;

    case kThreadAutoBoostClearFloorOpcode:
      *operation = "AutoBoostClearFloor";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<ULongValue>("LockAddress", decoder, fields) ||
      !Decode<UIntValue>("ThreadId", decoder, fields)) {
    return false;
  }

  if (opcode == kThreadAutoBoostEntryExhaustionOpcode &&
      !decoder->Skip(4)) {
    return false;
  }

  if (opcode == kThreadAutoBoostClearFloorOpcode && (
      !Decode<UShortValue>("BoostBitmap", decoder, fields) ||
      !Decode<UShortValue>("Reserved", decoder, fields))) {
    return false;
  }

  return true;
}

bool DecodeThreadAutoBoostSetFloorPayload(Decoder* decoder,
                                          unsigned char version,
                                          unsigned char opcode,
                                          bool is_64_bit,
                                          std::string* operation,
                                          StructValue* fields) {
  DCHECK(opcode == kThreadAutoBoostSetFloorOpcode);
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (!is_64_bit) {
    LOG(ERROR) << "Event AutoBoostSetFloor unsupported in 32 bit.";
    return false;
  }

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "AutoBoostSetFloor";

  // Decode the payload.
  if (!Decode<ULongValue>("Lock", decoder, fields) ||
      !Decode<UIntValue>("ThreadId", decoder, fields) ||
      !Decode<UCharValue>("NewCpuPriorityFloor", decoder, fields) ||
      !Decode<UCharValue>("OldCpuPriority", decoder, fields) ||
      !Decode<UCharValue>("IoPriorities", decoder, fields) ||
      !Decode<UCharValue>("BoostFlags", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeThreadSetPriorityPayload(Decoder* decoder,
                                    unsigned char version,
                                    unsigned char opcode,
                                    bool is_64_bit,
                                    std::string* operation,
                                    StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (!is_64_bit) {
    LOG(ERROR) << "Event ThreadSetPriority unsupported in 32 bit.";
    return false;
  }

  if (version != 3)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kThreadSetPriorityOpcode:
      *operation = "SetPriority";
      break;

    case kThreadSetIoPriorityOpcode:
      *operation = "SetIoPriority";
      break;

    case kThreadSetBasePriorityOpcode:
      *operation = "SetBasePriority";
      break;

    case kThreadSetPagePriorityOpcode:
      *operation = "SetPagePriority";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<UIntValue>("ThreadId", decoder, fields) ||
      !Decode<UCharValue>("OldPriority", decoder, fields) ||
      !Decode<UCharValue>("NewPriority", decoder, fields) ||
      !Decode<UShortValue>("Reserved", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeThreadCSwitchPayload(Decoder* decoder,
                                unsigned char version,
                                unsigned char opcode,
                                bool /* is_64_bit */,
                                std::string* operation,
                                StructValue* fields) {
  DCHECK(opcode == kThreadCSwitchOpcode);
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "CSwitch";

  // Decode the payload.
  if (!Decode<UIntValue>("NewThreadId", decoder, fields) ||
      !Decode<UIntValue>("OldThreadId", decoder, fields) ||
      !Decode<CharValue>("NewThreadPriority", decoder, fields) ||
      !Decode<CharValue>("OldThreadPriority", decoder, fields) ||
      !Decode<UCharValue>("PreviousCState", decoder, fields) ||
      !Decode<CharValue>("SpareByte", decoder, fields) ||
      !Decode<CharValue>("OldThreadWaitReason", decoder, fields) ||
      !Decode<CharValue>("OldThreadWaitMode", decoder, fields) ||
      !Decode<CharValue>("OldThreadState", decoder, fields) ||
      !Decode<CharValue>("OldThreadWaitIdealProcessor", decoder, fields) ||
      !Decode<UIntValue>("NewThreadWaitTime", decoder, fields) ||
      !Decode<UIntValue>("Reserved", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeThreadCompCSPayload(Decoder* decoder,
                               unsigned char version,
                               unsigned char opcode,
                               bool /* is_64_bit */,
                               std::string* operation,
                               StructValue* fields) {
  DCHECK(opcode == kThreadCompCSOpcode);
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "CompCS";

  // This payload is a compressed version of the CSwitch event.
  // TODO(bergeret): Determine a way to decode this event.
  LOG(ERROR) << "The CompCS Thread event is currently unsupported.";
  return false;
}

bool DecodeThreadReadyThreadPayload(Decoder* decoder,
                                    unsigned char version,
                                    unsigned char opcode,
                                    bool /* is_64_bit */,
                                    std::string* operation,
                                    StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kThreadReadyThreadOpcode);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "ReadyThread";

  // Decode the payload.
  if (!Decode<UIntValue>("TThreadId", decoder, fields) ||
      !Decode<CharValue>("AdjustReason", decoder, fields) ||
      !Decode<CharValue>("AdjustIncrement", decoder, fields) ||
      !Decode<CharValue>("Flag", decoder, fields) ||
      !Decode<CharValue>("Reserved", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeThreadSpinLockPayload(Decoder* decoder,
                                unsigned char version,
                                unsigned char opcode,
                                bool is_64_bit,
                                std::string* operation,
                                StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kThreadSpinLockOpcode);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (!is_64_bit) {
    LOG(ERROR) << "Event ThreadSpinLock unsupported in 32 bit.";
    return false;
  }

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "SpinLock";

  // Decode the payload.
  if (!Decode<ULongValue>("SpinLockAddress", decoder, fields) ||
      !Decode<ULongValue>("CallerAddress", decoder, fields) ||
      !Decode<ULongValue>("AcquireTime", decoder, fields) ||
      !Decode<ULongValue>("ReleaseTime", decoder, fields) ||
      !Decode<UIntValue>("WaitTimeInCycles", decoder, fields) ||
      !Decode<UIntValue>("SpinCount", decoder, fields) ||
      !Decode<UIntValue>("ThreadId", decoder, fields) ||
      !Decode<UIntValue>("InterruptCount", decoder, fields) ||
      !Decode<UCharValue>("Irql", decoder, fields) ||
      !Decode<UCharValue>("AcquireDepth", decoder, fields) ||
      !Decode<UCharValue>("Flag", decoder, fields) ||
      !DecodeArray<UCharValue>("Reserved", 5, decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeThreadStartEndPayload(Decoder* decoder,
                                 unsigned char version,
                                 unsigned char opcode,
                                 bool is_64_bit,
                                 std::string* operation,
                                 StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  // Set the operation name.
  switch (opcode) {
    case kThreadDCStartOpcode:
      *operation = "DCStart";
      break;

    case kThreadStartOpcode:
      *operation = "Start";
      break;

    case kThreadDCEndOpcode:
      *operation = "DCEnd";
      break;

    case kThreadEndOpcode:
      *operation = "End";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<UIntValue>("ProcessId", decoder, fields) ||
      !Decode<UIntValue>("TThreadId", decoder, fields)) {
    return false;
  }

  if (version == 1) {
    if ((opcode == kThreadStartOpcode || opcode == kThreadDCStartOpcode) && (
        !DecodeUInteger("StackBase", is_64_bit, decoder, fields) ||
        !DecodeUInteger("StackLimit", is_64_bit, decoder, fields) ||
        !DecodeUInteger("UserStackBase", is_64_bit, decoder, fields) ||
        !DecodeUInteger("UserStackLimit", is_64_bit, decoder, fields) ||
        !DecodeUInteger("StartAddr", is_64_bit, decoder, fields) ||
        !DecodeUInteger("Win32StartAddr", is_64_bit, decoder, fields) ||
        // This field is a signed char, but is padded to an integer 32-bit.
        !Decode<CharValue>("WaitMode", decoder, fields) ||
        !decoder->Skip(3))) {
      return false;
    }
  } else if (version == 2) {
    if (!DecodeUInteger("StackBase", is_64_bit, decoder, fields) ||
        !DecodeUInteger("StackLimit", is_64_bit, decoder, fields) ||
        !DecodeUInteger("UserStackBase", is_64_bit, decoder, fields) ||
        !DecodeUInteger("UserStackLimit", is_64_bit, decoder, fields) ||
        !DecodeUInteger("StartAddr", is_64_bit, decoder, fields) ||
        !DecodeUInteger("Win32StartAddr", is_64_bit, decoder, fields) ||
        !DecodeUInteger("TebBase", is_64_bit, decoder, fields) ||
        !Decode<UIntValue>("SubProcessTag", decoder, fields)) {
      return false;
    }
  } else if (version == 3) {
    if (!DecodeUInteger("StackBase", is_64_bit, decoder, fields) ||
        !DecodeUInteger("StackLimit", is_64_bit, decoder, fields) ||
        !DecodeUInteger("UserStackBase", is_64_bit, decoder, fields) ||
        !DecodeUInteger("UserStackLimit", is_64_bit, decoder, fields) ||
        !DecodeUInteger("Affinity", is_64_bit, decoder, fields) ||
        !DecodeUInteger("Win32StartAddr", is_64_bit, decoder, fields) ||
        !DecodeUInteger("TebBase", is_64_bit, decoder, fields) ||
        !Decode<UIntValue>("SubProcessTag", decoder, fields) ||
        !Decode<UCharValue>("BasePriority", decoder, fields) ||
        !Decode<UCharValue>("PagePriority", decoder, fields) ||
        !Decode<UCharValue>("IoPriority", decoder, fields) ||
        !Decode<UCharValue>("ThreadFlags", decoder, fields)) {
      return false;
    }
  } else {
    return false;
  }

  return true;
}

bool DecodeThreadPayload(Decoder* decoder,
                         unsigned char version,
                         unsigned char opcode,
                         bool is_64_bit,
                         std::string* operation,
                         StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  switch (opcode) {
    case kThreadCSwitchOpcode:
      return DecodeThreadCSwitchPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kThreadCompCSOpcode:
      return DecodeThreadCompCSPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kThreadReadyThreadOpcode:
      return DecodeThreadReadyThreadPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kThreadSpinLockOpcode:
      return DecodeThreadSpinLockPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kThreadDCStartOpcode:
    case kThreadStartOpcode:
    case kThreadDCEndOpcode:
    case kThreadEndOpcode:
      return DecodeThreadStartEndPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kThreadAutoBoostClearFloorOpcode:
    case kThreadAutoBoostEntryExhaustionOpcode:
      return DecodeThreadAutoBoostPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kThreadAutoBoostSetFloorOpcode:
      return DecodeThreadAutoBoostSetFloorPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kThreadSetPriorityOpcode:
    case kThreadSetIoPriorityOpcode:
    case kThreadSetBasePriorityOpcode:
    case kThreadSetPagePriorityOpcode:
      return DecodeThreadSetPriorityPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    default:
      return false;
  }
}

bool DecodeProcessStartEndDefunctPayload(Decoder* decoder,
                                         unsigned char version,
                                         unsigned char opcode,
                                         bool is_64_bit,
                                         std::string* operation,
                                         StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (opcode == kProcessDefunctOpcode) {
    if (version < 2 || version > 5)
      return false;
  } else {
    if (version > 4)
      return false;
  }

  // Set the operation name.
  switch (opcode) {
    case kProcessDCStartOpcode:
      *operation = "DCStart";
      break;

    case kProcessStartOpcode:
      *operation = "Start";
      break;

    case kProcessDCEndOpcode:
      *operation = "DCEnd";
      break;

    case kProcessEndOpcode:
      *operation = "End";
      break;

    case kProcessDefunctOpcode:
      *operation = "Defunct";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (version == 1 &&
      !DecodeUInteger("PageDirectoryBase", is_64_bit, decoder, fields)) {
    return false;
  }

  if (version >= 2 &&
      !DecodeUInteger("UniqueProcessKey", is_64_bit, decoder, fields)) {
    return false;
  }

  if (!Decode<UIntValue>("ProcessId", decoder, fields) ||
      !Decode<UIntValue>("ParentId", decoder, fields)) {
    return false;
  }

  if (version >= 1 &&
      !Decode<UIntValue>("SessionId", decoder, fields) ||
      !Decode<IntValue>("ExitStatus", decoder, fields)) {
    return false;
  }

  if (version >= 3 &&
      !DecodeUInteger("DirectoryTableBase", is_64_bit, decoder, fields)) {
    return false;
  }

  if (version >= 4 &&
      !Decode<UIntValue>("Flags", decoder, fields)) {
    return false;
  }

  if (!DecodeSID("UserSID", is_64_bit, decoder, fields))
    return false;

  if (version >= 1 &&
      !Decode<StringValue>("ImageFileName", decoder, fields)) {
    return false;
  }

  if (version >= 2 &&
      !DecodeW16String("CommandLine", decoder, fields)) {
    return false;
  }

  if (version >= 4 && (
      !DecodeW16String("PackageFullName", decoder, fields) ||
      !DecodeW16String("ApplicationId", decoder, fields))) {
    return false;
  }

  if (version >= 5 &&
      !Decode<ULongValue>("ExitTime", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeProcessTerminatePayload(Decoder* decoder,
                                   unsigned char version,
                                   unsigned char opcode,
                                   bool is_64_bit,
                                   std::string* operation,
                                   StructValue* fields) {
  DCHECK(opcode == kProcessTerminateOpcode);
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "Terminate";

  // Decode the payload.
  if (!Decode<UIntValue>("ProcessId", decoder, fields))
    return false;

  return true;
}

bool DecodeProcessPerfCtrPayload(Decoder* decoder,
                                 unsigned char version,
                                 unsigned char opcode,
                                 bool is_64_bit,
                                 std::string* operation,
                                 StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kProcessPerfCtrOpcode:
      *operation = "PerfCtr";
      break;

    case kProcessPerfCtrRundownOpcode:
      *operation = "PerfCtrRundown";
      break;

    default:
      // TODO(fdoray): NOTREACHED();
      return false;
  }

  // Decode the payload.
  if (!Decode<UIntValue>("ProcessId", decoder, fields) ||
      !Decode<UIntValue>("PageFaultCount", decoder, fields) ||
      !Decode<UIntValue>("HandleCount", decoder, fields) ||
      !Decode<UIntValue>("Reserved", decoder, fields) ||
      !DecodeUInteger("PeakVirtualSize", is_64_bit, decoder, fields) ||
      !DecodeUInteger("PeakWorkingSetSize", is_64_bit, decoder, fields) ||
      !DecodeUInteger("PeakPagefileUsage", is_64_bit, decoder, fields) ||
      !DecodeUInteger("QuotaPeakPagedPoolUsage", is_64_bit,  decoder, fields) ||
      !DecodeUInteger("QuotaPeakNonPagedPoolUsage", is_64_bit, decoder,
                      fields) ||
      !DecodeUInteger("VirtualSize", is_64_bit, decoder, fields) ||
      !DecodeUInteger("WorkingSetSize", is_64_bit, decoder, fields) ||
      !DecodeUInteger("PagefileUsage", is_64_bit, decoder, fields) ||
      !DecodeUInteger("QuotaPagedPoolUsage", is_64_bit, decoder, fields) ||
      !DecodeUInteger("QuotaNonPagedPoolUsage", is_64_bit, decoder, fields) ||
      !DecodeUInteger("PrivatePageCount", is_64_bit, decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeProcessPayload(Decoder* decoder,
                          unsigned char version,
                          unsigned char opcode,
                          bool is_64_bit,
                          std::string* operation,
                          StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  switch (opcode) {
    case kProcessDCStartOpcode:
    case kProcessStartOpcode:
    case kProcessDefunctOpcode:
    case kProcessDCEndOpcode:
    case kProcessEndOpcode:
      return DecodeProcessStartEndDefunctPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kProcessTerminateOpcode:
      return DecodeProcessTerminatePayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kProcessPerfCtrOpcode:
    case kProcessPerfCtrRundownOpcode:
      return DecodeProcessPerfCtrPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    default:
      return false;
  }
}

bool DecodeTcplpGroup1IPV4Payload(Decoder* decoder,
                                  unsigned char version,
                                  unsigned char opcode,
                                  bool is_64_bit,
                                  std::string* operation,
                                  StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kTcplpRecvIPV4Opcode:
      *operation = "RecvIPV4";
      break;

    case kTcplpDisconnectIPV4Opcode:
      *operation = "DisconnectIPV4";
      break;

    case kTcplpRetransmitIPV4Opcode:
      *operation = "RetransmitIPV4";
      break;

    case kTcplpReconnectIPV4Opcode:
      *operation = "ReconnectIPV4";
      break;

    case kTcplpTCPCopyIPV4Opcode:
      *operation = "TCPCopyIPV4";
      break;

    default:
      // TODO(fdoray): NOTREACHED();
      return false;
  }

  // Decode the payload.
  if (!Decode<UIntValue>("PID", decoder, fields) ||
      !Decode<UIntValue>("size", decoder, fields) ||
      !Decode<UIntValue>("daddr", decoder, fields) ||
      !Decode<UIntValue>("saddr", decoder, fields) ||
      !Decode<UShortValue>("dport", decoder, fields) ||
      !Decode<UShortValue>("sport", decoder, fields) ||
      !Decode<UIntValue>("seqnum", decoder, fields) ||
      !DecodeUInteger("connid", is_64_bit, decoder, fields)) {
    return false;
  }

  return true;
}


bool DecodeTcplpGroup2IPV4Payload(Decoder* decoder,
                                  unsigned char version,
                                  unsigned char opcode,
                                  bool is_64_bit,
                                  std::string* operation,
                                  StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kTcplpConnectIPV4Opcode:
      *operation = "ConnectIPV4";
      break;
    case kTcplpAcceptIPV4Opcode:
      *operation = "AcceptIPV4";
      break;
    default:
      // TODO(fdoray): NOTREACHED();
      return false;
  }

  // Decode the payload.
  if (!Decode<UIntValue>("PID", decoder, fields) ||
      !Decode<UIntValue>("size", decoder, fields) ||
      !Decode<UIntValue>("daddr", decoder, fields) ||
      !Decode<UIntValue>("saddr", decoder, fields) ||
      !Decode<UShortValue>("dport", decoder, fields) ||
      !Decode<UShortValue>("sport", decoder, fields) ||
      !Decode<UShortValue>("mss", decoder, fields) ||
      !Decode<UShortValue>("sackopt", decoder, fields) ||
      !Decode<UShortValue>("tsopt", decoder, fields) ||
      !Decode<UShortValue>("wsopt", decoder, fields) ||
      !Decode<UIntValue>("rcvwin", decoder, fields) ||
      !Decode<ShortValue>("rcvwinscale", decoder, fields) ||
      !Decode<ShortValue>("sndwinscale", decoder, fields) ||
      !Decode<UIntValue>("seqnum", decoder, fields) ||
      !DecodeUInteger("connid", is_64_bit, decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeTcplpSendIPV4Payload(Decoder* decoder,
                                unsigned char version,
                                unsigned char opcode,
                                bool is_64_bit,
                                std::string* operation,
                                StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kTcplpSendIPV4Opcode);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "SendIPV4";

  // Decode the payload.
  if (!Decode<UIntValue>("PID", decoder, fields) ||
      !Decode<UIntValue>("size", decoder, fields) ||
      !Decode<UIntValue>("daddr", decoder, fields) ||
      !Decode<UIntValue>("saddr", decoder, fields) ||
      !Decode<UShortValue>("dport", decoder, fields) ||
      !Decode<UShortValue>("sport", decoder, fields) ||
      !Decode<UIntValue>("startime", decoder, fields) ||
      !Decode<UIntValue>("endtime", decoder, fields) ||
      !Decode<UIntValue>("seqnum", decoder, fields) ||
      !DecodeUInteger("connid", is_64_bit, decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeTcplpPayload(Decoder* decoder,
                        unsigned char version,
                        unsigned char opcode,
                        bool is_64_bit,
                        std::string* operation,
                        StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  switch (opcode) {
    case kTcplpRecvIPV4Opcode:
    case kTcplpDisconnectIPV4Opcode:
    case kTcplpRetransmitIPV4Opcode:
    case kTcplpReconnectIPV4Opcode:
    case kTcplpTCPCopyIPV4Opcode:
      return DecodeTcplpGroup1IPV4Payload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kTcplpConnectIPV4Opcode:
    case kTcplpAcceptIPV4Opcode:
      return DecodeTcplpGroup2IPV4Payload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kTcplpSendIPV4Opcode:
      return DecodeTcplpSendIPV4Payload(
          decoder, version, opcode, is_64_bit, operation, fields);

    default:
      return false;
  }
}

bool DecodeRegistryGenericPayload(Decoder* decoder,
                                  unsigned char version,
                                  unsigned char opcode,
                                  bool is_64_bit,
                                  std::string* operation,
                                  StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version < 1 || version > 2)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kRegistryCreateOpcode:
      *operation = "Create";
      break;

    case kRegistryOpenOpcode:
      *operation = "Open";
      break;

    case kRegistryDeleteOpcode:
      *operation = "Delete";
      break;

    case kRegistryQueryOpcode:
      *operation = "Query";
      break;

    case kRegistrySetValueOpcode:
      *operation = "SetValue";
      break;

    case kRegistryDeleteValueOpcode:
      *operation = "DeleteValue";
      break;

    case kRegistryQueryValueOpcode:
      *operation = "QueryValue";
      break;

    case kRegistryEnumerateKeyOpcode:
      *operation = "EnumerateKey";
      break;

    case kRegistryEnumerateValueKeyOpcode:
      *operation = "EnumerateValueKey";
      break;

    case kRegistryQueryMultipleValueOpcode:
      *operation = "QueryMultipleValue";
      break;

    case kRegistrySetInformationOpcode:
      *operation = "SetInformation";
      break;

    case kRegistryFlushOpcode:
      *operation = "Flush";
      break;

    case kRegistryKCBCreateOpcode:
      *operation = "KCBCreate";
      break;

    case kRegistryKCBDeleteOpcode:
      *operation = "KCBDelete";
      break;

    case kRegistryKCBRundownBeginOpcode:
      *operation = "KCBRundownBegin";
      break;

    case kRegistryKCBRundownEndOpcode:
      *operation = "KCBRundownEnd";
      break;

    case kRegistryVirtualizeOpcode:
      *operation = "Virtualize";
      break;

    case kRegistryCloseOpcode:
      *operation = "Close";
      break;

    case kRegistrySetSecurityOpcode:
      *operation = "SetSecurity";
      break;

    case kRegistryQuerySecurityOpcode:
      *operation = "QuerySecurity";
      break;

    default:
      // TODO(fdoray): NOTREACHED();
      return false;
  }

  // Decode the payload.
  if (version == 1) {
    if (!Decode<UIntValue>("Status", decoder, fields) ||
        !DecodeUInteger("KeyHandle", is_64_bit, decoder, fields) ||
        !Decode<LongValue>("ElapsedTime", decoder, fields) ||
        !Decode<UIntValue>("Index", decoder, fields) ||
        !DecodeW16String("KeyName", decoder, fields)) {
      return false;
    }
  } else {
    if (!Decode<LongValue>("InitialTime", decoder, fields) ||
        !Decode<UIntValue>("Status", decoder, fields) ||
        !Decode<UIntValue>("Index", decoder, fields) ||
        !DecodeUInteger("KeyHandle", is_64_bit, decoder, fields) ||
        !DecodeW16String("KeyName", decoder, fields)) {
      return false;
    }
  }

  return true;
}

bool DecodeRegistryCountersPayload(Decoder* decoder,
                                   unsigned char version,
                                   unsigned char opcode,
                                   bool /* is_64_bit */,
                                   std::string* operation,
                                   StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kRegistryCountersOpcode);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "Counters";

  // Decode the payload.
  if (!Decode<ULongValue>("Counter1", decoder, fields) ||
      !Decode<ULongValue>("Counter2", decoder, fields) ||
      !Decode<ULongValue>("Counter3", decoder, fields) ||
      !Decode<ULongValue>("Counter4", decoder, fields) ||
      !Decode<ULongValue>("Counter5", decoder, fields) ||
      !Decode<ULongValue>("Counter6", decoder, fields) ||
      !Decode<ULongValue>("Counter7", decoder, fields) ||
      !Decode<ULongValue>("Counter8", decoder, fields) ||
      !Decode<ULongValue>("Counter9", decoder, fields) ||
      !Decode<ULongValue>("Counter10", decoder, fields) ||
      !Decode<ULongValue>("Counter11", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeRegistryConfigPayload(Decoder* decoder,
                                 unsigned char version,
                                 unsigned char opcode,
                                 bool /* is_64_bit */,
                                 std::string* operation,
                                 StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kRegistryConfigOpcode);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "Config";

  // Decode the payload.
  if (!Decode<UIntValue>("CurrentControlSet", decoder, fields))
    return false;

  return true;
}

bool DecodeRegistryPayload(Decoder* decoder,
                           unsigned char version,
                           unsigned char opcode,
                           bool is_64_bit,
                           std::string* operation,
                           StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  switch (opcode) {
    case kRegistryCreateOpcode:
    case kRegistryOpenOpcode:
    case kRegistryDeleteOpcode:
    case kRegistryQueryOpcode:
    case kRegistrySetValueOpcode:
    case kRegistryDeleteValueOpcode:
    case kRegistryQueryValueOpcode:
    case kRegistryEnumerateKeyOpcode:
    case kRegistryEnumerateValueKeyOpcode:
    case kRegistryQueryMultipleValueOpcode:
    case kRegistrySetInformationOpcode:
    case kRegistryFlushOpcode:
    case kRegistryKCBCreateOpcode:
    case kRegistryKCBDeleteOpcode:
    case kRegistryKCBRundownBeginOpcode:
    case kRegistryKCBRundownEndOpcode:
    case kRegistryVirtualizeOpcode:
    case kRegistryCloseOpcode:
    case kRegistrySetSecurityOpcode:
    case kRegistryQuerySecurityOpcode:
      return DecodeRegistryGenericPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kRegistryCountersOpcode:
      return DecodeRegistryCountersPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kRegistryConfigOpcode:
      return DecodeRegistryConfigPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    default:
      return false;
  }
}

bool DecodeFileIOFileNamePayload(Decoder* decoder,
                                 unsigned char version,
                                 unsigned char opcode,
                                 bool is_64_bit,
                                 std::string* operation,
                                 StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kFileIOFileCreateOpcode:
      *operation = "FileCreate";
      break;
    case kFileIOFileDeleteOpcode:
      *operation = "FileDelete";
      break;
    case kFileIOFileRundownOpcode:
      *operation = "FileRundown";
      break;
    default:
      return false;
  }

  // Decode the payload.
  if (!DecodeUInteger("FileObject", is_64_bit, decoder, fields) ||
      !DecodeW16String("FileName", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeFileIOCreatePayload(Decoder* decoder,
                               unsigned char version,
                               unsigned char opcode,
                               bool is_64_bit,
                               std::string* operation,
                               StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kFileIOCreateOpcode);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version < 2 || version > 3)
    return false;

  // Set the operation name.
  *operation = "Create";

  // Decode the payload.
  if (!DecodeUInteger("IrpPtr", is_64_bit, decoder, fields))
    return false;

  if (version == 2 && (
      !Decode<UIntValue>("TTID", decoder, fields) ||
      !DecodeUInteger("FileObject", is_64_bit, decoder, fields))) {
    return false;
  }

  if (version == 3 && (
      !DecodeUInteger("FileObject", is_64_bit, decoder, fields) ||
      !Decode<UIntValue>("TTID", decoder, fields))) {
    return false;
  }

  if (!Decode<UIntValue>("CreateOptions", decoder, fields) ||
      !Decode<UIntValue>("FileAttributes", decoder, fields) ||
      !Decode<UIntValue>("ShareAccess", decoder, fields) ||
      !DecodeW16String("OpenPath", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeFileIOSimpleOpPayload(Decoder* decoder,
                                 unsigned char version,
                                 unsigned char opcode,
                                 bool is_64_bit,
                                 std::string* operation,
                                 StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version < 2 || version > 3)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kFileIOCleanupOpcode:
      *operation = "Cleanup";
      break;
    case kFileIOCloseOpcode:
      *operation = "Close";
      break;
    case kFileIOFlushOpcode:
      *operation = "Flush";
      break;
    default:
      return false;
  }

  // Decode the payload.
  if (!DecodeUInteger("IrpPtr", is_64_bit, decoder, fields))
    return false;

  if (version == 2 && (
      !Decode<UIntValue>("TTID", decoder, fields) ||
      !DecodeUInteger("FileObject", is_64_bit, decoder, fields) ||
      !DecodeUInteger("FileKey", is_64_bit, decoder, fields))) {
    return false;
  }

  if (version == 3 && (
      !DecodeUInteger("FileObject", is_64_bit, decoder, fields) ||
      !DecodeUInteger("FileKey", is_64_bit, decoder, fields) ||
      !Decode<UIntValue>("TTID", decoder, fields))) {
    return false;
  }

  return true;
}

bool DecodeFileIOReadWritePayload(Decoder* decoder,
                                  unsigned char version,
                                  unsigned char opcode,
                                  bool is_64_bit,
                                  std::string* operation,
                                  StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version < 2 || version > 3)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kFileIOReadOpcode:
      *operation = "Read";
      break;
    case kFileIOWriteOpcode:
      *operation = "Write";
      break;
    default:
      return false;
  }

  // Decode the payload.
  if (!Decode<ULongValue>("Offset", decoder, fields) ||
      !DecodeUInteger("IrpPtr", is_64_bit, decoder, fields)) {
    return false;
  }
  
  if (version == 2 &&
      !Decode<UIntValue>("TTID", decoder, fields)) {
    return false;
  }
  
  if (!DecodeUInteger("FileObject", is_64_bit, decoder, fields) ||
      !DecodeUInteger("FileKey", is_64_bit, decoder, fields)) {
    return false;
  }
  
  if (version == 3 &&
      !Decode<UIntValue>("TTID", decoder, fields)) {
    return false;
  }
  
  if (!Decode<UIntValue>("IoSize", decoder, fields) ||
      !Decode<UIntValue>("IoFlags", decoder, fields)) {
    return false;
  }

  // Padding at the end of 64 bit events.
  if (is_64_bit && !decoder->Skip(4))
    return false;

  return true;
}

bool DecodeFileIOPathPayload(Decoder* decoder,
                             unsigned char version,
                             unsigned char opcode,
                             bool is_64_bit,
                             std::string* operation,
                             StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (!is_64_bit || version != 3)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kFileIODletePathOpcode:
      *operation = "DeletePath";
      break;
    case kFileIORenamePathOpcode:
      *operation = "RenamePath";
      break;
    default:
      return false;
  }

  // Decode the payload.
  if (!Decode<ULongValue>("IrpPtr", decoder, fields) ||
      !Decode<ULongValue>("FileObject", decoder, fields) ||
      !Decode<ULongValue>("FileKey", decoder, fields) ||
      !Decode<ULongValue>("ExtraInfo", decoder, fields) ||
      !Decode<UIntValue>("TTID", decoder, fields) ||
      !Decode<UIntValue>("InfoClass", decoder, fields) ||
      !DecodeW16String("FileName", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeFileIOInfoPayload(Decoder* decoder,
                             unsigned char version,
                             unsigned char opcode,
                             bool is_64_bit,
                             std::string* operation,
                             StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version < 2 && version > 3)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kFileIOSetInfoOpcode:
      *operation = "SetInfo";
      break;
    case kFileIODeleteOpcode:
      *operation = "Delete";
      break;
    case kFileIORenameOpcode:
      *operation = "Rename";
      break;
    case kFileIOQueryInfoOpcode:
      *operation = "QueryInfo";
      break;
    case kFileIOFSControlOpcode:
      *operation = "FSControl";
      break;
    default:
      return false;
  }

  // Decode the payload.
  if (!DecodeUInteger("IrpPtr", is_64_bit, decoder, fields))
    return false;
  
  if (version == 2 &&
      !Decode<UIntValue>("TTID", decoder, fields)) {
    return false;
  }
  

  if (!DecodeUInteger("FileObject", is_64_bit, decoder, fields) ||
      !DecodeUInteger("FileKey", is_64_bit, decoder, fields) ||
      !DecodeUInteger("ExtraInfo", is_64_bit, decoder, fields)) {
    return false;
  }
  
  if (version == 3 &&
      !Decode<UIntValue>("TTID", decoder, fields)) {
    return false;
  }
  
  if (!Decode<UIntValue>("InfoClass", decoder, fields))
    return false;

  return true;
}

bool DecodeFileIODirPayload(Decoder* decoder,
                            unsigned char version,
                            unsigned char opcode,
                            bool is_64_bit,
                            std::string* operation,
                            StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version < 2 || version > 3)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kFileIODirEnumOpcode:
      *operation = "DirEnum";
      break;
    case kFileIODirNotifyOpcode:
      *operation = "DirNotify";
      break;
    default:
      return false;
  }

  // Decode the payload.
  if (!DecodeUInteger("IrpPtr", is_64_bit, decoder, fields))
    return false;
  
  if (version == 2 &&
      !Decode<UIntValue>("TTID", decoder, fields)) {
    return false;
  }

  if (!DecodeUInteger("FileObject", is_64_bit, decoder, fields) ||
      !DecodeUInteger("FileKey", is_64_bit, decoder, fields)) {
    return false;
  }

  if (version == 3 &&
      !Decode<UIntValue>("TTID", decoder, fields)) {
    return false;
  }
  
  if (!Decode<UIntValue>("Length", decoder, fields) ||
      !Decode<UIntValue>("InfoClass", decoder, fields) ||
      !Decode<UIntValue>("FileIndex", decoder, fields) ||
      !DecodeW16String("FileName", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeFileIOOperationEndPayload(Decoder* decoder,
                                     unsigned char version,
                                     unsigned char opcode,
                                     bool is_64_bit,
                                     std::string* operation,
                                     StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kFileIOOperationEndOpcode);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version < 2 || version > 3)
    return false;

  // Set the operation name.
  *operation = "OperationEnd";

  // Decode the payload.
  if (!DecodeUInteger("IrpPtr", is_64_bit, decoder, fields) ||
      !DecodeUInteger("ExtraInfo", is_64_bit, decoder, fields) ||
      !Decode<UIntValue>("NtStatus", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeFileIOPayload(Decoder* decoder,
                         unsigned char version,
                         unsigned char opcode,
                         bool is_64_bit,
                         std::string* operation,
                         StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  switch (opcode) {
    case kFileIOFileCreateOpcode:
    case kFileIOFileDeleteOpcode:
    case kFileIOFileRundownOpcode:
      return DecodeFileIOFileNamePayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kFileIOCreateOpcode:
      return DecodeFileIOCreatePayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kFileIOCleanupOpcode:
    case kFileIOCloseOpcode:
    case kFileIOFlushOpcode:
      return DecodeFileIOSimpleOpPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kFileIOReadOpcode:
    case kFileIOWriteOpcode:
      return DecodeFileIOReadWritePayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kFileIODletePathOpcode:
    case kFileIORenamePathOpcode:
      return DecodeFileIOPathPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kFileIOSetInfoOpcode:
    case kFileIODeleteOpcode:
    case kFileIORenameOpcode:
    case kFileIOQueryInfoOpcode:
    case kFileIOFSControlOpcode:
      return DecodeFileIOInfoPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kFileIODirEnumOpcode:
    case kFileIODirNotifyOpcode:
      return DecodeFileIODirPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kFileIOOperationEndOpcode:
      return DecodeFileIOOperationEndPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    default:
      return false;
  }
}

bool DecodeStackWalkPayload(Decoder* decoder,
                            unsigned char version,
                            unsigned char opcode,
                            bool is_64_bit,
                            std::string* operation,
                            StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2 || opcode != kStackWalkStackOpcode || !is_64_bit)
    return false;

  // Set the operation name.
  *operation = "Stack";

  // Deduce the number of stack pointers from the event size.
  size_t num_stack_pointers = (decoder->RemainingBytes() - sizeof(int64) -
                               2 * sizeof(uint32)) / sizeof(uint64);

  // Decode the payload.
  if (!Decode<ULongValue>("EventTimeStamp", decoder, fields) ||
      !Decode<UIntValue>("StackProcess", decoder, fields) ||
      !Decode<UIntValue>("StackThread", decoder, fields) ||
      !DecodeArray<ULongValue>("Stack", num_stack_pointers, decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePageFaultCommonPageFaultPayload(Decoder* decoder,
                                           unsigned char version,
                                           unsigned char opcode,
                                           bool is_64_bit,
                                           std::string* operation,
                                           StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kPageFaultTransitionFaultOpcode:
      *operation = "TransitionFault";
      break;
    case kPageFaultDemandZeroFaultOpcode:
      *operation = "DemandZeroFault";
      break;
    case kPageFaultCopyOnWriteOpcode:
      *operation = "CopyOnWrite";
      break;
    case kPageFaultGuardPageFaultOpcode:
      *operation = "GuardPageFault";
      break;
    case kPageFaultHardPageFaultOpcode:
      *operation = "HardPageFault";
      break;
    case kPageFaultAccessViolationOpcode:
      *operation = "AccessViolation";
      break;
    default:
      return false;
  }

  // Decode the payload.
  if (!DecodeUInteger("VirtualAddress", is_64_bit, decoder, fields) ||
      !DecodeUInteger("ProgramCounter", is_64_bit, decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePageFaultHardPageFaultPayload(Decoder* decoder,
                                         unsigned char version,
                                         unsigned char opcode,
                                         bool is_64_bit,
                                         std::string* operation,
                                         StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kPageFaultHardFaultOpcode);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  *operation = "HardFault";

  // Decode the payload.
  if (!Decode<ULongValue>("InitialTime", decoder, fields) ||
      !Decode<ULongValue>("ReadOffset", decoder, fields) ||
      !DecodeUInteger("VirtualAddress", is_64_bit, decoder, fields) ||
      !DecodeUInteger("FileObject", is_64_bit, decoder, fields) ||
      !Decode<UIntValue>("TThreadId", decoder, fields) ||
      !Decode<UIntValue>("ByteCount", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePageFaultVirtualAllocFreePayload(Decoder* decoder,
                                            unsigned char version,
                                            unsigned char opcode,
                                            bool is_64_bit,
                                            std::string* operation,
                                            StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the operation name.
  switch (opcode) {
    case kPageFaultVirtualAllocOpcode:
      *operation = "VirtualAlloc";
      break;
    case kPageFaultVirtualFreeOpcode:
      *operation = "VirtualFree";
      break;
    default:
      return false;
  }

  // Decode the payload.
  if (!DecodeUInteger("BaseAddress", is_64_bit, decoder, fields) ||
      !DecodeUInteger("RegionSize", is_64_bit, decoder, fields) ||
      !Decode<UIntValue>("ProcessId", decoder, fields) ||
      !Decode<UIntValue>("Flags", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePageFaultPayload(Decoder* decoder,
                            unsigned char version,
                            unsigned char opcode,
                            bool is_64_bit,
                            std::string* operation,
                            StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(operation != NULL);
  DCHECK(fields != NULL);

  switch (opcode) {
    case kPageFaultTransitionFaultOpcode:
    case kPageFaultDemandZeroFaultOpcode:
    case kPageFaultCopyOnWriteOpcode:
    case kPageFaultGuardPageFaultOpcode:
    case kPageFaultHardPageFaultOpcode:
    case kPageFaultAccessViolationOpcode:
      return DecodePageFaultCommonPageFaultPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kPageFaultHardFaultOpcode:
      return DecodePageFaultHardPageFaultPayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    case kPageFaultVirtualAllocOpcode:
    case kPageFaultVirtualFreeOpcode:
      return DecodePageFaultVirtualAllocFreePayload(
          decoder, version, opcode, is_64_bit, operation, fields);

    default:
      return false;
  }
}

}  // namespace

bool DecodeRawETWKernelPayload(const std::string& provider_id,
                               unsigned char version,
                               unsigned char opcode,
                               bool is_64_bit,
                               const char* payload,
                               size_t payload_size,
                               std::string* operation,
                               std::string* category,
                               scoped_ptr<event::Value>* decoded_payload) {
  DCHECK(payload != NULL || payload_size == 0);  // note: payload can be NULL.
  DCHECK(operation != NULL);
  DCHECK(category != NULL);
  DCHECK(decoded_payload != NULL);

  // Create the byte decoder for the encoded payload.
  Decoder decoder(payload, payload_size);
  scoped_ptr<StructValue> fields(new StructValue);

  // Dispatch event by provider (GUID).
  if (provider_id == kEventTraceEventProviderId) {
    if (DecodeEventTracePayload(&decoder, version, opcode, is_64_bit,
                                operation, fields.get())) {
      *category = "EventTraceEvent";
    } else {
      LOG(WARNING) << "Error while decoding EventTraceEvent payload.";
      return false;
    }
  } else if (provider_id == kImageProviderId) {
    if (DecodeImagePayload(&decoder, version, opcode, is_64_bit,
                           operation, fields.get())) {
      *category = "Image";
    } else {
      LOG(ERROR) << "Error while decoding Image payload.";
      return false;
    }
  } else if (provider_id == kPerfInfoProviderId) {
    if (DecodePerfInfoPayload(&decoder, version, opcode, is_64_bit,
                              operation, fields.get())) {
      *category = "PerfInfo";
    } else {
      // TODO(etienneb): Complete the decoding of these payload.
      LOG(WARNING) << "Error while decoding PerfInfo payload.";
      return false;
    }
  } else if (provider_id == kThreadProviderId) {
    if (DecodeThreadPayload(&decoder, version, opcode, is_64_bit,
                            operation, fields.get())) {
      *category = "Thread";
    } else {
      // TODO(etienneb): Complete the decoding of these payload.
      LOG(WARNING) << "Error while decoding Thread payload.";
      return false;
    }
  } else if (provider_id == kProcessProviderId) {
    if (DecodeProcessPayload(&decoder, version, opcode, is_64_bit,
                             operation, fields.get())) {
      *category = "Process";
    } else {
      LOG(WARNING) << "Error while decoding Process payload.";
      return false;
    }
  } else if (provider_id == kTcplpProviderId) {
    if (DecodeTcplpPayload(&decoder, version, opcode, is_64_bit,
                           operation, fields.get())) {
      *category = "Tcplp";
    } else {
      LOG(WARNING) << "Error while decoding Tcplp payload.";
      return false;
    }
  } else if (provider_id == kRegistryProviderId) {
    if (DecodeRegistryPayload(&decoder, version, opcode, is_64_bit,
                              operation, fields.get())) {
      *category = "Registry";
    } else {
      LOG(WARNING) << "Error while decoding Registry payload.";
      return false;
    }
  } else if (provider_id == kFileIOProviderId) {
    if (DecodeFileIOPayload(&decoder, version, opcode, is_64_bit,
                            operation, fields.get())) {
      *category = "FileIO";
    } else {
      LOG(WARNING) << "Error while decoding FileIO payload.";
      return false;
    }
  } else if (provider_id == kStackWalkProviderId) {
    if (DecodeStackWalkPayload(&decoder, version, opcode, is_64_bit,
                               operation, fields.get())) {
      *category = "StackWalk";
    } else {
      LOG(WARNING) << "Error while decoding StackWalk payload.";
      return false;
    }
  } else if (provider_id == kPageFaultProviderId) {
    if (DecodePageFaultPayload(&decoder, version, opcode, is_64_bit,
                               operation, fields.get())) {
      *category = "PageFault";
    } else {
      LOG(WARNING) << "Error while decoding PageFault payload.";
      return false;
    }
  } else {
    // Unsupported event.
    return false;
  }

  // Make sure that all the payload has been decoded.
  if (decoder.RemainingBytes() != 0)
    return false;

  // Successful decoding of this event.
  *decoded_payload = fields.Pass();
  return true;
}

}  // namespace etw
}  // namespace parser
