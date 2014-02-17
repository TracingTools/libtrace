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
using event::StringValue;
using event::StructValue;
using event::UCharValue;
using event::UIntValue;
using event::ULongValue;
using event::UShortValue;
using event::Value;

// Constants for Image events.
const std::string kImageProviderId = "2CB15D1D-5FC1-11D2-ABE1-00A0C911F518";
const unsigned char kImageUnloadOpcode = 2;
const unsigned char kImageDCStartOpcode = 3;
const unsigned char kImageDCEndOpcode = 4;
const unsigned char kImageLoadOpcode = 10;
const unsigned char kImageKernelBaseOpcode = 33;

// Constants for PerfInfo events.
const std::string kPerfInfoProviderId = "CE1DBFB4-137E-4DA6-87B0-3F59AA102CBC";
const unsigned char kPerfInfoSampleProfOpcode = 46;
const unsigned char kPerfInfoISRMSIOpcode = 50;
const unsigned char kPerfInfoSysClEnterOpcode = 51;
const unsigned char kPerfInfoSysClExitOpcode = 52;
const unsigned char kPerfInfoISROpcode = 67;
const unsigned char kPerfInfoDPCOpcode = 68;
const unsigned char kPerfInfoTimerDPCOpcode = 69;
const unsigned char kPerfInfoCollectionStartSecondOpcode = 73;
const unsigned char kPerfInfoCollectionEndOpcode = 74;
const unsigned char kPerfInfoCollectionStartOpcode = 75;
const unsigned char kPerfInfoCollectionEndSecondOpcode = 76;
const unsigned char kPerfInfoUnknown80Opcode = 80;
const unsigned char kPerfInfoUnknown81Opcode = 81;
const unsigned char kPerfInfoUnknown82Opcode = 82;
const unsigned char kPerfInfoUnknown83Opcode = 83;
const unsigned char kPerfInfoUnknown84Opcode = 84;
const unsigned char kPerfInfoUnknown85Opcode = 85;

// Constants for Thread events.
const std::string kThreadProviderId = "3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C";
const unsigned char kThreadStartOpcode = 1;
const unsigned char kThreadEndOpcode = 2;
const unsigned char kThreadDCStartOpcode = 3;
const unsigned char kThreadDCEndOpcode = 4;
const unsigned char kThreadCSwitchOpcode = 36;
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

bool DecodeImagePayload(Decoder* decoder,
                        unsigned char version,
                        unsigned char opcode,
                        bool is_64_bit,
                        std::string* event_name,
                        StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version > 3)
    return false;

  // Set the event name.
  switch (opcode) {
    case kImageLoadOpcode:
      // Image load event. Generated when a DLL or executable file is loaded.
      *event_name = "Image_Load";
      break;
    case kImageUnloadOpcode:
      // Image unload event. Generated when a DLL or executable file is
      // unloaded.
      *event_name = "Image_Unload";
      break;
    case kImageDCStartOpcode:
      // Data collection start event. Enumerates all loaded images at the
      // beginning of the trace.
      *event_name = "Image_DCStart";
      break;
    case kImageDCEndOpcode:
      // Data collection end event. Enumerates all loaded images at the end
      // of the trace.
      *event_name = "Image_DCEnd";
      break;
    case kImageKernelBaseOpcode:
      // Kernel load address event.
      *event_name = "Image_KernelBase";
      break;
    default:
      return false;
  }

  if (!DecodeUInteger("BaseAddress", is_64_bit, decoder, fields))
    return false;

  if (opcode == kImageKernelBaseOpcode)
    return true;

  if (is_64_bit && version != 0) {
    if (!Decode<ULongValue>("ModuleSize", decoder, fields))
      return false;
  } else {
    if (!Decode<UIntValue>("ModuleSize", decoder, fields))
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
                                     bool is_64_bit,
                                     std::string* event_name,
                                     StructValue* fields) {
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 3)
    return false;

  // Set the event name.
  switch (opcode) {
    case kPerfInfoCollectionStartOpcode:
      *event_name = "PerfInfo_CollectionStart";
      break;

    case kPerfInfoCollectionEndOpcode:
      *event_name = "PerfInfo_CollectionEnd";
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
                              std::string* event_name,
                              StructValue* fields) {
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  switch (opcode) {
    case kPerfInfoISRMSIOpcode:
      *event_name = "PerfInfo_ISR-MSI";
      break;

    case kPerfInfoISROpcode:
      *event_name = "PerfInfo_ISR";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<ULongValue>("InitialTime", decoder, fields) ||
      !Decode<ULongValue>("Routine", decoder, fields) ||
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

bool DecodePerfInfoCollectionSecondPayload(Decoder* decoder,
                                           unsigned char version,
                                           unsigned char opcode,
                                           bool is_64_bit,
                                           std::string* event_name,
                                           StructValue* fields) {
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 3)
    return false;

  // Set the event name.
  switch (opcode) {
    case kPerfInfoCollectionStartSecondOpcode:
      *event_name = "PerfInfo_CollectionStart";
      break;

    case kPerfInfoCollectionEndSecondOpcode:
      *event_name = "PerfInfo_CollectionEnd";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<UIntValue>("Source", decoder, fields) ||
      !Decode<UIntValue>("NewInterval", decoder, fields) ||
      !Decode<UIntValue>("OldInterval", decoder, fields) ||
      !DecodeW16String("SourceName", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePerfInfoDPCPayload(Decoder* decoder,
                              unsigned char version,
                              unsigned char opcode,
                              bool is_64_bit,
                              std::string* event_name,
                              StructValue* fields) {
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  switch (opcode) {
    case kPerfInfoDPCOpcode:
      *event_name = "PerfInfo_DPC";
      break;

    case kPerfInfoTimerDPCOpcode:
      *event_name = "PerfInfo_TimerDPC";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<ULongValue>("InitialTime", decoder, fields) ||
      !Decode<ULongValue>("Routine", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePerfInfoSysClEnterPayload(Decoder* decoder,
                                     unsigned char version,
                                     unsigned char opcode,
                                     bool is_64_bit,
                                     std::string* event_name,
                                     StructValue* fields) {
  DCHECK(opcode == kPerfInfoSysClEnterOpcode);
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  *event_name = "PerfInfo_SysClEnter";

  // Decode the payload.
  if (!Decode<ULongValue>("SysCallAddress", decoder, fields))
    return false;

  return true;
}

bool DecodePerfInfoSysClExitPayload(Decoder* decoder,
                                    unsigned char version,
                                    unsigned char opcode,
                                    bool is_64_bit,
                                    std::string* event_name,
                                    StructValue* fields) {
  DCHECK(opcode == kPerfInfoSysClExitOpcode);
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  *event_name = "PerfInfo_SysClExit";

  // Decode the payload.
  if (!Decode<UIntValue>("SysCallNtStatus", decoder, fields))
    return false;

  return true;
}

bool DecodePerfInfoSampleProfPayload(Decoder* decoder,
                                     unsigned char version,
                                     unsigned char opcode,
                                     bool is_64_bit,
                                     std::string* event_name,
                                     StructValue* fields) {
  DCHECK(opcode == kPerfInfoSampleProfOpcode);
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  *event_name = "PerfInfo_SampleProf";

  // Decode the payload.
  if (!Decode<ULongValue>("InstructionPointer", decoder, fields) ||
      !Decode<UIntValue>("ThreadId", decoder, fields) ||
      !Decode<UShortValue>("Count", decoder, fields) ||
      !Decode<UShortValue>("Reserved", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodePerfInfoPayload(Decoder* decoder,
                           unsigned char version,
                           unsigned char opcode,
                           bool is_64_bit,
                           std::string* event_name,
                           StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (!is_64_bit)
    return false;

  switch (opcode) {
    case kPerfInfoCollectionStartOpcode:
    case kPerfInfoCollectionEndOpcode:
      return DecodePerfInfoCollectionPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kPerfInfoCollectionStartSecondOpcode:
    case kPerfInfoCollectionEndSecondOpcode:
      return DecodePerfInfoCollectionSecondPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kPerfInfoISROpcode:
    case kPerfInfoISRMSIOpcode:
      return DecodePerfInfoISRPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kPerfInfoDPCOpcode:
    case kPerfInfoTimerDPCOpcode:
      return DecodePerfInfoDPCPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kPerfInfoSysClEnterOpcode:
      return DecodePerfInfoSysClEnterPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kPerfInfoSysClExitOpcode:
      return DecodePerfInfoSysClExitPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kPerfInfoSampleProfOpcode:
      return DecodePerfInfoSampleProfPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kPerfInfoUnknown80Opcode:
    case kPerfInfoUnknown81Opcode:
    case kPerfInfoUnknown82Opcode:
    case kPerfInfoUnknown83Opcode:
    case kPerfInfoUnknown84Opcode:
    case kPerfInfoUnknown85Opcode:
      // TODO(fdoray): Decode these events.
      return true;

    default:
      return false;
  }
}

bool DecodeThreadAutoBoostPayload(Decoder* decoder,
                                  unsigned char version,
                                  unsigned char opcode,
                                  bool is_64_bit,
                                  std::string* event_name,
                                  StructValue* fields) {
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  switch (opcode) {
    case kThreadAutoBoostEntryExhaustionOpcode:
      *event_name = "Thread_AutoBoostEntryExhaustion";
      break;

    case kThreadAutoBoostClearFloorOpcode:
      *event_name = "Thread_AutoBoostClearFloor";
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
                                          std::string* event_name,
                                          StructValue* fields) {
  DCHECK(opcode == kThreadAutoBoostSetFloorOpcode);
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  *event_name = "Thread_AutoBoostSetFloor";

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
                                    std::string* event_name,
                                    StructValue* fields) {
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 3)
    return false;

  // Set the event name.
  switch (opcode) {
    case kThreadSetPriorityOpcode:
      *event_name = "Thread_SetPriority";
      break;

    case kThreadSetIoPriorityOpcode:
      *event_name = "Thread_SetIoPriority";
      break;

    case kThreadSetBasePriorityOpcode:
      *event_name = "Thread_SetBasePriority";
      break;

    case kThreadSetPagePriorityOpcode:
      *event_name = "Thread_SetPagePriority";
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
                                bool is_64_bit,
                                std::string* event_name,
                                StructValue* fields) {
  DCHECK(opcode == kThreadCSwitchOpcode);
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  *event_name = "Thread_CSwitch";

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

bool DecodeThreadReadyThreadPayload(Decoder* decoder,
                                    unsigned char version,
                                    unsigned char opcode,
                                    bool is_64_bit,
                                    std::string* event_name,
                                    StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kThreadReadyThreadOpcode);
  DCHECK(is_64_bit);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  *event_name = "Thread_ReadyThread";

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
                                std::string* event_name,
                                StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(opcode == kThreadSpinLockOpcode);
  DCHECK(is_64_bit);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  *event_name = "Thread_SpinLock";

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
                                 std::string* event_name,
                                 StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(is_64_bit);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 3)
    return false;

  // Set the event name.
  switch (opcode) {
    case kThreadDCStartOpcode:
      *event_name = "Thread_DCStart";
      break;

    case kThreadStartOpcode:
      *event_name = "Thread_Start";
      break;

    case kThreadDCEndOpcode:
      *event_name = "Thread_DCEnd";
      break;

    case kThreadEndOpcode:
      *event_name = "Thread_End";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<UIntValue>("ProcessId", decoder, fields) ||
      !Decode<UIntValue>("TThreadId", decoder, fields) ||
      !Decode<ULongValue>("StackBase", decoder, fields) ||
      !Decode<ULongValue>("StackLimit", decoder, fields) ||
      !Decode<ULongValue>("UserStackBase", decoder, fields) ||
      !Decode<ULongValue>("UserStackLimit", decoder, fields) ||
      !Decode<ULongValue>("Affinity", decoder, fields) ||
      !Decode<ULongValue>("Win32StartAddr", decoder, fields) ||
      !Decode<ULongValue>("TebBase", decoder, fields) ||
      !Decode<UIntValue>("SubProcessTag", decoder, fields) ||
      !Decode<UCharValue>("BasePriority", decoder, fields) ||
      !Decode<UCharValue>("PagePriority", decoder, fields) ||
      !Decode<UCharValue>("IoPriority", decoder, fields) ||
      !Decode<UCharValue>("ThreadFlags", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeThreadPayload(Decoder* decoder,
                         unsigned char version,
                         unsigned char opcode,
                         bool is_64_bit,
                         std::string* event_name,
                         StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (!is_64_bit)
    return false;

  switch (opcode) {
    case kThreadCSwitchOpcode:
      return DecodeThreadCSwitchPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kThreadReadyThreadOpcode:
      return DecodeThreadReadyThreadPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kThreadSpinLockOpcode:
      return DecodeThreadSpinLockPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kThreadDCStartOpcode:
    case kThreadStartOpcode:
    case kThreadDCEndOpcode:
    case kThreadEndOpcode:
      return DecodeThreadStartEndPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kThreadAutoBoostClearFloorOpcode:
    case kThreadAutoBoostEntryExhaustionOpcode:
      return DecodeThreadAutoBoostPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kThreadAutoBoostSetFloorOpcode:
      return DecodeThreadAutoBoostSetFloorPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kThreadSetPriorityOpcode:
    case kThreadSetIoPriorityOpcode:
    case kThreadSetBasePriorityOpcode:
    case kThreadSetPagePriorityOpcode:
      return DecodeThreadSetPriorityPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    default:
      return false;
  }
}

bool DecodeProcessStartEndDefunctPayload(Decoder* decoder,
                                         unsigned char version,
                                         unsigned char opcode,
                                         bool is_64_bit,
                                         std::string* event_name,
                                         StructValue* fields) {
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (opcode == kProcessDefunctOpcode) {
    if (version < 3 || version > 5)
      return false;
  } else {
    if (version < 3 || version > 4)
      return false;
  }

  // Set the event name.
  switch (opcode) {
    case kProcessDCStartOpcode:
      *event_name = "Process_DCStart";
      break;

    case kProcessStartOpcode:
      *event_name = "Process_Start";
      break;

    case kProcessDCEndOpcode:
      *event_name = "Process_DCEnd";
      break;

    case kProcessEndOpcode:
      *event_name = "Process_End";
      break;

    case kProcessDefunctOpcode:
      *event_name = "Process_Defunct";
      break;

    default:
      // TODO(fdoray): NOTREACHED() macro.
      return false;
  }

  // Decode the payload.
  if (!Decode<ULongValue>("UniqueProcessKey", decoder, fields) ||
      !Decode<UIntValue>("ProcessId", decoder, fields) ||
      !Decode<UIntValue>("ParentId", decoder, fields) ||
      !Decode<UIntValue>("SessionId", decoder, fields) ||
      !Decode<IntValue>("ExitStatus", decoder, fields) ||
      !Decode<ULongValue>("DirectoryTableBase", decoder, fields)) {
    return false;
  }

  if (version >= 4 &&
      !Decode<UIntValue>("Flags", decoder, fields)) {
    return false;
  }

  if (!DecodeSID("UserSID", is_64_bit, decoder, fields) ||
      !Decode<StringValue>("ImageFileName", decoder, fields) ||
      !DecodeW16String("CommandLine", decoder, fields)) {
    return false;
  }

  if (version >= 4 && (
      !DecodeW16String("PackageFullName", decoder, fields) ||
      !DecodeW16String("ApplicationId", decoder, fields))) {
    return false;
  }

  if (version == 5 && opcode == kProcessDefunctOpcode &&
      !Decode<ULongValue>("ExitTime", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeProcessTerminatePayload(Decoder* decoder,
                                   unsigned char version,
                                   unsigned char opcode,
                                   bool is_64_bit,
                                   std::string* event_name,
                                   StructValue* fields) {
  DCHECK(opcode == kProcessTerminateOpcode);
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  *event_name = "Process_Terminate";

  // Decode the payload.
  if (!Decode<UIntValue>("ProcessId", decoder, fields))
    return false;

  return true;
}

bool DecodeProcessPerfCtrPayload(Decoder* decoder,
                                 unsigned char version,
                                 unsigned char opcode,
                                 bool is_64_bit,
                                 std::string* event_name,
                                 StructValue* fields) {
  DCHECK(is_64_bit);
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (version != 2)
    return false;

  // Set the event name.
  switch (opcode) {
    case kProcessPerfCtrOpcode:
      *event_name = "Process_PerfCtr";
      break;

    case kProcessPerfCtrRundownOpcode:
      *event_name = "Process_PerfCtrRundown";
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
      !Decode<ULongValue>("PeakVirtualSize", decoder, fields) ||
      !Decode<ULongValue>("PeakWorkingSetSize", decoder, fields) ||
      !Decode<ULongValue>("PeakPagefileUsage", decoder, fields) ||
      !Decode<ULongValue>("QuotaPeakPagedPoolUsage", decoder, fields) ||
      !Decode<ULongValue>("QuotaPeakNonPagedPoolUsage", decoder, fields) ||
      !Decode<ULongValue>("VirtualSize", decoder, fields) ||
      !Decode<ULongValue>("WorkingSetSize", decoder, fields) ||
      !Decode<ULongValue>("PagefileUsage", decoder, fields) ||
      !Decode<ULongValue>("QuotaPagedPoolUsage", decoder, fields) ||
      !Decode<ULongValue>("QuotaNonPagedPoolUsage", decoder, fields) ||
      !Decode<ULongValue>("PrivatePageCount", decoder, fields)) {
    return false;
  }

  return true;
}

bool DecodeProcessPayload(Decoder* decoder,
                          unsigned char version,
                          unsigned char opcode,
                          bool is_64_bit,
                          std::string* event_name,
                          StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(event_name != NULL);
  DCHECK(fields != NULL);

  if (!is_64_bit)
    return false;

  switch (opcode) {
    case kProcessDCStartOpcode:
    case kProcessStartOpcode:
    case kProcessDefunctOpcode:
    case kProcessDCEndOpcode:
    case kProcessEndOpcode:
      return DecodeProcessStartEndDefunctPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kProcessTerminateOpcode:
      return DecodeProcessTerminatePayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

    case kProcessPerfCtrOpcode:
    case kProcessPerfCtrRundownOpcode:
      return DecodeProcessPerfCtrPayload(
          decoder, version, opcode, is_64_bit, event_name, fields);

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
                               std::string* event_name,
                               scoped_ptr<event::Value>* decoded_payload) {
  DCHECK(payload != NULL || payload_size == 0);  // note: payload can be NULL.
  DCHECK(event_name != NULL);
  DCHECK(decoded_payload != NULL);

  // Create the byte decoder for the encoded payload.
  Decoder decoder(payload, payload_size);
  scoped_ptr<StructValue> fields(new StructValue);

  // Dispatch event by provider (GUID).
  if (provider_id == kImageProviderId) {
    if (!DecodeImagePayload(
            &decoder, version, opcode, is_64_bit, event_name, fields.get())) {
      LOG(ERROR) << "Error while decoding Image payload.";
      return false;
    }
  } else if (provider_id == kPerfInfoProviderId) {
    if (!DecodePerfInfoPayload(
            &decoder, version, opcode, is_64_bit, event_name, fields.get())) {
      // TODO(etienneb): Complete the decoding of these payload.
      LOG(WARNING) << "Error while decoding PerfInfo payload.";
      return false;
    }
  } else if (provider_id == kThreadProviderId) {
    if (!DecodeThreadPayload(
            &decoder, version, opcode, is_64_bit, event_name, fields.get())) {
      // TODO(etienneb): Complete the decoding of these payload.
      LOG(WARNING) << "Error while decoding Thread payload.";
      return false;
    }
  } else if (provider_id == kProcessProviderId) {
    if (!DecodeProcessPayload(
            &decoder, version, opcode, is_64_bit, event_name, fields.get())) {
      LOG(WARNING) << "Error while decoding Process payload.";
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
