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
#include "base/scoped_ptr.h"
#include "event/utils.h"
#include "event/value.h"
#include "gtest/gtest.h"

namespace parser {
namespace etw {

namespace {

using event::ArrayValue;
using event::CharValue;
using event::UCharValue;
using event::UShortValue;
using event::IntValue;
using event::UIntValue;
using event::LongValue;
using event::ULongValue;
using event::StringValue;
using event::StructValue;
using event::Value;
using event::WStringValue;

// ETW payload version.
const unsigned char kVersion1 = 1;
const unsigned char kVersion2 = 2;
const unsigned char kVersion3 = 3;
const unsigned char kVersion4 = 4;
const unsigned char kVersion5 = 5;

// Flag indicating to decode 64-bit integer.
bool k64bit = true;

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

// Constants for Process events.
const char kProcessProviderId[] = "3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C";
const unsigned char kProcessStartOpcode = 1;
const unsigned char kProcessEndOpcode = 2;
const unsigned char kProcessDCStartOpcode = 3;
const unsigned char kProcessDCEndOpcode = 4;
const unsigned char kProcessTerminateOpcode = 11;
const unsigned char kProcessPerfCtrOpcode = 32;
const unsigned char kProcessPerfCtrRundownOpcode = 33;
const unsigned char kProcessDefunctOpcode = 39;

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

const unsigned char kImageUnloadPayloadV2[] = {
    0x00, 0x00, 0x78, 0xF7, 0xFE, 0x07, 0x00, 0x00,
    0x00, 0x20, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x44, 0x17, 0x00, 0x00, 0xA1, 0x77, 0x0E, 0x00,
    0xFE, 0xDE, 0x5B, 0x4A, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x78, 0xF7, 0xFE, 0x07, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5C, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
    0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00,
    0x5C, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00,
    0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x33, 0x00,
    0x32, 0x00, 0x5C, 0x00, 0x77, 0x00, 0x62, 0x00,
    0x65, 0x00, 0x6D, 0x00, 0x5C, 0x00, 0x66, 0x00,
    0x61, 0x00, 0x73, 0x00, 0x74, 0x00, 0x70, 0x00,
    0x72, 0x00, 0x6F, 0x00, 0x78, 0x00, 0x2E, 0x00,
    0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x00, 0x00
    };

const unsigned char kImageUnloadPayloadV3[] = {
    0x00, 0x00, 0xF3, 0xA3, 0xFC, 0x7F, 0x00, 0x00,
    0x00, 0x40, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xF8, 0x07, 0x00, 0x00, 0x7B, 0x2E, 0x0E, 0x00,
    0xB8, 0xDE, 0x15, 0x52, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xF3, 0xA3, 0xFC, 0x7F, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5C, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
    0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00,
    0x5C, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00,
    0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x33, 0x00,
    0x32, 0x00, 0x5C, 0x00, 0x77, 0x00, 0x62, 0x00,
    0x65, 0x00, 0x6D, 0x00, 0x5C, 0x00, 0x66, 0x00,
    0x61, 0x00, 0x73, 0x00, 0x74, 0x00, 0x70, 0x00,
    0x72, 0x00, 0x6F, 0x00, 0x78, 0x00, 0x2E, 0x00,
    0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x00, 0x00
    };

const unsigned char kImageDCStartPayloadV2[] = {
    0x00, 0x80, 0xE0, 0x02, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x60, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x45, 0xA2, 0x55, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5C, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00,
    0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x52, 0x00,
    0x6F, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x5C, 0x00,
    0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00,
    0x65, 0x00, 0x6D, 0x00, 0x33, 0x00, 0x32, 0x00,
    0x5C, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x6F, 0x00,
    0x73, 0x00, 0x6B, 0x00, 0x72, 0x00, 0x6E, 0x00,
    0x6C, 0x00, 0x2E, 0x00, 0x65, 0x00, 0x78, 0x00,
    0x65, 0x00, 0x00, 0x00 };

const unsigned char kImageDCStartPayloadV3[] = {
    0x00, 0x00, 0x45, 0x77, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x80, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x18, 0xBF, 0x16, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x45, 0x77, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5C, 0x00, 0x44, 0x00, 0x65, 0x00, 0x76, 0x00,
    0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x5C, 0x00,
    0x48, 0x00, 0x61, 0x00, 0x72, 0x00, 0x64, 0x00,
    0x64, 0x00, 0x69, 0x00, 0x73, 0x00, 0x6B, 0x00,
    0x56, 0x00, 0x6F, 0x00, 0x6C, 0x00, 0x75, 0x00,
    0x6D, 0x00, 0x65, 0x00, 0x34, 0x00, 0x5C, 0x00,
    0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00,
    0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x5C, 0x00,
    0x53, 0x00, 0x79, 0x00, 0x73, 0x00, 0x57, 0x00,
    0x4F, 0x00, 0x57, 0x00, 0x36, 0x00, 0x34, 0x00,
    0x5C, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x64, 0x00,
    0x6C, 0x00, 0x6C, 0x00, 0x2E, 0x00, 0x64, 0x00,
    0x6C, 0x00, 0x6C, 0x00, 0x00, 0x00 };

const unsigned char kImageDCEndPayloadV2[] = {
    0x00, 0x90, 0xE1, 0x02, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x50, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xB3, 0xCB, 0x54, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5C, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00,
    0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x52, 0x00,
    0x6F, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x5C, 0x00,
    0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00,
    0x65, 0x00, 0x6D, 0x00, 0x33, 0x00, 0x32, 0x00,
    0x5C, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x6F, 0x00,
    0x73, 0x00, 0x6B, 0x00, 0x72, 0x00, 0x6E, 0x00,
    0x6C, 0x00, 0x2E, 0x00, 0x65, 0x00, 0x78, 0x00,
    0x65, 0x00, 0x00, 0x00 };

const unsigned char kImageDCEndPayloadV3[] = {
    0x00, 0xF0, 0x86, 0x74, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x10, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xD6, 0x20, 0x71, 0x00,
    0x9C, 0x8D, 0x71, 0x52, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5C, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00,
    0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x52, 0x00,
    0x6F, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x5C, 0x00,
    0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00,
    0x65, 0x00, 0x6D, 0x00, 0x33, 0x00, 0x32, 0x00,
    0x5C, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x6F, 0x00,
    0x73, 0x00, 0x6B, 0x00, 0x72, 0x00, 0x6E, 0x00,
    0x6C, 0x00, 0x2E, 0x00, 0x65, 0x00, 0x78, 0x00,
    0x65, 0x00, 0x00, 0x00 };

const unsigned char kImageLoadPayloadV2[] = {
    0x00, 0x00, 0x40, 0x71, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xF4, 0x0E, 0x00, 0x00, 0x9A, 0xFE, 0x00, 0x00,
    0xE4, 0xC3, 0x5B, 0x4A, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x40, 0x71,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5C, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
    0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00,
    0x5C, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00,
    0x57, 0x00, 0x4F, 0x00, 0x57, 0x00, 0x36, 0x00,
    0x34, 0x00, 0x5C, 0x00, 0x77, 0x00, 0x73, 0x00,
    0x63, 0x00, 0x69, 0x00, 0x73, 0x00, 0x76, 0x00,
    0x69, 0x00, 0x66, 0x00, 0x2E, 0x00, 0x64, 0x00,
    0x6C, 0x00, 0x6C, 0x00, 0x00, 0x00 };

const unsigned char kImageLoadPayloadV3[] = {
    0x00, 0x00, 0x49, 0x3A, 0xF7, 0x7F, 0x00, 0x00,
    0x00, 0x90, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x8C, 0x0A, 0x00, 0x00, 0x31, 0x6E, 0x07, 0x00,
    0x9D, 0x9D, 0x10, 0x50, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x3A, 0xF7, 0x7F, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5C, 0x00, 0x44, 0x00, 0x65, 0x00, 0x76, 0x00,
    0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x5C, 0x00,
    0x48, 0x00, 0x61, 0x00, 0x72, 0x00, 0x64, 0x00,
    0x64, 0x00, 0x69, 0x00, 0x73, 0x00, 0x6B, 0x00,
    0x56, 0x00, 0x6F, 0x00, 0x6C, 0x00, 0x75, 0x00,
    0x6D, 0x00, 0x65, 0x00, 0x34, 0x00, 0x5C, 0x00,
    0x50, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x67, 0x00,
    0x72, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x20, 0x00,
    0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00,
    0x73, 0x00, 0x20, 0x00, 0x28, 0x00, 0x78, 0x00,
    0x38, 0x00, 0x36, 0x00, 0x29, 0x00, 0x5C, 0x00,
    0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00,
    0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00,
    0x4B, 0x00, 0x69, 0x00, 0x74, 0x00, 0x73, 0x00,
    0x5C, 0x00, 0x38, 0x00, 0x2E, 0x00, 0x30, 0x00,
    0x5C, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
    0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00,
    0x20, 0x00, 0x50, 0x00, 0x65, 0x00, 0x72, 0x00,
    0x66, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6D, 0x00,
    0x61, 0x00, 0x6E, 0x00, 0x63, 0x00, 0x65, 0x00,
    0x20, 0x00, 0x54, 0x00, 0x6F, 0x00, 0x6F, 0x00,
    0x6C, 0x00, 0x6B, 0x00, 0x69, 0x00, 0x74, 0x00,
    0x5C, 0x00, 0x78, 0x00, 0x70, 0x00, 0x65, 0x00,
    0x72, 0x00, 0x66, 0x00, 0x2E, 0x00, 0x65, 0x00,
    0x78, 0x00, 0x65, 0x00, 0x00, 0x00 };

const unsigned char kImageKernelBasePayloadV2[] = {
    0x00, 0x90, 0xE1, 0x02, 0x00, 0xF8, 0xFF, 0xFF
    };

const unsigned char kPerfInfoSampleProfPayloadV2[] = {
    0x4B, 0xAB, 0x8C, 0x74, 0x00, 0xF8, 0xFF, 0xFF,
    0x70, 0x1F, 0x00, 0x00, 0x01, 0x00, 0x40, 0x00
    };

const unsigned char kPerfInfoISRMSIPayloadV2[] = {
    0xEB, 0xED, 0x3A, 0xA8, 0x66, 0x04, 0x00, 0x00,
    0x20, 0x7E, 0x93, 0x00, 0x00, 0xF8, 0xFF, 0xFF,
    0x01, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

const unsigned char kPerfInfoSysClEnterPayloadV2[] = {
    0x24, 0x1D, 0x90, 0x74, 0x00, 0xF8, 0xFF, 0xFF
    };

const unsigned char kPerfInfoSysClExitPayloadV2[] = {
    0x00, 0x00, 0x00, 0x00 };

const unsigned char kPerfInfoISRPayloadV2[] = {
    0xAC, 0x4D, 0x42, 0xA8, 0x66, 0x04, 0x00, 0x00,
    0xC0, 0x15, 0xF9, 0x02, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x81, 0x00, 0x00 };

const unsigned char kPerfInfoDPCPayloadV2[] = {
    0xCD, 0xEC, 0x3A, 0xA8, 0x66, 0x04, 0x00, 0x00,
    0xE4, 0xBC, 0x96, 0x74, 0x00, 0xF8, 0xFF, 0xFF
    };

const unsigned char kPerfInfoTimerDPCPayloadV2[] = {
    0x75, 0x24, 0x3C, 0xA8, 0x66, 0x04, 0x00, 0x00,
    0xD8, 0x04, 0x11, 0x03, 0x00, 0xF8, 0xFF, 0xFF
    };

const unsigned char kPerfInfoCollectionStartSecondPayloadV3[] = {
    0x00, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00,
    0x10, 0x27, 0x00, 0x00, 0x54, 0x00, 0x69, 0x00,
    0x6D, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00
    };

const unsigned char kPerfInfoCollectionStartPayloadV3[] = {
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

const unsigned char kPerfInfoCollectionEndPayloadV3[] = {
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

const unsigned char kPerfInfoCollectionEndSecondPayloadV3[] = {
    0x00, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00,
    0x10, 0x27, 0x00, 0x00, 0x54, 0x00, 0x69, 0x00,
    0x6D, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00
    };

const unsigned char kProcessStartPayloadV3[] = {
    0x60, 0x80, 0x62, 0x0F, 0x80, 0xFA, 0xFF, 0xFF,
    0x00, 0x1A, 0x00, 0x00, 0xA0, 0x1C, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00,
    0x00, 0xF0, 0x43, 0x1D, 0x01, 0x00, 0x00, 0x00,
    0x30, 0x56, 0x53, 0x15, 0xA0, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0xA0, 0xF8, 0xFF, 0xFF,
    0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x15, 0x00, 0x00, 0x00, 0x02, 0x03, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x00, 0x00, 0x78, 0x70, 0x65, 0x72,
    0x66, 0x2E, 0x65, 0x78, 0x65, 0x00, 0x78, 0x00,
    0x70, 0x00, 0x65, 0x00, 0x72, 0x00, 0x66, 0x00,
    0x20, 0x00, 0x20, 0x00, 0x2D, 0x00, 0x64, 0x00,
    0x20, 0x00, 0x6F, 0x00, 0x75, 0x00, 0x74, 0x00,
    0x2E, 0x00, 0x65, 0x00, 0x74, 0x00, 0x6C, 0x00,
    0x00, 0x00 };

const unsigned char kProcessStartPayloadV4[] = {
    0x80, 0x40, 0xFC, 0x1A, 0x00, 0xE0, 0xFF, 0xFF,
    0x8C, 0x0A, 0x00, 0x00, 0x08, 0x17, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00,
    0x00, 0xB0, 0xA2, 0xA3, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x90, 0xF0, 0x57, 0x04,
    0x00, 0xC0, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x06, 0xE9, 0x03, 0x00, 0x00,
    0x78, 0x70, 0x65, 0x72, 0x66, 0x2E, 0x65, 0x78,
    0x65, 0x00, 0x78, 0x00, 0x70, 0x00, 0x65, 0x00,
    0x72, 0x00, 0x66, 0x00, 0x20, 0x00, 0x20, 0x00,
    0x2D, 0x00, 0x73, 0x00, 0x74, 0x00, 0x6F, 0x00,
    0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

const unsigned char kProcessEndPayloadV3[] = {
    0x60, 0x80, 0x62, 0x0F, 0x80, 0xFA, 0xFF, 0xFF,
    0x2C, 0x20, 0x00, 0x00, 0xA0, 0x1C, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xA0, 0x3F, 0xA4, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xB1, 0x2B, 0x11, 0xA0, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xF8, 0xFF, 0xFF,
    0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x15, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x03, 0x00, 0x00, 0x78, 0x70, 0x65, 0x72,
    0x66, 0x2E, 0x65, 0x78, 0x65, 0x00, 0x78, 0x00,
    0x70, 0x00, 0x65, 0x00, 0x72, 0x00, 0x66, 0x00,
    0x20, 0x00, 0x20, 0x00, 0x2D, 0x00, 0x6F, 0x00,
    0x6E, 0x00, 0x20, 0x00, 0x50, 0x00, 0x52, 0x00,
    0x4F, 0x00, 0x43, 0x00, 0x5F, 0x00, 0x54, 0x00,
    0x48, 0x00, 0x52, 0x00, 0x45, 0x00, 0x41, 0x00,
    0x44, 0x00, 0x2B, 0x00, 0x4C, 0x00, 0x4F, 0x00,
    0x41, 0x00, 0x44, 0x00, 0x45, 0x00, 0x52, 0x00,
    0x2B, 0x00, 0x43, 0x00, 0x53, 0x00, 0x57, 0x00,
    0x49, 0x00, 0x54, 0x00, 0x43, 0x00, 0x48, 0x00,
    0x20, 0x00, 0x2D, 0x00, 0x73, 0x00, 0x74, 0x00,
    0x61, 0x00, 0x63, 0x00, 0x6B, 0x00, 0x77, 0x00,
    0x61, 0x00, 0x6C, 0x00, 0x6B, 0x00, 0x20, 0x00,
    0x49, 0x00, 0x6D, 0x00, 0x61, 0x00, 0x67, 0x00,
    0x65, 0x00, 0x4C, 0x00, 0x6F, 0x00, 0x61, 0x00,
    0x64, 0x00, 0x2B, 0x00, 0x49, 0x00, 0x6D, 0x00,
    0x61, 0x00, 0x67, 0x00, 0x65, 0x00, 0x55, 0x00,
    0x6E, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x61, 0x00,
    0x64, 0x00, 0x00, 0x00 };

const unsigned char kProcessEndPayloadV4[] = {
    0x80, 0x40, 0xFC, 0x1A, 0x00, 0xE0, 0xFF, 0xFF,
    0xF8, 0x07, 0x00, 0x00, 0x08, 0x17, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x80, 0xC0, 0xBD, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xA0, 0xC8, 0xFC, 0x15,
    0x00, 0xC0, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
    0x12, 0x13, 0x0F, 0x12, 0x13, 0x42, 0x24, 0x33,
    0xCC, 0xCA, 0xCC, 0xCB, 0xBA, 0xBE, 0x00, 0x00,
    0x78, 0x70, 0x65, 0x72, 0x66, 0x2E, 0x65, 0x78,
    0x65, 0x00, 0x78, 0x00, 0x70, 0x00, 0x65, 0x00,
    0x72, 0x00, 0x66, 0x00, 0x20, 0x00, 0x20, 0x00,
    0x2D, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x20, 0x00,
    0x50, 0x00, 0x52, 0x00, 0x4F, 0x00, 0x43, 0x00,
    0x5F, 0x00, 0x54, 0x00, 0x48, 0x00, 0x52, 0x00,
    0x45, 0x00, 0x41, 0x00, 0x44, 0x00, 0x2B, 0x00,
    0x4C, 0x00, 0x4F, 0x00, 0x41, 0x00, 0x44, 0x00,
    0x45, 0x00, 0x52, 0x00, 0x2B, 0x00, 0x50, 0x00,
    0x52, 0x00, 0x4F, 0x00, 0x46, 0x00, 0x49, 0x00,
    0x4C, 0x00, 0x45, 0x00, 0x2B, 0x00, 0x43, 0x00,
    0x53, 0x00, 0x57, 0x00, 0x49, 0x00, 0x54, 0x00,
    0x43, 0x00, 0x48, 0x00, 0x2B, 0x00, 0x44, 0x00,
    0x49, 0x00, 0x53, 0x00, 0x50, 0x00, 0x41, 0x00,
    0x54, 0x00, 0x43, 0x00, 0x48, 0x00, 0x45, 0x00,
    0x52, 0x00, 0x2B, 0x00, 0x44, 0x00, 0x50, 0x00,
    0x43, 0x00, 0x2B, 0x00, 0x49, 0x00, 0x4E, 0x00,
    0x54, 0x00, 0x45, 0x00, 0x52, 0x00, 0x52, 0x00,
    0x55, 0x00, 0x50, 0x00, 0x54, 0x00, 0x2B, 0x00,
    0x53, 0x00, 0x59, 0x00, 0x53, 0x00, 0x43, 0x00,
    0x41, 0x00, 0x4C, 0x00, 0x4C, 0x00, 0x2B, 0x00,
    0x50, 0x00, 0x52, 0x00, 0x49, 0x00, 0x4F, 0x00,
    0x52, 0x00, 0x49, 0x00, 0x54, 0x00, 0x59, 0x00,
    0x2B, 0x00, 0x53, 0x00, 0x50, 0x00, 0x49, 0x00,
    0x4E, 0x00, 0x4C, 0x00, 0x4F, 0x00, 0x43, 0x00,
    0x4B, 0x00, 0x2B, 0x00, 0x50, 0x00, 0x45, 0x00,
    0x52, 0x00, 0x46, 0x00, 0x5F, 0x00, 0x43, 0x00,
    0x4F, 0x00, 0x55, 0x00, 0x4E, 0x00, 0x54, 0x00,
    0x45, 0x00, 0x52, 0x00, 0x2B, 0x00, 0x44, 0x00,
    0x49, 0x00, 0x53, 0x00, 0x4B, 0x00, 0x5F, 0x00,
    0x49, 0x00, 0x4F, 0x00, 0x2B, 0x00, 0x44, 0x00,
    0x49, 0x00, 0x53, 0x00, 0x4B, 0x00, 0x5F, 0x00,
    0x49, 0x00, 0x4F, 0x00, 0x5F, 0x00, 0x49, 0x00,
    0x4E, 0x00, 0x49, 0x00, 0x54, 0x00, 0x2B, 0x00,
    0x46, 0x00, 0x49, 0x00, 0x4C, 0x00, 0x45, 0x00,
    0x5F, 0x00, 0x49, 0x00, 0x4F, 0x00, 0x2B, 0x00,
    0x46, 0x00, 0x49, 0x00, 0x4C, 0x00, 0x45, 0x00,
    0x5F, 0x00, 0x49, 0x00, 0x4F, 0x00, 0x5F, 0x00,
    0x49, 0x00, 0x4E, 0x00, 0x49, 0x00, 0x54, 0x00,
    0x2B, 0x00, 0x48, 0x00, 0x41, 0x00, 0x52, 0x00,
    0x44, 0x00, 0x5F, 0x00, 0x46, 0x00, 0x41, 0x00,
    0x55, 0x00, 0x4C, 0x00, 0x54, 0x00, 0x53, 0x00,
    0x2B, 0x00, 0x46, 0x00, 0x49, 0x00, 0x4C, 0x00,
    0x45, 0x00, 0x4E, 0x00, 0x41, 0x00, 0x4D, 0x00,
    0x45, 0x00, 0x2B, 0x00, 0x52, 0x00, 0x45, 0x00,
    0x47, 0x00, 0x49, 0x00, 0x53, 0x00, 0x54, 0x00,
    0x52, 0x00, 0x59, 0x00, 0x2B, 0x00, 0x44, 0x00,
    0x52, 0x00, 0x49, 0x00, 0x56, 0x00, 0x45, 0x00,
    0x52, 0x00, 0x53, 0x00, 0x2B, 0x00, 0x50, 0x00,
    0x4F, 0x00, 0x57, 0x00, 0x45, 0x00, 0x52, 0x00,
    0x2B, 0x00, 0x43, 0x00, 0x43, 0x00, 0x2B, 0x00,
    0x4E, 0x00, 0x45, 0x00, 0x54, 0x00, 0x57, 0x00,
    0x4F, 0x00, 0x52, 0x00, 0x4B, 0x00, 0x54, 0x00,
    0x52, 0x00, 0x41, 0x00, 0x43, 0x00, 0x45, 0x00,
    0x2B, 0x00, 0x56, 0x00, 0x49, 0x00, 0x52, 0x00,
    0x54, 0x00, 0x5F, 0x00, 0x41, 0x00, 0x4C, 0x00,
    0x4C, 0x00, 0x4F, 0x00, 0x43, 0x00, 0x2B, 0x00,
    0x4D, 0x00, 0x45, 0x00, 0x4D, 0x00, 0x49, 0x00,
    0x4E, 0x00, 0x46, 0x00, 0x4F, 0x00, 0x2B, 0x00,
    0x4D, 0x00, 0x45, 0x00, 0x4D, 0x00, 0x4F, 0x00,
    0x52, 0x00, 0x59, 0x00, 0x2B, 0x00, 0x54, 0x00,
    0x49, 0x00, 0x4D, 0x00, 0x45, 0x00, 0x52, 0x00,
    0x20, 0x00, 0x2D, 0x00, 0x66, 0x00, 0x20, 0x00,
    0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x6B, 0x00,
    0x65, 0x00, 0x72, 0x00, 0x6E, 0x00, 0x65, 0x00,
    0x6C, 0x00, 0x2E, 0x00, 0x65, 0x00, 0x74, 0x00,
    0x6C, 0x00, 0x20, 0x00, 0x2D, 0x00, 0x42, 0x00,
    0x75, 0x00, 0x66, 0x00, 0x66, 0x00, 0x65, 0x00,
    0x72, 0x00, 0x53, 0x00, 0x69, 0x00, 0x7A, 0x00,
    0x65, 0x00, 0x20, 0x00, 0x34, 0x00, 0x30, 0x00,
    0x39, 0x00, 0x36, 0x00, 0x20, 0x00, 0x2D, 0x00,
    0x4D, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x42, 0x00,
    0x75, 0x00, 0x66, 0x00, 0x66, 0x00, 0x65, 0x00,
    0x72, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32, 0x00,
    0x35, 0x00, 0x36, 0x00, 0x20, 0x00, 0x2D, 0x00,
    0x4D, 0x00, 0x61, 0x00, 0x78, 0x00, 0x42, 0x00,
    0x75, 0x00, 0x66, 0x00, 0x66, 0x00, 0x65, 0x00,
    0x72, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32, 0x00,
    0x35, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00 };

const unsigned char kProcessDCStartPayloadV3[] = {
    0x80, 0x81, 0x01, 0x03, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x70, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x56, 0x62, 0x2A, 0xA0, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xFF, 0xFF,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x10, 0x00, 0x00, 0x00, 0x49, 0x64, 0x6C, 0x65,
    0x00, 0x00, 0x00 };

const unsigned char kProcessDCStartPayloadV4[] = {
    0xC0, 0x53, 0xBB, 0x74, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x80, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xC0, 0xBB, 0xE7, 0x2D,
    0x00, 0xC0, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x05, 0x10, 0x00, 0x00, 0x00,
    0x49, 0x64, 0x6C, 0x65, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00 };

const unsigned char kProcessDCEndPayloadV3[] = {
    0x80, 0x81, 0x01, 0x03, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x70, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xCD, 0x7E, 0x05, 0xA0, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x12, 0x00, 0x00, 0x00, 0x49, 0x64, 0x6C, 0x65,
    0x00, 0x00, 0x00 };

const unsigned char kProcessDCEndPayloadV4[] = {
    0xC0, 0x53, 0xBB, 0x74, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x80, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xF0, 0x85, 0x86, 0x16,
    0x00, 0xC0, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x74, 0x00, 0x61, 0x00, 0x01, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x05, 0x10, 0x00, 0x00, 0x00,
    0x49, 0x64, 0x6C, 0x65, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00 };

const unsigned char kProcessTerminatePayloadV2[] = {
    0xF8, 0x07, 0x00, 0x00 };

const unsigned char kProcessPerfCtrPayloadV2[] = {
    0xF8, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x30, 0xAD, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xC0, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x70, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xE0, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

const unsigned char kProcessPerfCtrRundownPayloadV2[] = {
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x63, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

const unsigned char kProcessDefunctPayloadV3[] = {
    0x60, 0xE0, 0xA6, 0x13, 0x80, 0xFA, 0xFF, 0xFF,
    0x64, 0x0E, 0x00, 0x00, 0x94, 0x08, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x40, 0xEF, 0x97, 0x01, 0x00, 0x00, 0x00,
    0xE0, 0x87, 0x8B, 0x04, 0xA0, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x10, 0x00, 0x00, 0x00, 0x63, 0x6D, 0x64, 0x2E,
    0x65, 0x78, 0x65, 0x00, 0x00, 0x00 };

const unsigned char kProcessDefunctPayloadV5[] = {
    0xC0, 0xC5, 0xF2, 0x06, 0x00, 0xE0, 0xFF, 0xFF,
    0x48, 0x19, 0x00, 0x00, 0x10, 0x08, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x60, 0xCB, 0x4F, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xF0, 0xE5, 0x3B, 0x03,
    0x00, 0xC0, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0C, 0x00, 0x01, 0x05, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0x03, 0x00, 0x00,
    0x63, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x2E, 0x65,
    0x78, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x8D, 0x49, 0xA2, 0xF9, 0xEC, 0xFA, 0xCE,
    0x01 };

const unsigned char kThreadStartPayloadV3[] = {
    0x78, 0x21, 0x00, 0x00, 0x94, 0x14, 0x00, 0x00,
    0x00, 0x30, 0x0E, 0x27, 0x00, 0xD0, 0xFF, 0xFF,
    0x00, 0xD0, 0x0D, 0x27, 0x00, 0xD0, 0xFF, 0xFF,
    0x30, 0xFD, 0x0B, 0x06, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x80, 0x0B, 0x06, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2C, 0xFD, 0x58, 0x5C, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xC0, 0x12, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x05, 0x02, 0x00
    };

const unsigned char kThreadEndPayloadV3[] = {
    0xF8, 0x07, 0x00, 0x00, 0xD8, 0x0C, 0x00, 0x00,
    0x00, 0x70, 0x8C, 0x29, 0x00, 0xD0, 0xFF, 0xFF,
    0x00, 0x10, 0x8C, 0x29, 0x00, 0xD0, 0xFF, 0xFF,
    0x00, 0x00, 0x1C, 0x42, 0xD2, 0x00, 0x00, 0x00,
    0x00, 0xE0, 0x1B, 0x42, 0xD2, 0x00, 0x00, 0x00,
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x85, 0x72, 0xAE, 0xFC, 0x7F, 0x00, 0x00,
    0x00, 0x80, 0xB3, 0x39, 0xF7, 0x7F, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x05, 0x02, 0x00
    };

const unsigned char kThreadDCStartPayloadV3[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x70, 0x48, 0x76, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x10, 0x48, 0x76, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x07, 0x9C, 0x74, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00
    };

const unsigned char kThreadDCEndPayload[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xD0, 0xB9, 0x00, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x70, 0xB9, 0x00, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x70, 0x68, 0xE8, 0x02, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

const unsigned char kThreadDCEndPayloadV3[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x70, 0x48, 0x76, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x10, 0x48, 0x76, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x07, 0x9C, 0x74, 0x00, 0xF8, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00
    };

const unsigned char kThreadCSwitchPayloadV2[] = {
    0xCC, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x04,
    0x01, 0x00, 0x00, 0x00, 0x87, 0x6D, 0x88, 0x34
    };

const unsigned char kThreadSpinLockPayloadV2[] = {
    0x60, 0x01, 0xB2, 0x02, 0x00, 0xE0, 0xFF, 0xFF,
    0x10, 0x04, 0x9E, 0x74, 0x00, 0xF8, 0xFF, 0xFF,
    0x9E, 0x8B, 0x93, 0x3C, 0xAC, 0x79, 0x07, 0x00,
    0x27, 0x8E, 0x93, 0x3C, 0xAC, 0x79, 0x07, 0x00,
    0x91, 0x06, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

const unsigned char kThreadSetPriorityPayloadV3[] = {
    0x20, 0x02, 0x00, 0x00, 0x0F, 0x10, 0x00, 0x00
    };

const unsigned char kThreadSetBasePriorityPayloadV3[] = {
    0xF0, 0x1A, 0x00, 0x00, 0x04, 0x07, 0x07, 0x00
    };

const unsigned char kThreadReadyThreadPayloadV2[] = {
    0xCC, 0x08, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00
    };

const unsigned char kThreadSetPagePriorityPayloadV3[] = {
    0x6C, 0x1A, 0x00, 0x00, 0x05, 0x06, 0x00, 0x00
    };

const unsigned char kThreadSetIoPriorityPayloadV3[] = {
    0xBC, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
    };

const unsigned char kThreadAutoBoostSetFloorPayloadV2[] = {
    0x78, 0x51, 0x15, 0x01, 0x00, 0xE0, 0xFF, 0xFF,
    0xF0, 0x1A, 0x00, 0x00, 0x0B, 0x07, 0x20, 0x00
    };

const unsigned char kThreadAutoBoostClearFloorPayloadV2[] = {
    0x78, 0x51, 0x15, 0x01, 0x00, 0xE0, 0xFF, 0xFF,
    0xF0, 0x1A, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00
    };

const unsigned char kThreadAutoBoostEntryExhaustionPayloadV2[] = {
    0xF0, 0x34, 0xA4, 0x08, 0x00, 0xE0, 0xFF, 0xFF,
    0xBC, 0x0B, 0x00, 0x00, 0x00, 0xF8, 0xFF, 0xFF
    };

scoped_ptr<Value> MakeSID64(uint64 psid,
                            uint32 attributes,
                            const unsigned char bytes[],
                            size_t length) {
  scoped_ptr<StructValue> sid_struct(new StructValue());
  sid_struct->AddField<ULongValue>("PSid", psid);
  sid_struct->AddField<UIntValue>("Attributes", attributes);

  scoped_ptr<ArrayValue> sid_array(new ArrayValue());
  sid_array->AppendAll<UCharValue>(bytes, length);
  sid_struct->AddField("Sid", sid_array.PassAs<Value>());

  return sid_struct.PassAs<Value>();
}

}  // namespace

TEST(EtwRawDecoderTest, ImageUnloadV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kImageProviderId,
          kVersion2, kImageUnloadOpcode, k64bit,
          reinterpret_cast<const char*>(&kImageUnloadPayloadV2[0]),
          sizeof(kImageUnloadPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("BaseAddress", 0x7FEF7780000ULL);
  expected->AddField<ULongValue>("ModuleSize", 0xE2000ULL);
  expected->AddField<UIntValue>("ProcessId", 5956U);
  expected->AddField<UIntValue>("ImageCheckSum", 948129U);
  expected->AddField<UIntValue>("TimeDateStamp", 1247534846U);
  expected->AddField<UIntValue>("Reserved0", 0U);
  expected->AddField<ULongValue>("DefaultBase", 0x7FEF7780000ULL);
  expected->AddField<UIntValue>("Reserved1", 0U);
  expected->AddField<UIntValue>("Reserved2", 0U);
  expected->AddField<UIntValue>("Reserved3", 0U);
  expected->AddField<UIntValue>("Reserved4", 0U);
  std::wstring filename = L"\\Windows\\System32\\wbem\\fastprox.dll";
  expected->AddField<WStringValue>("ImageFileName", filename);

  EXPECT_STREQ("Image_Unload", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ImageUnloadV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kImageProviderId,
          kVersion3, kImageUnloadOpcode, k64bit,
          reinterpret_cast<const char*>(&kImageUnloadPayloadV3[0]),
          sizeof(kImageUnloadPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("BaseAddress", 140723059097600ULL);
  expected->AddField<ULongValue>("ModuleSize", 933888ULL);
  expected->AddField<UIntValue>("ProcessId", 2040U);
  expected->AddField<UIntValue>("ImageCheckSum", 929403U);
  expected->AddField<UIntValue>("TimeDateStamp", 1377164984U);
  expected->AddField<UCharValue>("SignatureLevel", 0);
  expected->AddField<UCharValue>("SignatureType", 0);
  expected->AddField<UShortValue>("Reserved0", 0U);
  expected->AddField<ULongValue>("DefaultBase", 140723059097600ULL);
  expected->AddField<UIntValue>("Reserved1", 0U);
  expected->AddField<UIntValue>("Reserved2", 0U);
  expected->AddField<UIntValue>("Reserved3", 0U);
  expected->AddField<UIntValue>("Reserved4", 0U);
  std::wstring filename = L"\\Windows\\System32\\wbem\\fastprox.dll";
  expected->AddField<WStringValue>("ImageFileName", filename);

  EXPECT_STREQ("Image_Unload", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ImageDCStartV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kImageProviderId,
          kVersion2, kImageDCStartOpcode, k64bit,
          reinterpret_cast<const char*>(&kImageDCStartPayloadV2[0]),
          sizeof(kImageDCStartPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("BaseAddress", 18446735277664796672ULL);
  expected->AddField<ULongValue>("ModuleSize", 0x5E6000ULL);
  expected->AddField<UIntValue>("ProcessId", 0U);
  expected->AddField<UIntValue>("ImageCheckSum", 5612101U);
  expected->AddField<UIntValue>("TimeDateStamp", 0U);
  expected->AddField<UIntValue>("Reserved0", 0U);
  expected->AddField<ULongValue>("DefaultBase", 0U);
  expected->AddField<UIntValue>("Reserved1", 0U);
  expected->AddField<UIntValue>("Reserved2", 0U);
  expected->AddField<UIntValue>("Reserved3", 0U);
  expected->AddField<UIntValue>("Reserved4", 0U);
  std::wstring filename = L"\\SystemRoot\\system32\\ntoskrnl.exe";
  expected->AddField<WStringValue>("ImageFileName", filename);

  EXPECT_STREQ("Image_DCStart", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ImageDCStartV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kImageProviderId,
          kVersion3, kImageDCStartOpcode, k64bit,
          reinterpret_cast<const char*>(&kImageDCStartPayloadV3[0]),
          sizeof(kImageDCStartPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("BaseAddress", 2001010688ULL);
  expected->AddField<ULongValue>("ModuleSize", 1474560ULL);
  expected->AddField<UIntValue>("ProcessId", 4U);
  expected->AddField<UIntValue>("ImageCheckSum", 1490712);
  expected->AddField<UIntValue>("TimeDateStamp", 0U);
  expected->AddField<UCharValue>("SignatureLevel", 12);
  expected->AddField<UCharValue>("SignatureType", 1);
  expected->AddField<UShortValue>("Reserved0", 0U);
  expected->AddField<ULongValue>("DefaultBase", 2001010688ULL);
  expected->AddField<UIntValue>("Reserved1", 0U);
  expected->AddField<UIntValue>("Reserved2", 0U);
  expected->AddField<UIntValue>("Reserved3", 0U);
  expected->AddField<UIntValue>("Reserved4", 0U);
  std::wstring filename =
      L"\\Device\\HarddiskVolume4\\Windows\\SysWOW64\\ntdll.dll";
  expected->AddField<WStringValue>("ImageFileName", filename);

  EXPECT_STREQ("Image_DCStart", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ImageDCEndV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kImageProviderId,
          kVersion2, kImageDCEndOpcode, true,
          reinterpret_cast<const char*>(&kImageDCEndPayloadV2[0]),
          sizeof(kImageDCEndPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("BaseAddress", 18446735277664866304ULL);
  expected->AddField<ULongValue>("ModuleSize", 0x5E5000ULL);
  expected->AddField<UIntValue>("ProcessId", 0U);
  expected->AddField<UIntValue>("ImageCheckSum", 5557171U);
  expected->AddField<UIntValue>("TimeDateStamp", 0U);
  expected->AddField<UIntValue>("Reserved0", 0U);
  expected->AddField<ULongValue>("DefaultBase", 0U);
  expected->AddField<UIntValue>("Reserved1", 0U);
  expected->AddField<UIntValue>("Reserved2", 0U);
  expected->AddField<UIntValue>("Reserved3", 0U);
  expected->AddField<UIntValue>("Reserved4", 0U);
  std::wstring filename = L"\\SystemRoot\\system32\\ntoskrnl.exe";
  expected->AddField<WStringValue>("ImageFileName", filename);

  EXPECT_STREQ("Image_DCEnd", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ImageDCEndV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kImageProviderId,
          kVersion3, kImageDCEndOpcode, true,
          reinterpret_cast<const char*>(&kImageDCEndPayloadV3[0]),
          sizeof(kImageDCEndPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("BaseAddress", 18446735279571529728ULL);
  expected->AddField<ULongValue>("ModuleSize", 7868416ULL);
  expected->AddField<UIntValue>("ProcessId", 0U);
  expected->AddField<UIntValue>("ImageCheckSum", 7413974U);
  expected->AddField<UIntValue>("TimeDateStamp", 1383173532U);
  expected->AddField<UCharValue>("SignatureLevel", 0);
  expected->AddField<UCharValue>("SignatureType", 1);
  expected->AddField<UShortValue>("Reserved0", 0U);
  expected->AddField<ULongValue>("DefaultBase", 0U);
  expected->AddField<UIntValue>("Reserved1", 0U);
  expected->AddField<UIntValue>("Reserved2", 0U);
  expected->AddField<UIntValue>("Reserved3", 0U);
  expected->AddField<UIntValue>("Reserved4", 0U);
  std::wstring filename = L"\\SystemRoot\\system32\\ntoskrnl.exe";
  expected->AddField<WStringValue>("ImageFileName", filename);

  EXPECT_STREQ("Image_DCEnd", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ImageLoadV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kImageProviderId,
          kVersion2, kImageLoadOpcode, k64bit,
          reinterpret_cast<const char*>(&kImageLoadPayloadV2[0]),
          sizeof(kImageLoadPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("BaseAddress", 0x71400000ULL);
  expected->AddField<ULongValue>("ModuleSize", 0x8000ULL);
  expected->AddField<UIntValue>("ProcessId", 3828U);
  expected->AddField<UIntValue>("ImageCheckSum", 65178U);
  expected->AddField<UIntValue>("TimeDateStamp", 1247527908U);
  expected->AddField<UIntValue>("Reserved0", 0U);
  expected->AddField<ULongValue>("DefaultBase", 0x7140000000005000ULL);
  expected->AddField<UIntValue>("Reserved1", 0U);
  expected->AddField<UIntValue>("Reserved2", 0U);
  expected->AddField<UIntValue>("Reserved3", 0U);
  expected->AddField<UIntValue>("Reserved4", 0U);
  std::wstring filename = L"\\Windows\\SysWOW64\\wscisvif.dll";
  expected->AddField<WStringValue>("ImageFileName", filename);

  EXPECT_STREQ("Image_Load", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ImageLoadV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kImageProviderId,
          kVersion3, kImageLoadOpcode, k64bit,
          reinterpret_cast<const char*>(&kImageLoadPayloadV3[0]),
          sizeof(kImageLoadPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("BaseAddress", 140699811512320ULL);
  expected->AddField<ULongValue>("ModuleSize", 430080U);
  expected->AddField<UIntValue>("ProcessId", 2700U);
  expected->AddField<UIntValue>("ImageCheckSum", 486961U);
  expected->AddField<UIntValue>("TimeDateStamp", 1343266205U);
  expected->AddField<UCharValue>("SignatureLevel", 0);
  expected->AddField<UCharValue>("SignatureType", 0);
  expected->AddField<UShortValue>("Reserved0", 0U);
  expected->AddField<ULongValue>("DefaultBase", 140699811512320ULL);
  expected->AddField<UIntValue>("Reserved1", 0U);
  expected->AddField<UIntValue>("Reserved2", 0U);
  expected->AddField<UIntValue>("Reserved3", 0U);
  expected->AddField<UIntValue>("Reserved4", 0U);
  std::wstring filename = L"\\Device\\HarddiskVolume4\\Program Files (x86)\\"
      L"Windows Kits\\8.0\\Windows Performance Toolkit\\xperf.exe";
  expected->AddField<WStringValue>("ImageFileName", filename);

  EXPECT_STREQ("Image_Load", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ImageKernelBaseV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kImageProviderId,
          kVersion2, kImageKernelBaseOpcode, k64bit,
          reinterpret_cast<const char*>(&kImageKernelBasePayloadV2[0]),
          sizeof(kImageKernelBasePayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("BaseAddress", 18446735277664866304ULL);

  EXPECT_STREQ("Image_KernelBase", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessStartV3) {
  std::string name;
  scoped_ptr<Value> fields;

  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion3, kProcessStartOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessStartPayloadV3[0]),
          sizeof(kProcessStartPayloadV3),
          &name, &fields));

  const unsigned char sid[] = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 2, 3,
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0 };

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("UniqueProcessKey", 18446738026653712480ULL);
  expected->AddField<UIntValue>("ProcessId", 6656);
  expected->AddField<UIntValue>("ParentId", 7328);
  expected->AddField<UIntValue>("SessionId", 1);
  expected->AddField<IntValue>("ExitStatus", 259);
  expected->AddField<ULongValue>("DirectoryTableBase", 4785958912);
  expected->AddField("UserSID", MakeSID64(18446735965169079856ULL,
                                          0,
                                          &sid[0],
                                          sizeof(sid)).Pass());
  std::string filename = "xperf.exe";
  expected->AddField<StringValue>("ImageFileName", filename);
  std::wstring commandline = L"xperf  -d out.etl";
  expected->AddField<WStringValue>("CommandLine", commandline);

  EXPECT_STREQ("Process_Start", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessStartV4) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion4, kProcessStartOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessStartPayloadV4[0]),
          sizeof(kProcessStartPayloadV4),
          &name, &fields));

  const unsigned char sid[] = {
      0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
      0x15, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
      0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x06,
      0xE9, 0x03, 0x00, 0x00 };

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("UniqueProcessKey", 18446708889790201984ULL);
  expected->AddField<UIntValue>("ProcessId", 2700U);
  expected->AddField<UIntValue>("ParentId", 5896U);
  expected->AddField<UIntValue>("SessionId", 5U);
  expected->AddField<IntValue>("ExitStatus", 259);
  expected->AddField<ULongValue>("DirectoryTableBase", 2745348096ULL);
  expected->AddField<UIntValue>("Flags", 0U);
  expected->AddField("UserSID", MakeSID64(18446673705038246032ULL,
                                          0,
                                          &sid[0],
                                          sizeof(sid)).Pass());

  expected->AddField<StringValue>("ImageFileName", "xperf.exe");
  expected->AddField<WStringValue>("CommandLine", L"xperf  -stop");
  expected->AddField<WStringValue>("PackageFullName", L"");
  expected->AddField<WStringValue>("ApplicationId", L"");

  EXPECT_STREQ("Process_Start", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessEndV3) {
  std::string name;
  scoped_ptr<Value> fields;

  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion3, kProcessEndOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessEndPayloadV3[0]),
          sizeof(kProcessEndPayloadV3),
          &name, &fields));

  const unsigned char sid[] = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 2, 3,
      4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 3, 0, 0 };

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("UniqueProcessKey", 18446738026653712480ULL);
  expected->AddField<UIntValue>("ProcessId", 8236ULL);
  expected->AddField<UIntValue>("ParentId", 7328U);
  expected->AddField<UIntValue>("SessionId", 1U);
  expected->AddField<IntValue>("ExitStatus", 0);
  expected->AddField<ULongValue>("DirectoryTableBase", 2755633152U);
  expected->AddField("UserSID", MakeSID64(18446735965099372992ULL,
                                          0,
                                          &sid[0],
                                          sizeof(sid)).Pass());
  std::string filename = "xperf.exe";
  expected->AddField<StringValue>("ImageFileName", filename);
  std::wstring commandline =
     L"xperf  -on PROC_THREAD+LOADER+CSWITCH -stackwalk ImageLoad+ImageUnload";
  expected->AddField<WStringValue>("CommandLine", commandline);

  EXPECT_STREQ("Process_End", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessEndV4) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion4, kProcessEndOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessEndPayloadV4[0]),
          sizeof(kProcessEndPayloadV4),
          &name, &fields));

  const unsigned char sid[] = {
      0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
      0x15, 0x00, 0x00, 0x00, 0x12, 0x13, 0x0F, 0x12,
      0x13, 0x42, 0x24, 0x33, 0xCC, 0xCA, 0xCC, 0xCB,
      0xBA, 0xBE, 0x00, 0x00 };

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("UniqueProcessKey", 18446708889790201984ULL);
  expected->AddField<UIntValue>("ProcessId", 2040U);
  expected->AddField<UIntValue>("ParentId", 5896U);
  expected->AddField<UIntValue>("SessionId", 5U);
  expected->AddField<IntValue>("ExitStatus", 0);
  expected->AddField<ULongValue>("DirectoryTableBase", 7478476800ULL);
  expected->AddField<UIntValue>("Flags", 0U);
  expected->AddField("UserSID", MakeSID64(18446673705334261920ULL,
                                          0,
                                          &sid[0],
                                          sizeof(sid)).Pass());

  expected->AddField<StringValue>("ImageFileName", "xperf.exe");
  expected->AddField<WStringValue>("CommandLine",
      L"xperf  -on PROC_THREAD+LOADER+PROFILE+CSWITCH+DISPATCHER+DPC+INTERRUPT"
      L"+SYSCALL+PRIORITY+SPINLOCK+PERF_COUNTER+DISK_IO+DISK_IO_INIT+FILE_IO+"
      L"FILE_IO_INIT+HARD_FAULTS+FILENAME+REGISTRY+DRIVERS+POWER+CC+"
      L"NETWORKTRACE+VIRT_ALLOC+MEMINFO+MEMORY+TIMER -f C:\\kernel.etl "
      L"-BufferSize 4096 -MinBuffers 256 -MaxBuffers 256");
  expected->AddField<WStringValue>("PackageFullName", L"");
  expected->AddField<WStringValue>("ApplicationId", L"");

  EXPECT_STREQ("Process_End", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessDCStartV3) {
  std::string name;
  scoped_ptr<Value> fields;

  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion3, kProcessDCStartOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessDCStartPayloadV3[0]),
          sizeof(kProcessDCStartPayloadV3),
          &name, &fields));

  const unsigned char sid[] = { 1, 1, 0, 0, 0, 0, 0, 5, 16, 0, 0, 0 };

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("UniqueProcessKey",  18446735277666959744ULL);
  expected->AddField<UIntValue>("ProcessId", 0);
  expected->AddField<UIntValue>("ParentId", 0U);
  expected->AddField<UIntValue>("SessionId", 0xFFFFFFFFU);
  expected->AddField<IntValue>("ExitStatus", 0);
  expected->AddField<ULongValue>("DirectoryTableBase", 1601536);
  expected->AddField("UserSID", MakeSID64(18446735965522384448ULL,
                                          0,
                                          &sid[0],
                                          sizeof(sid)).Pass());
  std::string filename = "Idle";
  expected->AddField<StringValue>("ImageFileName", filename);
  std::wstring commandline = L"";
  expected->AddField<WStringValue>("CommandLine", commandline);

  EXPECT_STREQ("Process_DCStart", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessDCStartV4) {
  std::string name;
  scoped_ptr<Value> fields;

  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion4, kProcessDCStartOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessDCStartPayloadV4[0]),
          sizeof(kProcessDCStartPayloadV4),
          &name, &fields));

  const unsigned char sid[] = { 1, 1, 0, 0, 0, 0, 0, 5, 16, 0, 0, 0 };

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("UniqueProcessKey", 18446735279574963136ULL);
  expected->AddField<UIntValue>("ProcessId", 0U);
  expected->AddField<UIntValue>("ParentId", 0U);
  expected->AddField<UIntValue>("SessionId", 4294967295U);
  expected->AddField<IntValue>("ExitStatus", 0);
  expected->AddField<ULongValue>("DirectoryTableBase", 1736704ULL);
  expected->AddField<UIntValue>("Flags", 0U);
  expected->AddField("UserSID", MakeSID64(18446673705735535552ULL,
                                          0,
                                          &sid[0],
                                          sizeof(sid)).Pass());
  expected->AddField<StringValue>("ImageFileName", "Idle");
  expected->AddField<WStringValue>("CommandLine", L"");
  expected->AddField<WStringValue>("PackageFullName", L"");
  expected->AddField<WStringValue>("ApplicationId", L"");

  EXPECT_STREQ("Process_DCStart", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessDCEndV4) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion4, kProcessDCEndOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessDCEndPayloadV4[0]),
          sizeof(kProcessDCEndPayloadV4),
          &name, &fields));

  const unsigned char sid[] = {
      0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
      0x10, 0x00, 0x00, 0x00 };

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("UniqueProcessKey", 18446735279574963136ULL);
  expected->AddField<UIntValue>("ProcessId", 0U);
  expected->AddField<UIntValue>("ParentId", 0U);
  expected->AddField<UIntValue>("SessionId", 4294967295U);
  expected->AddField<IntValue>("ExitStatus", 0);
  expected->AddField<ULongValue>("DirectoryTableBase", 1736704ULL);
  expected->AddField<UIntValue>("Flags", 0U);
  expected->AddField("UserSID", MakeSID64(18446673705343288816ULL,
                                          0,
                                          &sid[0],
                                          sizeof(sid)).Pass());
  expected->AddField<StringValue>("ImageFileName", "Idle");
  expected->AddField<WStringValue>("CommandLine", L"");
  expected->AddField<WStringValue>("PackageFullName", L"");
  expected->AddField<WStringValue>("ApplicationId", L"");

  EXPECT_STREQ("Process_DCEnd", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessTerminateV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion2, kProcessTerminateOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessTerminatePayloadV2[0]),
          sizeof(kProcessTerminatePayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("ProcessId", 2040U);

  EXPECT_STREQ("Process_Terminate", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessPerfCtrV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion2, kProcessPerfCtrOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessPerfCtrPayloadV2[0]),
          sizeof(kProcessPerfCtrPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("ProcessId", 2040U);
  expected->AddField<UIntValue>("PageFaultCount", 0U);
  expected->AddField<UIntValue>("HandleCount", 0U);
  expected->AddField<UIntValue>("Reserved", 0U);
  expected->AddField<ULongValue>("PeakVirtualSize", 61681664ULL);
  expected->AddField<ULongValue>("PeakWorkingSetSize", 6537216ULL);
  expected->AddField<ULongValue>("PeakPagefileUsage", 2191360ULL);
  expected->AddField<ULongValue>("QuotaPeakPagedPoolUsage", 113160ULL);
  expected->AddField<ULongValue>("QuotaPeakNonPagedPoolUsage", 9696ULL);
  expected->AddField<ULongValue>("VirtualSize", 0ULL);
  expected->AddField<ULongValue>("WorkingSetSize", 0ULL);
  expected->AddField<ULongValue>("PagefileUsage", 0ULL);
  expected->AddField<ULongValue>("QuotaPagedPoolUsage", 0ULL);
  expected->AddField<ULongValue>("QuotaNonPagedPoolUsage", 0ULL);
  expected->AddField<ULongValue>("PrivatePageCount", 0ULL);

  EXPECT_STREQ("Process_PerfCtr", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessPerfCtrRundownV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion2, kProcessPerfCtrRundownOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessPerfCtrRundownPayloadV2[0]),
          sizeof(kProcessPerfCtrRundownPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("ProcessId", 0U);
  expected->AddField<UIntValue>("PageFaultCount", 1U);
  expected->AddField<UIntValue>("HandleCount", 1123U);
  expected->AddField<UIntValue>("Reserved", 0U);
  expected->AddField<ULongValue>("PeakVirtualSize", 65536ULL);
  expected->AddField<ULongValue>("PeakWorkingSetSize", 24576ULL);
  expected->AddField<ULongValue>("PeakPagefileUsage", 0ULL);
  expected->AddField<ULongValue>("QuotaPeakPagedPoolUsage", 0ULL);
  expected->AddField<ULongValue>("QuotaPeakNonPagedPoolUsage", 0ULL);
  expected->AddField<ULongValue>("VirtualSize", 65536ULL);
  expected->AddField<ULongValue>("WorkingSetSize", 24576ULL);
  expected->AddField<ULongValue>("PagefileUsage", 0ULL);
  expected->AddField<ULongValue>("QuotaPagedPoolUsage", 0ULL);
  expected->AddField<ULongValue>("QuotaNonPagedPoolUsage", 0ULL);
  expected->AddField<ULongValue>("PrivatePageCount", 0ULL);

  EXPECT_STREQ("Process_PerfCtrRundown", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessDefunctV3) {
  std::string name;
  scoped_ptr<Value> fields;

  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion3, kProcessDefunctOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessDefunctPayloadV3[0]),
          sizeof(kProcessDefunctPayloadV3),
          &name, &fields));

  const unsigned char sid[] = { 1, 1, 0, 0, 0, 0, 0, 5, 16, 0, 0, 0 };

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("UniqueProcessKey", 18446738026725302368ULL);
  expected->AddField<UIntValue>("ProcessId", 3684U);
  expected->AddField<UIntValue>("ParentId", 2196U);
  expected->AddField<UIntValue>("SessionId", 0);
  expected->AddField<IntValue>("ExitStatus", 0);
  expected->AddField<ULongValue>("DirectoryTableBase", 6844006400ULL);
  expected->AddField("UserSID", MakeSID64(18446735964887549920ULL,
                                          0,
                                          &sid[0],
                                          sizeof(sid)).Pass());
  expected->AddField<StringValue>("ImageFileName", "cmd.exe");
  expected->AddField<WStringValue>("CommandLine", L"");

  EXPECT_STREQ("Process_Defunct", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ProcessDefunctV5) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kProcessProviderId,
          kVersion5, kProcessDefunctOpcode, k64bit,
          reinterpret_cast<const char*>(&kProcessDefunctPayloadV5[0]),
          sizeof(kProcessDefunctPayloadV5),
          &name, &fields));

  const unsigned char sid[] = {
      0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
      0x15, 0x00, 0x00, 0x00, 0xC0, 0xC1, 0xC2, 0xC3,
      0xC4, 0xC5, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3,
      0xD4, 0x03, 0x00, 0x00 };

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("UniqueProcessKey", 18446708889454036416ULL);
  expected->AddField<UIntValue>("ProcessId", 6472U);
  expected->AddField<UIntValue>("ParentId", 2064U);
  expected->AddField<UIntValue>("SessionId", 1U);
  expected->AddField<IntValue>("ExitStatus", 0);
  expected->AddField<ULongValue>("DirectoryTableBase", 1338728448ULL);
  expected->AddField<UIntValue>("Flags", 0U);
  expected->AddField("UserSID", MakeSID64(18446673705019631088ULL,
                                          0,
                                          &sid[0],
                                          sizeof(sid)).Pass());
  expected->AddField<StringValue>("ImageFileName", "chrome.exe");
  expected->AddField<WStringValue>("CommandLine", L"");
  expected->AddField<WStringValue>("PackageFullName", L"");
  expected->AddField<WStringValue>("ApplicationId", L"");
  expected->AddField<ULongValue>("ExitTime", 130317334947711373ULL);

  EXPECT_STREQ("Process_Defunct", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, PerfInfoSampleProfV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kPerfInfoProviderId,
          kVersion2, kPerfInfoSampleProfOpcode, k64bit,
          reinterpret_cast<const char*>(&kPerfInfoSampleProfPayloadV2[0]),
          sizeof(kPerfInfoSampleProfPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("InstructionPointer",
                                 18446735279571905355ULL);
  expected->AddField<UIntValue>("ThreadId", 8048U);
  expected->AddField<UShortValue>("Count", 1);
  expected->AddField<UShortValue>("Reserved", 64);

  EXPECT_STREQ("PerfInfo_SampleProf", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, PerfInfoISRMSIV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kPerfInfoProviderId,
          kVersion2, kPerfInfoISRMSIOpcode, k64bit,
          reinterpret_cast<const char*>(&kPerfInfoISRMSIPayloadV2[0]),
          sizeof(kPerfInfoISRMSIPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("InitialTime", 4838955609579ULL);
  expected->AddField<ULongValue>("Routine", 18446735277626195488ULL);
  expected->AddField<UCharValue>("ReturnValue", 1);
  expected->AddField<UShortValue>("Vector", 145);
  expected->AddField<UCharValue>("Reserved", 0);
  expected->AddField<UIntValue>("MessageNumber", 0U);

  EXPECT_STREQ("PerfInfo_ISR-MSI", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, PerfInfoSysClEnterV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kPerfInfoProviderId,
          kVersion2, kPerfInfoSysClEnterOpcode, k64bit,
          reinterpret_cast<const char*>(&kPerfInfoSysClEnterPayloadV2[0]),
          sizeof(kPerfInfoSysClEnterPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("SysCallAddress", 18446735279572131108ULL);

  EXPECT_STREQ("PerfInfo_SysClEnter", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, PerfInfoSysClExitV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kPerfInfoProviderId,
          kVersion2, kPerfInfoSysClExitOpcode, k64bit,
          reinterpret_cast<const char*>(&kPerfInfoSysClExitPayloadV2[0]),
          sizeof(kPerfInfoSysClExitPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("SysCallNtStatus", 0U);

  EXPECT_STREQ("PerfInfo_SysClExit", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, PerfInfoISRV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kPerfInfoProviderId,
          kVersion2, kPerfInfoISROpcode, k64bit,
          reinterpret_cast<const char*>(&kPerfInfoISRPayloadV2[0]),
          sizeof(kPerfInfoISRPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("InitialTime", 4838956092844ULL);
  expected->AddField<ULongValue>("Routine", 18446735277666407872ULL);
  expected->AddField<UCharValue>("ReturnValue", 0);
  expected->AddField<UShortValue>("Vector", 129);
  expected->AddField<UCharValue>("Reserved", 0);

  EXPECT_STREQ("PerfInfo_ISR", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, PerfInfoDPCV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kPerfInfoProviderId,
          kVersion2, kPerfInfoDPCOpcode, k64bit,
          reinterpret_cast<const char*>(&kPerfInfoDPCPayloadV2[0]),
          sizeof(kPerfInfoDPCPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("InitialTime", 4838955609293ULL);
  expected->AddField<ULongValue>("Routine", 18446735279572565220ULL);

  EXPECT_STREQ("PerfInfo_DPC", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, PerfInfoCollectionStartSecondV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kPerfInfoProviderId,
          kVersion3, kPerfInfoCollectionStartSecondOpcode, k64bit,
          reinterpret_cast<const char*>(
              &kPerfInfoCollectionStartSecondPayloadV3[0]),
          sizeof(kPerfInfoCollectionStartSecondPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("Source", 0U);
  expected->AddField<UIntValue>("NewInterval", 10000U);
  expected->AddField<UIntValue>("OldInterval", 10000U);
  expected->AddField<WStringValue>("SourceName", L"Timer");

  EXPECT_STREQ("PerfInfo_CollectionStart", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, PerfInfoCollectionStartV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kPerfInfoProviderId,
          kVersion3, kPerfInfoCollectionStartOpcode, k64bit,
          reinterpret_cast<const char*>(&kPerfInfoCollectionStartPayloadV3[0]),
          sizeof(kPerfInfoCollectionStartPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("SpinLockSpinThreshold", 1U);
  expected->AddField<UIntValue>("SpinLockContentionSampleRate", 1U);
  expected->AddField<UIntValue>("SpinLockAcquireSampleRate", 1000U);
  expected->AddField<UIntValue>("SpinLockHoldThreshold", 0U);

  EXPECT_STREQ("PerfInfo_CollectionStart", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, PerfInfoCollectionEndV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kPerfInfoProviderId,
          kVersion3, kPerfInfoCollectionEndOpcode, k64bit,
          reinterpret_cast<const char*>(&kPerfInfoCollectionEndPayloadV3[0]),
          sizeof(kPerfInfoCollectionEndPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("SpinLockSpinThreshold", 1U);
  expected->AddField<UIntValue>("SpinLockContentionSampleRate", 1U);
  expected->AddField<UIntValue>("SpinLockAcquireSampleRate", 1000U);
  expected->AddField<UIntValue>("SpinLockHoldThreshold", 0U);

  EXPECT_STREQ("PerfInfo_CollectionEnd", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, PerfInfoCollectionEndSecondV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kPerfInfoProviderId,
          kVersion3, kPerfInfoCollectionEndSecondOpcode, k64bit,
          reinterpret_cast<const char*>(
              &kPerfInfoCollectionEndSecondPayloadV3[0]),
          sizeof(kPerfInfoCollectionEndSecondPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("Source", 0U);
  expected->AddField<UIntValue>("NewInterval", 10000U);
  expected->AddField<UIntValue>("OldInterval", 10000U);
  expected->AddField<WStringValue>("SourceName", L"Timer");

  EXPECT_STREQ("PerfInfo_CollectionEnd", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadStartV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion3, kThreadStartOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadStartPayloadV3[0]),
          sizeof(kThreadStartPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("ProcessId", 8568U);
  expected->AddField<UIntValue>("TThreadId", 5268U);
  expected->AddField<ULongValue>("StackBase", 18446691297806659584ULL);
  expected->AddField<ULongValue>("StackLimit", 18446691297806635008ULL);
  expected->AddField<ULongValue>("UserStackBase", 101449008ULL);
  expected->AddField<ULongValue>("UserStackLimit", 101416960ULL);
  expected->AddField<ULongValue>("Affinity", 255ULL);
  expected->AddField<ULongValue>("Win32StartAddr", 1549335852ULL);
  expected->AddField<ULongValue>("TebBase", 4279418880ULL);
  expected->AddField<UIntValue>("SubProcessTag", 0U);
  expected->AddField<UCharValue>("BasePriority", 8);
  expected->AddField<UCharValue>("PagePriority", 5);
  expected->AddField<UCharValue>("IoPriority", 2);
  expected->AddField<UCharValue>("ThreadFlags", 0);

  EXPECT_STREQ("Thread_Start", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadEndV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion3, kThreadEndOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadEndPayloadV3[0]),
          sizeof(kThreadEndPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("ProcessId", 2040U);
  expected->AddField<UIntValue>("TThreadId", 3288U);
  expected->AddField<ULongValue>("StackBase", 18446691297848487936ULL);
  expected->AddField<ULongValue>("StackLimit", 18446691297848463360ULL);
  expected->AddField<ULongValue>("UserStackBase", 903052263424ULL);
  expected->AddField<ULongValue>("UserStackLimit", 903052255232ULL);
  expected->AddField<ULongValue>("Affinity", 255ULL);
  expected->AddField<ULongValue>("Win32StartAddr", 140723235226928ULL);
  expected->AddField<ULongValue>("TebBase", 140699801714688ULL);
  expected->AddField<UIntValue>("SubProcessTag", 0U);
  expected->AddField<UCharValue>("BasePriority", 8);
  expected->AddField<UCharValue>("PagePriority", 5);
  expected->AddField<UCharValue>("IoPriority", 2);
  expected->AddField<UCharValue>("ThreadFlags", 0);

  EXPECT_STREQ("Thread_End", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadDCStartV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion3, kThreadDCStartOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadDCStartPayloadV3[0]),
          sizeof(kThreadDCStartPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("ProcessId", 0U);
  expected->AddField<UIntValue>("TThreadId", 0U);
  expected->AddField<ULongValue>("StackBase", 18446735279600988160ULL);
  expected->AddField<ULongValue>("StackLimit", 18446735279600963584ULL);
  expected->AddField<ULongValue>("UserStackBase", 0ULL);
  expected->AddField<ULongValue>("UserStackLimit", 0ULL);
  expected->AddField<ULongValue>("Affinity", 1ULL);
  expected->AddField<ULongValue>("Win32StartAddr", 18446735279572912016ULL);
  expected->AddField<ULongValue>("TebBase", 0ULL);
  expected->AddField<UIntValue>("SubProcessTag", 0U);
  expected->AddField<UCharValue>("BasePriority", 0);
  expected->AddField<UCharValue>("PagePriority", 5);
  expected->AddField<UCharValue>("IoPriority", 0);
  expected->AddField<UCharValue>("ThreadFlags", 0);

  EXPECT_STREQ("Thread_DCStart", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadDCEndV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion3, kThreadDCEndOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadDCEndPayloadV3[0]),
          sizeof(kThreadDCEndPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("ProcessId", 0U);
  expected->AddField<UIntValue>("TThreadId", 0U);
  expected->AddField<ULongValue>("StackBase", 18446735279600988160ULL);
  expected->AddField<ULongValue>("StackLimit", 18446735279600963584ULL);
  expected->AddField<ULongValue>("UserStackBase", 0ULL);
  expected->AddField<ULongValue>("UserStackLimit", 0ULL);
  expected->AddField<ULongValue>("Affinity", 1ULL);
  expected->AddField<ULongValue>("Win32StartAddr", 18446735279572912016ULL);
  expected->AddField<ULongValue>("TebBase", 0ULL);
  expected->AddField<UIntValue>("SubProcessTag", 0U);
  expected->AddField<UCharValue>("BasePriority", 0);
  expected->AddField<UCharValue>("PagePriority", 5);
  expected->AddField<UCharValue>("IoPriority", 0);
  expected->AddField<UCharValue>("ThreadFlags", 0);

  EXPECT_STREQ("Thread_DCEnd", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadCSwitchV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion2, kThreadCSwitchOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadCSwitchPayloadV2[0]),
          sizeof(kThreadCSwitchPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("NewThreadId", 2252U);
  expected->AddField<UIntValue>("OldThreadId", 0U);
  expected->AddField<CharValue>("NewThreadPriority", 8);
  expected->AddField<CharValue>("OldThreadPriority", 0);
  expected->AddField<UCharValue>("PreviousCState", 1);
  expected->AddField<CharValue>("SpareByte", 0);
  expected->AddField<CharValue>("OldThreadWaitReason", 0);
  expected->AddField<CharValue>("OldThreadWaitMode", 0);
  expected->AddField<CharValue>("OldThreadState", 2);
  expected->AddField<CharValue>("OldThreadWaitIdealProcessor", 4);
  expected->AddField<UIntValue>("NewThreadWaitTime", 1U);
  expected->AddField<UIntValue>("Reserved", 881356167U);

  EXPECT_STREQ("Thread_CSwitch", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadSpinLockV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion2, kThreadSpinLockOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadSpinLockPayloadV2[0]),
          sizeof(kThreadSpinLockPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("SpinLockAddress", 18446708889382682976ULL);
  expected->AddField<ULongValue>("CallerAddress", 18446735279573042192ULL);
  expected->AddField<ULongValue>("AcquireTime", 2104105494612894ULL);
  expected->AddField<ULongValue>("ReleaseTime", 2104105494613543ULL);
  expected->AddField<UIntValue>("WaitTimeInCycles", 1681U);
  expected->AddField<UIntValue>("SpinCount", 11U);
  expected->AddField<UIntValue>("ThreadId", 0U);
  expected->AddField<UIntValue>("InterruptCount", 0U);
  expected->AddField<UCharValue>("Irql", 0);
  expected->AddField<UCharValue>("AcquireDepth", 1);
  expected->AddField<UCharValue>("Flag", 0);

  scoped_ptr<ArrayValue> reserved_array(new ArrayValue());
  for (int i = 0; i < 5; ++i)
    reserved_array->Append<UCharValue>(0);
  expected->AddField("Reserved", reserved_array.PassAs<Value>());

  EXPECT_STREQ("Thread_SpinLock", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadSetPriorityV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion3, kThreadSetPriorityOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadSetPriorityPayloadV3[0]),
          sizeof(kThreadSetPriorityPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("ThreadId", 544U);
  expected->AddField<UCharValue>("OldPriority", 15);
  expected->AddField<UCharValue>("NewPriority", 16);
  expected->AddField<UShortValue>("Reserved", 0);

  EXPECT_STREQ("Thread_SetPriority", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadSetBasePriorityV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion3, kThreadSetBasePriorityOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadSetBasePriorityPayloadV3[0]),
          sizeof(kThreadSetBasePriorityPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("ThreadId", 6896U);
  expected->AddField<UCharValue>("OldPriority", 4);
  expected->AddField<UCharValue>("NewPriority", 7);
  expected->AddField<UShortValue>("Reserved", 7);

  EXPECT_STREQ("Thread_SetBasePriority", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadReadyThreadV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion2, kThreadReadyThreadOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadReadyThreadPayloadV2[0]),
          sizeof(kThreadReadyThreadPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("TThreadId", 2252U);
  expected->AddField<CharValue>("AdjustReason", 1);
  expected->AddField<CharValue>("AdjustIncrement", 0);
  expected->AddField<CharValue>("Flag", 1);
  expected->AddField<CharValue>("Reserved", 0);

  EXPECT_STREQ("Thread_ReadyThread", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadSetPagePriorityV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion3, kThreadSetPagePriorityOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadSetPagePriorityPayloadV3[0]),
          sizeof(kThreadSetPagePriorityPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("ThreadId", 6764U);
  expected->AddField<UCharValue>("OldPriority", 5);
  expected->AddField<UCharValue>("NewPriority", 6);
  expected->AddField<UShortValue>("Reserved", 0);

  EXPECT_STREQ("Thread_SetPagePriority", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadSetIoPriorityV3) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion3, kThreadSetIoPriorityOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadSetIoPriorityPayloadV3[0]),
          sizeof(kThreadSetIoPriorityPayloadV3),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<UIntValue>("ThreadId", 188U);
  expected->AddField<UCharValue>("OldPriority", 2);
  expected->AddField<UCharValue>("NewPriority", 0);
  expected->AddField<UShortValue>("Reserved", 0);

  EXPECT_STREQ("Thread_SetIoPriority", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadAutoBoostSetFloorV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion2, kThreadAutoBoostSetFloorOpcode, k64bit,
          reinterpret_cast<const char*>(&kThreadAutoBoostSetFloorPayloadV2[0]),
          sizeof(kThreadAutoBoostSetFloorPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("Lock", 18446708889355637112ULL);
  expected->AddField<UIntValue>("ThreadId", 6896U);
  expected->AddField<UCharValue>("NewCpuPriorityFloor", 11);
  expected->AddField<UCharValue>("OldCpuPriority", 7);
  expected->AddField<UCharValue>("IoPriorities", 32);
  expected->AddField<UCharValue>("BoostFlags", 0);

  EXPECT_STREQ("Thread_AutoBoostSetFloor", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadAutoBoostClearFloorV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion2, kThreadAutoBoostClearFloorOpcode, k64bit,
          reinterpret_cast<const char*>(
              &kThreadAutoBoostClearFloorPayloadV2[0]),
          sizeof(kThreadAutoBoostClearFloorPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("LockAddress", 18446708889355637112ULL);
  expected->AddField<UIntValue>("ThreadId", 6896U);
  expected->AddField<UShortValue>("BoostBitmap", 2048);
  expected->AddField<UShortValue>("Reserved", 0);

  EXPECT_STREQ("Thread_AutoBoostClearFloor", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

TEST(EtwRawDecoderTest, ThreadAutoBoostEntryExhaustionV2) {
  std::string name;
  scoped_ptr<Value> fields;
  EXPECT_TRUE(
      DecodeRawETWKernelPayload(kThreadProviderId,
          kVersion2, kThreadAutoBoostEntryExhaustionOpcode, k64bit,
          reinterpret_cast<const char*>(
              &kThreadAutoBoostEntryExhaustionPayloadV2[0]),
          sizeof(kThreadAutoBoostEntryExhaustionPayloadV2),
          &name, &fields));

  scoped_ptr<StructValue> expected(new StructValue());
  expected->AddField<ULongValue>("LockAddress", 18446708889482441968ULL);
  expected->AddField<UIntValue>("ThreadId", 3004U);

  EXPECT_STREQ("Thread_AutoBoostEntryExhaustion", name.c_str());
  EXPECT_TRUE(expected->Equals(fields.get()));
}

}  // namespace etw
}  // namespace parser
