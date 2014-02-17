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

#ifndef PARSER_ETW_ETW_RAW_KERNEL_PAYLOAD_DECODER_H_
#define PARSER_ETW_ETW_RAW_KERNEL_PAYLOAD_DECODER_H_

#include <string>

#include "base/scoped_ptr.h"

// Forward declaration.
namespace event {
class Value;
}

namespace parser {
namespace etw {

// Decodes the raw payload of an ETW kernel event without relying on external
// definitions.
// see: http://msdn.microsoft.com/library/windows/desktop/aa364083.aspx
// @param provider_id the GUID of the provider of the event.
// @param version the version of the event definition.
// @param opcode the opcode of the event.
// @param is_64_bit indicates whether the event was generated on a 64-bit OS.
// @param payload the raw payload to decode.
// @param payload_size the size of the raw payload, in bytes.
// @param operation the name associated with the opcode of this event.
// @param category the name of the category of this event.
// @param decoded_payload the decoded payload.
// @returns true if the payload has been decoded successfully, false otherwise.
bool DecodeRawETWKernelPayload(const std::string& provider_id,
                               unsigned char version,
                               unsigned char opcode,
                               bool is_64_bit,
                               const char* payload,
                               size_t payload_size,
                               std::string* operation,
                               std::string* category,
                               scoped_ptr<event::Value>* decoded_payload);

}  // namespace etw
}  // namespace parser

#endif  // PARSER_ETW_ETW_RAW_KERNEL_PAYLOAD_DECODER_H_
