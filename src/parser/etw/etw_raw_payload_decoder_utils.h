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

#ifndef ETW_PARSER_ETW_ETW_RAW_PAYLOAD_DECODER_UTILS_H_
#define ETW_PARSER_ETW_ETW_RAW_PAYLOAD_DECODER_UTILS_H_

#include <string>

#include "base/logging.h"
#include "base/scoped_ptr.h"
#include "event/value.h"
#include "parser/decoder.h"

namespace parser {
namespace etw {

// Decode a value and add it as a field into struct.
// @tparam T the type of the value to decode.
// @param name the name of the field to be added.
// @param decoder the decoder processing the payload.
// @param fields the structure to receive the field.
// @returns true on sucess, false otherwise.
template <class T>
bool Decode(const std::string& name, Decoder* decoder,
            event::StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(fields != NULL);

  scoped_ptr<event::Value> decoded(decoder->Decode<T>());

  if (decoded.get() == NULL ||
      !fields->AddField(name, decoded.Pass())) {
    return false;
  }

  return true;
}

// Decode an array of values and add it as a field into a struct.
// @tparam T the type of the value to decode.
// @param name the name of the field to be added.
// @param length the number of element into the array.
// @param decoder the decoder processing the payload.
// @param fields the structure to receive the field.
// @returns true on sucess, false otherwise.
template <class T>
bool DecodeArray(const std::string& name,
                 size_t length,
                 Decoder* decoder,
                 event::StructValue* fields) {
  DCHECK(decoder != NULL);
  DCHECK(fields != NULL);

  scoped_ptr<event::ArrayValue> decoded(decoder->DecodeArray<T>(length));

  if (decoded.get() == NULL ||
      !fields->AddField(name, decoded.Pass())) {
    return false;
  }

  return true;
}

// Decode an unsigned integer and add it as a field into |fields|.
// The integer can be 32-bit or 64-bit depending on the flag |is_64_bit|.
// @param name the name of the field to be added.
// @param is_64_bit the flag to enable decoding of 64-bit integer.
// @param decoder the decoder processing the payload.
// @param fields the structure to receive the field.
// @returns true on sucess, false otherwise.
bool DecodeUInteger(const std::string& name,
                    bool is_64_bit,
                    Decoder* decoder,
                    event::StructValue* fields);

// Decode a string of 16-bit char and add it as a field into |fields|.
// @param name the name of the field to be added.
// @param decoder the decoder processing the payload.
// @param fields the structure to receive the field.
// @returns true on sucess, false otherwise.
bool DecodeW16String(const std::string& name,
                     Decoder* decoder,
                     event::StructValue* fields);

// Decode a SID (Secure ID) structure.
// @param name the name of the field to be added.
// @param is_64_bit the flag to enable decoding of 64-bit integer.
// @param decoder the decoder processing the payload.
// @param fields the structure to receive the field.
// @returns true on sucess, false otherwise.
bool DecodeSID(const std::string& name,
               bool is_64_bit,
               Decoder* decoder,
               event::StructValue* fields);

}  // namespace etw
}  // namespace parser

#endif  // ETW_PARSER_ETW_ETW_RAW_PAYLOAD_DECODER_UTILS_H_
