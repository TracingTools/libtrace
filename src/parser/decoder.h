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
//
// The decoder class provides utility functions to decode a sequence of bytes
// into Values. Parsers should use this class to decode the payloads.
//
// The decoder class should be used like this:
//
//  char payload[] = { .... };  // Sequence of bytes to decode.
//  Decoder decoder(&payload[0], sizeof(payload));
//
//  // Decode a single scalar value.
//  scoped_ptr<Value> my_int(decoder.Decode<UIntValue>());
//
//  // Decode an array of values.
//  scoped_ptr<Value> my_array(decoder->DecodeArray<UIntValue>(10));

#ifndef PARSER_DECODER_H_
#define PARSER_DECODER_H_

#include <iostream>
#include <iomanip>
#include <set>

#include "base/logging.h"
#include "base/scoped_ptr.h"
#include "event/value.h"

namespace parser {

// A utility class to decode a sequence of bytes into Values.
class Decoder {
 public:
  typedef event::Value Value;
  typedef event::ArrayValue ArrayValue;
  typedef event::StringValue StringValue;
  typedef event::WStringValue WStringValue;

  // Constructor.
  // @param buffer the sequence of bytes to decode. Must outlive the decoder.
  // @param buffer_size the number of bytes to decode.
  Decoder(const char* buffer, size_t buffer_size)
      : buffer_(buffer),
        buffer_size_(buffer_size),
        position_(0) {
  }

  // @returns the remaining number of bytes to decode.
  size_t RemainingBytes() const {
    return buffer_size_ - position_;
  }

  // Decode a scalar Value.
  // @tparam T the type of Value to decode.
  // @returns the decoded value if successful, NULL otherwise.
  template <typename T>
  scoped_ptr<T> Decode() {
    typedef typename T::ScalarType ScalarType;
    scoped_ptr<T> result;

    // There is not enough bytes, returns no value.
    if (RemainingBytes() < sizeof(ScalarType))
      return result.Pass();

    // Consume the bytes.
    size_t offset = position_;
    position_ += sizeof(ScalarType);
    result.reset(
        new T(*reinterpret_cast<const ScalarType*>(&buffer_[offset])));
    return result.Pass();
  }

  // Decode an array of scalar Value.
  // @tparam T the type of Value to decode.
  // @returns the decoded array if successful, NULL otherwise.
  template <typename T>
  scoped_ptr<ArrayValue> DecodeArray(size_t size) {
    scoped_ptr<event::ArrayValue> array(new event::ArrayValue());

    // Decode |size| elements from the sequence of bytes.
    for (size_t i = 0; i < size; ++i) {
      scoped_ptr<Value> element = Decode<T>();

      // If an error occurred, clears the array and returns no value.
      if (element.get() == NULL) {
        array.reset(NULL);
        return array.Pass();
      }

      // Append the new element to the array.
      array->Append(element.Pass());
    }

    return array.Pass();
  }

  // Decode a string.
  // @returns the decoded string.
  scoped_ptr<StringValue> DecodeString();

  // Decode a std::wstring.
  // @returns the decoded string.
  scoped_ptr<WStringValue> DecodeWString();

  // Decode a string of 16-bit chars.
  // @returns the decoded string.
  scoped_ptr<WStringValue> DecodeW16String();

  // Advances the current read position by the specified number of bytes.
  // @param size number of bytes to skip.
  // @returns true if the bytes have been skipped, false if there is not
  //    enough remaining bytes in the buffer.
  bool Skip(size_t size);

  // Look ahead for a character into the sequence of bytes.
  // @param offset the offset from the current position to look.
  // @returns the requested character.
  unsigned char lookup(size_t offset);

 private:
  // The sequence of bytes to decode.
  const char* buffer_;

  // The length of the sequence of bytes.
  size_t buffer_size_;

  // The actual position into the sequence of bytes.
  size_t position_;
};

template<>
inline scoped_ptr<event::StringValue> Decoder::Decode<event::StringValue>() {
  return DecodeString();
}

template<>
inline scoped_ptr<event::WStringValue> Decoder::Decode<event::WStringValue>() {
  return DecodeWString();
}

}  // namespace parser

#endif  // PARSER_DECODER_H_
