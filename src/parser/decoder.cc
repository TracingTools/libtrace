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

#include "parser/decoder.h"

#include <sstream>
#include <string>

#include "base/string_utils.h"

namespace parser {

namespace {

using event::Value;
using event::StringValue;
using event::WStringValue;

}  // namespace

scoped_ptr<StringValue> Decoder::DecodeString() {
  scoped_ptr<StringValue> result;
  size_t start = position_;
  while (RemainingBytes() >= sizeof(char)) {
    char c = buffer_[position_];
    ++position_;

    if (c == 0) {
      std::string string(&buffer_[start], position_ - start - 1);
      result.reset(new StringValue(string));
      break;
    }
  }

  return result.Pass();
}

scoped_ptr<WStringValue> Decoder::DecodeWString() {
  scoped_ptr<WStringValue> result;
  size_t start = position_;
  while (RemainingBytes() >= sizeof(wchar_t)) {
    wchar_t c = *reinterpret_cast<const wchar_t*>(&buffer_[position_]);
    position_ += sizeof(wchar_t);

    if (c == 0) {
      std::wstring wstring(reinterpret_cast<const wchar_t*>(&buffer_[start]),
                           (position_ - start - 1) / sizeof(wchar_t));
      result.reset(new WStringValue(wstring));
      break;
    }
  }

  return result.Pass();
}

scoped_ptr<WStringValue> Decoder::DecodeW16String() {
  // The decoding cannot use native wchar_t because it can be 2 bytes or
  // 4 bytes.
  scoped_ptr<WStringValue> result;
  std::wstringstream ss;
  while (RemainingBytes() >= 2) {
    wchar_t c = buffer_[position_] | (buffer_[position_ + 1]  << 8);
    position_ += 2;

    if (c == 0) {
      result.reset(new WStringValue(ss.str()));
      break;
    }

    ss << c;
  }

  return result.Pass();
}

scoped_ptr<WStringValue> Decoder::DecodeFixedW16String(size_t length) {
  // The decoding cannot use native wchar_t because it can be 2 bytes or
  // 4 bytes.
  scoped_ptr<WStringValue> result;
  std::wstringstream ss;

  // Check whether there is enough characters.
  if (RemainingBytes() < 2 * length)
    return result.Pass();

  // Compute the position after consuming the array.
  size_t next_position = position_ + 2 * length;

  // Consume the array.
  for (size_t i = 0; i < length; ++i) {
    wchar_t c = buffer_[position_] | (buffer_[position_ + 1]  << 8);
    position_ += 2;

    if (c == 0)
      break;

    ss << c;
  }

  // Move the decoder forward after the fixed length array.
  position_ = next_position;

  // Create and return the resulting value.
  result.reset(new WStringValue(ss.str()));

  return result.Pass();
}

bool Decoder::Skip(size_t size) {
  size_t new_position = position_ + size;
  if (new_position > buffer_size_)
    return false;
  position_ = new_position;
  return true;
}

unsigned char Decoder::Lookup(size_t offset) {
  if (position_ + offset >= buffer_size_)
    return 0;
  return static_cast<unsigned char>(buffer_[position_ + offset]);
}

}  // namespace parser
