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

#include "gtest/gtest.h"
#include "event/value.h"

namespace parser {

namespace {

using event::ArrayValue;
using event::CharValue;
using event::IntValue;
using event::LongValue;
using event::StringValue;
using event::WStringValue;
using event::Value;

const char kSmallBuffer[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

size_t kSmallBufferLength = sizeof(kSmallBuffer) / sizeof(char);

}  // namespace

TEST(DecoderTest, Constructor) {
  Decoder decoder(&kSmallBuffer[0], kSmallBufferLength);
  EXPECT_EQ(kSmallBufferLength, decoder.RemainingBytes());
}

TEST(DecoderTest, DecodeChar) {
  Decoder decoder(&kSmallBuffer[0], kSmallBufferLength);
  scoped_ptr<CharValue> value(decoder.Decode<CharValue>());
  EXPECT_EQ(event::VALUE_CHAR, value->GetType());
  EXPECT_EQ(0x01, CharValue::GetValue(value.get()));
  EXPECT_EQ(kSmallBufferLength - 1U, decoder.RemainingBytes());
}

TEST(DecoderTest, DecodeInt) {
  Decoder decoder(&kSmallBuffer[0], kSmallBufferLength);
  scoped_ptr<IntValue> value(decoder.Decode<IntValue>());
  EXPECT_EQ(event::VALUE_INT, value->GetType());
  EXPECT_EQ(0x04030201, IntValue::GetValue(value.get()));
  EXPECT_EQ(kSmallBufferLength - 4U, decoder.RemainingBytes());
}

TEST(DecoderTest, DecodeLong) {
  Decoder decoder(&kSmallBuffer[0], kSmallBufferLength);
  scoped_ptr<LongValue> value(decoder.Decode<LongValue>());
  EXPECT_EQ(event::VALUE_LONG, value->GetType());
  EXPECT_EQ(0x0807060504030201LL, LongValue::GetValue(value.get()));
  EXPECT_EQ(kSmallBufferLength - 8U, decoder.RemainingBytes());
}

TEST(DecoderTest, DecodeEmptyFails) {
  Decoder decoder(&kSmallBuffer[0], 0);
  scoped_ptr<IntValue> value(decoder.Decode<IntValue>());
  EXPECT_EQ(NULL, value.get());
}

TEST(DecoderTest, DecodeTooSmallFails) {
  Decoder decoder(&kSmallBuffer[0], 2);
  scoped_ptr<IntValue> value(decoder.Decode<IntValue>());
  EXPECT_EQ(NULL, value.get());
}

TEST(DecoderTest, DecodeArrayChar) {
  Decoder decoder(&kSmallBuffer[0], kSmallBufferLength);
  scoped_ptr<ArrayValue> value(decoder.DecodeArray<CharValue>(4));
  EXPECT_EQ(event::VALUE_ARRAY, value->GetType());
  EXPECT_EQ(4U, ArrayValue::Cast(value.get())->Length());
  EXPECT_EQ(kSmallBufferLength - 4U, decoder.RemainingBytes());

  for (int i = 0; i < 4; ++i) {
    char element = CharValue::GetValue(ArrayValue::Cast(value.get())->at(i));
    EXPECT_EQ(i + 1, element);
  }
}

TEST(DecoderTest, DecodeEmptyArray) {
  Decoder decoder(&kSmallBuffer[0], kSmallBufferLength);
  scoped_ptr<ArrayValue> value(decoder.DecodeArray<CharValue>(0));
  EXPECT_EQ(event::VALUE_ARRAY, value->GetType());
  EXPECT_EQ(0U, ArrayValue::Cast(value.get())->Length());
  EXPECT_EQ(kSmallBufferLength, decoder.RemainingBytes());
}

TEST(DecoderTest, DecodeString) {
  const char original[] = "This is a test.";
  Decoder decoder(&original[0], sizeof(original) / sizeof(char));
  scoped_ptr<StringValue> value(decoder.DecodeString());
  EXPECT_EQ(event::VALUE_STRING, value->GetType());
  EXPECT_EQ(0U, decoder.RemainingBytes());
  EXPECT_STREQ(original, StringValue::GetValue(value.get()).c_str());
}

TEST(DecoderTest, DecodeStringTemplate) {
  const char original[] = "This is a test.";
  Decoder decoder(&original[0], sizeof(original) / sizeof(char));
  scoped_ptr<StringValue> value(decoder.Decode<StringValue>());
  EXPECT_EQ(event::VALUE_STRING, value->GetType());
  EXPECT_EQ(0U, decoder.RemainingBytes());
  EXPECT_STREQ(original, StringValue::GetValue(value.get()).c_str());
}

TEST(DecoderTest, DecodeWString) {
  const wchar_t original[] = L"This is a test.";
  Decoder decoder(reinterpret_cast<const char*>(&original[0]),
                  sizeof(original) / sizeof(char));
  scoped_ptr<WStringValue> value(decoder.DecodeWString());
  EXPECT_EQ(event::VALUE_WSTRING, value->GetType());
  EXPECT_EQ(0U, decoder.RemainingBytes());
  EXPECT_EQ(0, WStringValue::GetValue(value.get()).compare(original));
}

TEST(DecoderTest, DecodeWStringTemplate) {
  const wchar_t original[] = L"This is a test.";
  Decoder decoder(reinterpret_cast<const char*>(&original[0]),
                  sizeof(original) / sizeof(char));
  scoped_ptr<WStringValue> value(decoder.Decode<WStringValue>());
  EXPECT_EQ(event::VALUE_WSTRING, value->GetType());
  EXPECT_EQ(0U, decoder.RemainingBytes());
  EXPECT_EQ(0, WStringValue::GetValue(value.get()).compare(original));
}

TEST(DecoderTest, DecodeW16String) {
  const char original[] = "T\0h\0i\0s\0 \0i\0s\0 \0a\0 \0t\0e\0s\0t\0.\0\0";
  const wchar_t expected[] = L"This is a test.";
  Decoder decoder(&original[0], sizeof(original) / sizeof(char));
  scoped_ptr<WStringValue> value(decoder.DecodeW16String());
  EXPECT_EQ(event::VALUE_WSTRING, value->GetType());
  EXPECT_EQ(0U, decoder.RemainingBytes());
  EXPECT_EQ(0, WStringValue::GetValue(value.get()).compare(expected));
}

}  // namespace parser
