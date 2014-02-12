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

#include "parser/etw/etw_raw_payload_decoder_utils.h"

#include "event/value.h"
#include "gtest/gtest.h"

namespace parser {
namespace etw {

namespace {

using event::ArrayValue;
using event::UIntValue;
using event::ShortValue;
using event::StringValue;
using event::StructValue;

const char kSmallBuffer[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

size_t kSmallBufferLength = sizeof(kSmallBuffer) / sizeof(char);

}  // namespace

TEST(EtwDecoderUtilsTest, DecodeUInt32) {
  StructValue fields;
  Decoder decoder(&kSmallBuffer[0], kSmallBufferLength);
  EXPECT_TRUE(Decode<UIntValue>("integer", &decoder, &fields));

  uint32 value;
  EXPECT_TRUE(fields.GetFieldAsUInteger("integer", &value));
  EXPECT_EQ(0x04030201, value);
}

TEST(EtwDecoderUtilsTest, DecodeArrayOfShort) {
  StructValue fields;
  Decoder decoder(&kSmallBuffer[0], kSmallBufferLength);
  EXPECT_TRUE(DecodeArray<ShortValue>("shorts", 4, &decoder, &fields));
  EXPECT_EQ(decoder.RemainingBytes(), 0);

  const ArrayValue* decoded = NULL;
  EXPECT_TRUE(fields.GetFieldAs<ArrayValue>("shorts", &decoded));
  uint32 element1 = 0;
  uint32 element2 = 0;
  uint32 element3 = 0;
  uint32 element4 = 0;
  EXPECT_TRUE(decoded->GetElementAsUInteger(0, &element1));
  EXPECT_TRUE(decoded->GetElementAsUInteger(1, &element2));
  EXPECT_TRUE(decoded->GetElementAsUInteger(2, &element3));
  EXPECT_TRUE(decoded->GetElementAsUInteger(3, &element4));
  EXPECT_EQ(element1, 0x0201);
  EXPECT_EQ(element2, 0x0403);
  EXPECT_EQ(element3, 0x0605);
  EXPECT_EQ(element4, 0x0807);

  // There is no element at offset 4.
  uint32 no_element = 0;
  EXPECT_FALSE(decoded->GetElementAsUInteger(4, &no_element));
  EXPECT_EQ(no_element, 0);

  // Should not be able to decode an other value.
  EXPECT_FALSE(DecodeArray<ShortValue>("error", 1, &decoder, &fields));
}

TEST(EtwDecoderUtilsTest, DecodeUInteger32) {
  StructValue fields;
  Decoder decoder(&kSmallBuffer[0], kSmallBufferLength);
  EXPECT_TRUE(DecodeUInteger("test1", false, &decoder, &fields));
  EXPECT_TRUE(DecodeUInteger("test2", false, &decoder, &fields));

  uint32 test1 = 0;
  uint32 test2 = 0;
  EXPECT_TRUE(fields.GetFieldAsUInteger("test1", &test1));
  EXPECT_TRUE(fields.GetFieldAsUInteger("test2", &test2));
  EXPECT_EQ(test1, 0x04030201U);
  EXPECT_EQ(test2, 0x08070605U);

  // Should not be able to decode an other value.
  EXPECT_FALSE(DecodeUInteger("error", true, &decoder, &fields));
}

TEST(EtwDecoderUtilsTest, DecodeUInteger64) {
  StructValue fields;
  Decoder decoder(&kSmallBuffer[0], kSmallBufferLength);
  EXPECT_TRUE(DecodeUInteger("test", true, &decoder, &fields));

  uint64 test = 0;
  EXPECT_TRUE(fields.GetFieldAsULong("test", &test));
  EXPECT_EQ(test, 0x0807060504030201ULL);

  // Should not be able to decode an other value.
  EXPECT_FALSE(DecodeUInteger("error", true, &decoder, &fields));
}

TEST(EtwDecoderUtilsTest, DecodeString) {
  const char original[] = "This is a test.\0OK";
  StructValue fields;
  Decoder decoder(&original[0], sizeof(original));
  EXPECT_TRUE(Decode<StringValue>("test", &decoder, &fields));
  EXPECT_TRUE(Decode<StringValue>("answer", &decoder, &fields));

  std::string answer;
  EXPECT_TRUE(fields.GetFieldAsString("answer", &answer));
  EXPECT_STREQ("OK", answer.c_str());

  // Should not be able to decode an other value.
  EXPECT_FALSE(Decode<StringValue>("error", &decoder, &fields));
}

TEST(EtwDecoderUtilsTest, DecodeWString) {
  const char original[] = "t\0e\0s\0t\0.\0\0\0O\0K\0\0";
  StructValue fields;
  Decoder decoder(&original[0], sizeof(original));
  EXPECT_TRUE(DecodeW16String("test", &decoder, &fields));
  EXPECT_TRUE(DecodeW16String("answer", &decoder, &fields));

  std::string answer;
  EXPECT_TRUE(fields.GetFieldAsString("answer", &answer));
  EXPECT_STREQ("OK", answer.c_str());

  // Should not be able to decode an other value.
  EXPECT_FALSE(DecodeW16String("error", &decoder, &fields));
}

TEST(EtwDecoderUtilsTest, DecodeSID) {
  const char original_sid[] = {
      1, 2, 3, 4, 1, 2, 3, 4,
      5, 4, 3, 2, 0, 0, 0, 0,
      1, 5, 0, 0, 0, 0, 0, 5,
      21, 0, 0, 0, 1, 2, 3, 4,
      5, 6, 7, 8, 9, 10, 11, 12,
      13, 3, 0, 0 };

  Decoder decoder(&original_sid[0], sizeof(original_sid));
  StructValue fields;
  EXPECT_TRUE(DecodeSID("sid", true, &decoder, &fields));

  const StructValue* sid = NULL;
  EXPECT_TRUE(fields.GetFieldAs<StructValue>("sid", &sid));

  uint64 psid = 0;
  EXPECT_TRUE(sid->GetFieldAsULong("PSid", &psid));
  EXPECT_EQ(0x0403020104030201ULL, psid);

  uint32 attributes = 0;
  EXPECT_TRUE(sid->GetFieldAsUInteger("Attributes", &attributes));
  EXPECT_EQ(0x02030405, attributes);
}

}  // namespace etw
}  // namespace parser
