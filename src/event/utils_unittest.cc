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

#include "event/utils.h"
#include "event/value.h"
#include "gtest/gtest.h"

namespace event {

TEST(EventToStringTest, ScalarType) {
  IntValue int_value(-42);
  std::string int_str;
  EXPECT_TRUE(ToString(&int_value, &int_str));
  EXPECT_STREQ("-42", int_str.c_str());

  UIntValue uint_value(42);
  std::string uint_str;
  EXPECT_TRUE(ToString(&uint_value, &uint_str));
  EXPECT_STREQ("42", uint_str.c_str());

  LongValue long_value(-42);
  std::string long_str;
  EXPECT_TRUE(ToString(&long_value, &long_str));
  EXPECT_STREQ("-42", long_str.c_str());

  ULongValue ulong_value(42);
  std::string ulong_str;
  EXPECT_TRUE(ToString(&ulong_value, &ulong_str));
  EXPECT_STREQ("42", ulong_str.c_str());

  FloatValue float_value(.5);
  std::string float_str;
  EXPECT_TRUE(ToString(&float_value, &float_str));
  EXPECT_STREQ("0.5", float_str.c_str());

  DoubleValue double_value(.25);
  std::string double_str;
  EXPECT_TRUE(ToString(&double_value, &double_str));
  EXPECT_STREQ("0.25", double_str.c_str());

  StringValue string_value("dummy");
  std::string string_str;
  EXPECT_TRUE(ToString(&string_value, &string_str));
  EXPECT_STREQ("\"dummy\"", string_str.c_str());
}

TEST(EventToStringTest, ArrayType) {
  ArrayValue array_value;
  array_value.Append<IntValue>(12);
  array_value.Append<IntValue>(13);
  array_value.Append<IntValue>(14);

  std::string array_str;
  EXPECT_TRUE(ToString(&array_value, &array_str));

  const char* expected = "[\n    12\n    13\n    14\n]";
  EXPECT_STREQ(expected, array_str.c_str());
}

TEST(EventToStringTest, StructType) {
  StructValue struct_value;
  struct_value.AddField<IntValue>("field", 12);
  struct_value.AddField<IntValue>("other", 13);
  struct_value.AddField<IntValue>("dummy", 14);

  std::string struct_str;
  EXPECT_TRUE(ToString(&struct_value, &struct_str));

  const char* expected = "{\n    field = 12\n    other = 13\n    dummy = 14\n}";
  EXPECT_STREQ(expected, struct_str.c_str());
}

TEST(EventToStringTest, Event) {
  scoped_ptr<StructValue> payload(new StructValue());
  payload->AddField<IntValue>("field", 12);
  Event event(42, payload.PassAs<const Value>());

  std::string event_str;
  EXPECT_TRUE(ToString(event, &event_str));

  const char* expected = "[42] event {\n    field = 12\n}";
  EXPECT_STREQ(expected, event_str.c_str());
}

}  // namespace event
