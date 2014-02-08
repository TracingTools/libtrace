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

#include <string>

#include "event/value.h"
#include "gtest/gtest.h"

namespace event {

namespace {

class IncrementOnDelete : public IntValue {
 public:
  IncrementOnDelete(int value, int* ptr)
      : IntValue(value), ptr_(ptr) {
  }
  ~IncrementOnDelete() { *ptr_ += 1; }
 private:
  int* ptr_;
};

}

TEST(ScalarValueTest, Accessors) {
  BoolValue value_bool(true);
  EXPECT_EQ(true, value_bool.GetValue());
  EXPECT_TRUE(value_bool.IsScalar());
  EXPECT_FALSE(value_bool.IsAggregate());
  EXPECT_TRUE(value_bool.IsInteger());
  EXPECT_FALSE(value_bool.IsSigned());
  EXPECT_FALSE(value_bool.IsFloating());

  IntValue char_value(42);
  EXPECT_EQ(42, char_value.GetValue());
  EXPECT_TRUE(char_value.IsScalar());
  EXPECT_FALSE(char_value.IsAggregate());
  EXPECT_TRUE(char_value.IsInteger());
  EXPECT_TRUE(char_value.IsSigned());
  EXPECT_FALSE(char_value.IsFloating());

  UIntValue uchar_value(42U);
  EXPECT_EQ(42U, uchar_value.GetValue());
  EXPECT_TRUE(uchar_value.IsScalar());
  EXPECT_FALSE(uchar_value.IsAggregate());
  EXPECT_TRUE(uchar_value.IsInteger());
  EXPECT_FALSE(uchar_value.IsSigned());
  EXPECT_FALSE(uchar_value.IsFloating());

  IntValue int_value(42);
  EXPECT_EQ(42, int_value.GetValue());
  EXPECT_TRUE(int_value.IsScalar());
  EXPECT_FALSE(int_value.IsAggregate());
  EXPECT_TRUE(int_value.IsInteger());
  EXPECT_TRUE(int_value.IsSigned());
  EXPECT_FALSE(int_value.IsFloating());

  UIntValue uint_value(42U);
  EXPECT_EQ(42U, uint_value.GetValue());
  EXPECT_TRUE(uint_value.IsScalar());
  EXPECT_FALSE(uint_value.IsAggregate());
  EXPECT_TRUE(uint_value.IsInteger());
  EXPECT_FALSE(uint_value.IsSigned());
  EXPECT_FALSE(uint_value.IsFloating());

  LongValue long_value(4200L);
  EXPECT_EQ(4200L, long_value.GetValue());
  EXPECT_TRUE(long_value.IsScalar());
  EXPECT_FALSE(long_value.IsAggregate());
  EXPECT_TRUE(long_value.IsInteger());
  EXPECT_TRUE(long_value.IsSigned());
  EXPECT_FALSE(long_value.IsFloating());

  ULongValue ulong_value(4200UL);
  EXPECT_EQ(4200UL, ulong_value.GetValue());
  EXPECT_TRUE(ulong_value.IsScalar());
  EXPECT_FALSE(ulong_value.IsAggregate());
  EXPECT_TRUE(ulong_value.IsInteger());
  EXPECT_FALSE(ulong_value.IsSigned());
  EXPECT_FALSE(ulong_value.IsFloating());

  StringValue str_value("dummy");
  EXPECT_STREQ("dummy", str_value.GetValue().c_str());
  EXPECT_TRUE(str_value.IsScalar());
  EXPECT_FALSE(str_value.IsAggregate());
  EXPECT_FALSE(str_value.IsInteger());
  EXPECT_FALSE(str_value.IsSigned());
  EXPECT_FALSE(str_value.IsFloating());

  std::wstring test_wstr(L"dummy");
  test_wstr.push_back(static_cast<wchar_t>(0x03b1));
  test_wstr.push_back(static_cast<wchar_t>(0x03b2));
  WStringValue wstr_value(test_wstr);
  EXPECT_STREQ(test_wstr.c_str(), wstr_value.GetValue().c_str());
  EXPECT_TRUE(wstr_value.IsScalar());
  EXPECT_FALSE(wstr_value.IsAggregate());
  EXPECT_FALSE(wstr_value.IsInteger());
  EXPECT_FALSE(wstr_value.IsSigned());
  EXPECT_FALSE(wstr_value.IsFloating());

  FloatValue float_value(.42f);
  EXPECT_FLOAT_EQ(.42f, float_value.GetValue());
  EXPECT_TRUE(float_value.IsScalar());
  EXPECT_FALSE(float_value.IsAggregate());
  EXPECT_FALSE(float_value.IsInteger());
  EXPECT_TRUE(float_value.IsSigned());
  EXPECT_TRUE(float_value.IsFloating());

  DoubleValue double_value(.42);
  EXPECT_DOUBLE_EQ(.42, double_value.GetValue());
  EXPECT_TRUE(double_value.IsScalar());
  EXPECT_FALSE(double_value.IsAggregate());
  EXPECT_FALSE(double_value.IsInteger());
  EXPECT_TRUE(double_value.IsSigned());
  EXPECT_TRUE(double_value.IsFloating());
}

TEST(ScalarValueTest, IsSigned) {
  BoolValue value_bool(true);
  LongValue long_value(42LL);
  ULongValue ulong_value(42ULL);
  ArrayValue array_value;
  EXPECT_FALSE(value_bool.IsSigned());
  EXPECT_TRUE(long_value.IsSigned());
  EXPECT_FALSE(ulong_value.IsSigned());
  EXPECT_FALSE(array_value.IsSigned());
}

TEST(ScalarValueTest, Limits) {
  EXPECT_FALSE(BoolValue::MinValue());
  EXPECT_TRUE(BoolValue::MaxValue());
  EXPECT_EQ(-0x7FFFFFFF - 1, IntValue::MinValue());
  EXPECT_EQ(0x7FFFFFFF, IntValue::MaxValue());
  EXPECT_EQ(0U, UIntValue::MinValue());
  EXPECT_EQ(0xFFFFFFFFU, UIntValue::MaxValue());
  EXPECT_EQ(-0x7FFFFFFFFFFFFFFFLL - 1, LongValue::MinValue());
  EXPECT_EQ(0x7FFFFFFFFFFFFFFFLL, LongValue::MaxValue());
  EXPECT_EQ(0ULL, ULongValue::MinValue());
  EXPECT_EQ(0xFFFFFFFFFFFFFFFFULL, ULongValue::MaxValue());
}

TEST(ScalarValueTest, GetAsInteger) {
  BoolValue bool_value(1);
  CharValue char_value(42);
  UCharValue uchar_value(42);
  ShortValue short_value(42);
  UShortValue ushort_value(42);
  UIntValue uint_value(42);
  IntValue int_value(42);
  LongValue long_value(42);
  ULongValue ulong_value(42U);
  DoubleValue double_value(.42);
  Value* value;
  int32 resut_value;

  value = &bool_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsInteger(&resut_value));
  EXPECT_EQ(1, resut_value);

  value = &char_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsInteger(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &uchar_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsInteger(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &short_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsInteger(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &ushort_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsInteger(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &int_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsInteger(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &uint_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsInteger(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &long_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsInteger(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &ulong_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsInteger(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &double_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsInteger(&resut_value));
  EXPECT_EQ(0, resut_value);
}

TEST(ScalarValueTest, GetAsIntegerWithULong) {
  ULongValue ulong_value1(0x000000007FFFFFFFULL);
  ULongValue ulong_value2(0xFFFFFFFFFFFFFFFFULL);
  int32 resut_value = 0;
  Value* value = &ulong_value1;
  EXPECT_TRUE(value->GetAsInteger(&resut_value));
  value = &ulong_value2;
  EXPECT_FALSE(value->GetAsInteger(&resut_value));
}

TEST(ScalarValueTest, GetAsUInteger) {
  BoolValue bool_value(1);
  CharValue char_value(42);
  UCharValue uchar_value(42);
  ShortValue short_value(42);
  UShortValue ushort_value(42);
  UIntValue uint_value(42);
  IntValue int_value(42);
  LongValue long_value(42);
  ULongValue ulong_value(42U);
  DoubleValue double_value(.42);
  Value* value;
  uint32 resut_value;

  value = &bool_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(1U, resut_value);

  value = &char_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &uchar_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &short_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &ushort_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &int_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &uint_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &long_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &ulong_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &double_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(0U, resut_value);
}

TEST(ScalarValueTest, GetAsUIntegerWithNegativeValue) {
  CharValue char_value(-1);
  ShortValue short_value(-1);
  IntValue int_value(-1);
  LongValue long_value(-1);
  Value* value;
  uint32 resut_value;

  value = &char_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(0U, resut_value);

  value = &short_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(0U, resut_value);

  value = &int_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(0U, resut_value);

  value = &long_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(0U, resut_value);
}

TEST(ScalarValueTest, GetAsUIntegerWithBigValue) {
  LongValue long_value(0x1FFFFFFFFLL);
  ULongValue ulong_value(0x1FFFFFFFFLL);
  Value* value;
  uint32 resut_value;

  value = &long_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(0U, resut_value);

  value = &ulong_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsUInteger(&resut_value));
  EXPECT_EQ(0U, resut_value);
}

TEST(ScalarValueTest, GetAsLong) {
  BoolValue bool_value(1);
  CharValue char_value(42);
  UCharValue uchar_value(42);
  ShortValue short_value(42);
  UShortValue ushort_value(42);
  UIntValue uint_value(42);
  IntValue int_value(42);
  LongValue long_value(42);
  LongValue ulong_value(42U);
  DoubleValue double_value(.42);
  Value* value;
  int64 resut_value;

  value = &bool_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsLong(&resut_value));
  EXPECT_EQ(1, resut_value);

  value = &char_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsLong(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &uchar_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsLong(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &short_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsLong(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &ushort_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsLong(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &int_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsLong(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &uint_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsLong(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &long_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsLong(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &ulong_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsLong(&resut_value));
  EXPECT_EQ(42, resut_value);

  value = &double_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsLong(&resut_value));
  EXPECT_EQ(0, resut_value);
}

TEST(ScalarValueTest, GetAsLongWithBigValue) {
  ULongValue ulong_value1(0x7FFFFFFFFFFFFFFFULL);
  ULongValue ulong_value2(0xFFFFFFFFFFFFFFFFULL);
  int64 resut_value = 0;
  Value* value = &ulong_value1;
  EXPECT_TRUE(value->GetAsLong(&resut_value));
  value = &ulong_value2;
  EXPECT_FALSE(value->GetAsLong(&resut_value));
}

TEST(ScalarValueTest, GetAsULong) {
  BoolValue bool_value(1);
  CharValue char_value(42);
  UCharValue uchar_value(42);
  ShortValue short_value(42);
  UShortValue ushort_value(42);
  UIntValue uint_value(42);
  IntValue int_value(42);
  LongValue long_value(42);
  ULongValue ulong_value(42U);
  DoubleValue double_value(.42);
  Value* value;
  uint64 resut_value;

  value = &bool_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsULong(&resut_value));
  EXPECT_EQ(1U, resut_value);

  value = &char_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsULong(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &uchar_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsULong(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &short_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsULong(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &ushort_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsULong(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &int_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsULong(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &uint_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsULong(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &long_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsULong(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &ulong_value;
  resut_value = 0;
  EXPECT_TRUE(value->GetAsULong(&resut_value));
  EXPECT_EQ(42U, resut_value);

  value = &double_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsULong(&resut_value));
  EXPECT_EQ(0U, resut_value);
}

TEST(ScalarValueTest, GetAsULongWithNegativeValue) {
  CharValue char_value(-1);
  ShortValue short_value(-1);
  IntValue int_value(-1);
  LongValue long_value(-1);
  Value* value;
  uint64 resut_value;

  value = &char_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsULong(&resut_value));
  EXPECT_EQ(0U, resut_value);

  value = &short_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsULong(&resut_value));
  EXPECT_EQ(0U, resut_value);

  value = &int_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsULong(&resut_value));
  EXPECT_EQ(0U, resut_value);

  value = &long_value;
  resut_value = 0;
  EXPECT_FALSE(value->GetAsULong(&resut_value));
  EXPECT_EQ(0U, resut_value);
}

TEST(ScalarValueTest, GetAsFloating) {
  CharValue char_value(42);
  IntValue int_value(42);
  FloatValue float_value(.42f);
  DoubleValue double_value(.42);
  Value* value;
  double result_value;

  value = &char_value;
  result_value = 0;
  EXPECT_FALSE(value->GetAsFloating(&result_value));
  EXPECT_EQ(0U, result_value);

  value = &int_value;
  result_value = 0;
  EXPECT_FALSE(value->GetAsFloating(&result_value));
  EXPECT_EQ(0U, result_value);

  value = &float_value;
  result_value = 0;
  EXPECT_TRUE(value->GetAsFloating(&result_value));
  EXPECT_NEAR(.42, result_value, 0.000001);

  value = &double_value;
  result_value = 0;
  EXPECT_TRUE(value->GetAsFloating(&result_value));
  EXPECT_DOUBLE_EQ(.42, result_value);
}

TEST(ScalarValueTest, GetAsString) {
  StringValue string_value("42");
  WStringValue wstring_value(L"42");
  DoubleValue double_value(.42);
  Value* value;
  std::string result_value;

  value = &string_value;
  result_value = "";
  EXPECT_TRUE(value->GetAsString(&result_value));
  EXPECT_STREQ("42", result_value.c_str());

  value = &wstring_value;
  result_value = "";
  EXPECT_TRUE(value->GetAsString(&result_value));
  EXPECT_STREQ("42", result_value.c_str());

  value = &double_value;
  result_value = "";
  EXPECT_FALSE(value->GetAsString(&result_value));
  EXPECT_STREQ("", result_value.c_str());
}

TEST(ScalarValueTest, GetAsWString) {
  StringValue string_value("42");
  WStringValue wstring_value(L"42");
  DoubleValue double_value(.42);
  Value* value;
  std::wstring result_value;

  value = &string_value;
  result_value = L"";
  EXPECT_TRUE(value->GetAsWString(&result_value));
  EXPECT_STREQ(L"42", result_value.c_str());

  value = &wstring_value;
  result_value = L"";
  EXPECT_TRUE(value->GetAsWString(&result_value));
  EXPECT_STREQ(L"42", result_value.c_str());

  value = &double_value;
  result_value = L"";
  EXPECT_FALSE(value->GetAsWString(&result_value));
  EXPECT_STREQ(L"", result_value.c_str());
}

TEST(ScalarValueTest, InstanceOf) {
  LongValue value_long(4L);
  IntValue int_long(4);
  Value* value;

  value = &value_long;
  EXPECT_TRUE(LongValue::InstanceOf(value));
  EXPECT_FALSE(IntValue::InstanceOf(value));

  value = &int_long;
  EXPECT_FALSE(LongValue::InstanceOf(value));
  EXPECT_TRUE(IntValue::InstanceOf(value));
}

TEST(ScalarValueTest, Cast) {
  LongValue value_long(4L);
  const Value* value = &value_long;
  const LongValue* casted_value = LongValue::Cast(value);

  EXPECT_EQ(&value_long, casted_value);
}

TEST(ScalarValueTest, GetValue) {
  LongValue value_long(4L);
  const Value* value = &value_long;

  EXPECT_EQ(4L, LongValue::GetValue(value));
}

TEST(ScalarValueTest, GetValueSafe) {
  LongValue value_long(4L);
  const Value* value = &value_long;

  int64 raw_long_value = 0;
  EXPECT_TRUE(LongValue::GetValue(value, &raw_long_value));
  EXPECT_EQ(4L, raw_long_value);

  int32 raw_int_value = 0;
  EXPECT_FALSE(IntValue::GetValue(value, &raw_int_value));
  EXPECT_EQ(0, raw_int_value);
}

TEST(ScalarValueTest, Equals) {
  LongValue value_long1(4L);
  LongValue value_long2(4L);
  LongValue value_long3(-4L);
  IntValue value_long4(4L);
  EXPECT_TRUE(value_long1.Equals(&value_long2));
  EXPECT_FALSE(value_long1.Equals(&value_long3));
  EXPECT_FALSE(value_long1.Equals(&value_long4));
  EXPECT_FALSE(value_long1.Equals(NULL));
}

TEST(ArrayValueTest, Constructor) {
  ArrayValue value;
  EXPECT_EQ(0UL, value.Length());
}

TEST(ArrayValueTest, Accessors) {
  ArrayValue value;
  EXPECT_TRUE(value.IsAggregate());
  EXPECT_FALSE(value.IsScalar());
  EXPECT_FALSE(value.IsInteger());
  EXPECT_FALSE(value.IsFloating());
}

TEST(ArrayValueTest, Operations) {
  ArrayValue value;
  EXPECT_TRUE(value.IsEmpty());
  value.Append<IntValue>(42);
  EXPECT_FALSE(value.IsEmpty());
  value.Append<IntValue>(43);
  EXPECT_EQ(2U, value.Length());

  EXPECT_EQ(42, IntValue::Cast(value[0])->GetValue());
  EXPECT_EQ(43, IntValue::Cast(value[1])->GetValue());

  const ArrayValue& const_value = value;
  EXPECT_EQ(42, IntValue::Cast(const_value[0])->GetValue());
  EXPECT_EQ(43, IntValue::Cast(const_value[1])->GetValue());
}

TEST(ArrayValueTest, Iterate) {
  scoped_ptr<Value> v1(new IntValue(42));
  scoped_ptr<Value> v2(new IntValue(43));
  scoped_ptr<Value> v3(new IntValue(44));
  Value* v1_raw = v1.get();
  Value* v2_raw = v2.get();
  Value* v3_raw = v3.get();

  ArrayValue value;
  value.Append(v1.Pass());
  value.Append(v2.Pass());
  value.Append(v3.Pass());

  ArrayValue::const_iterator it = value.values_begin();
  EXPECT_EQ(v1_raw, *it);
  ++it;
  EXPECT_EQ(v2_raw, *it);
  ++it;
  EXPECT_EQ(v3_raw, *it);
  ++it;
  EXPECT_TRUE(it == value.values_end());
}

TEST(ArrayValueTest, Instanceof) {
  ArrayValue value;

  EXPECT_FALSE(IntValue::InstanceOf(&value));
  EXPECT_TRUE(ArrayValue::InstanceOf(&value));
  EXPECT_FALSE(StructValue::InstanceOf(&value));
}

TEST(ArrayValueTest, Cast) {
  ArrayValue array_value;
  EXPECT_EQ(&array_value, ArrayValue::Cast(&array_value));
}

TEST(ArrayValueTest, Equals) {
  IntValue int_value(42);

  ArrayValue array_value1;
  array_value1.Append<IntValue>(42);
  array_value1.Append<IntValue>(43);
  array_value1.Append<IntValue>(44);

  ArrayValue array_value2;
  int32 values[] = { 42, 43, 44 };
  array_value2.AppendAll<IntValue>(&values[0], 3);
  ArrayValue array_value3;
  array_value3.AppendAll<IntValue>(&values[0], 2);
  ArrayValue array_value4;
  array_value4.AppendAll<IntValue>(&values[1], 2);

  EXPECT_FALSE(array_value1.Equals(NULL));
  EXPECT_FALSE(array_value1.Equals(&int_value));
  EXPECT_TRUE(array_value1.Equals(&array_value2));
  EXPECT_FALSE(array_value1.Equals(&array_value3));
  EXPECT_FALSE(array_value3.Equals(&array_value4));
}

TEST(ArrayValueTest, Append) {
  ArrayValue array_value;
  scoped_ptr<Value> v1(new IntValue(42));
  scoped_ptr<Value> v2(new IntValue(43));

  array_value.Append(v1.Pass());
  EXPECT_EQ(1, array_value.Length());
  array_value.Append(v2.Pass());
  EXPECT_EQ(2, array_value.Length());
  array_value.Append<IntValue>(44);
  EXPECT_EQ(3, array_value.Length());
}

TEST(ArrayValueTest, At) {
  ArrayValue array_value;
  int32 values[] = { 42, 43, 44 };
  array_value.AppendAll<IntValue>(&values[0], 3);

  ArrayValue* ptr = &array_value;
  EXPECT_EQ(42, IntValue::Cast(ptr->at(0))->GetValue());
  EXPECT_EQ(43, IntValue::Cast(ptr->at(1))->GetValue());
  EXPECT_EQ(44, IntValue::Cast(ptr->at(2))->GetValue());

  const ArrayValue* const_ptr = &array_value;
  EXPECT_EQ(42, IntValue::Cast(const_ptr->at(0))->GetValue());
  EXPECT_EQ(43, IntValue::Cast(const_ptr->at(1))->GetValue());
  EXPECT_EQ(44, IntValue::Cast(const_ptr->at(2))->GetValue());
}

TEST(ArrayValueTest, GetElementAs) {
  ArrayValue array_value;

  array_value.Append<IntValue>(42);
  array_value.Append<UIntValue>(43);
  array_value.Append<LongValue>(44);
  array_value.Append<ULongValue>(45);
  array_value.Append<DoubleValue>(0.5);
  array_value.Append<StringValue>("dummy");
  array_value.Append<WStringValue>(L"dummy");

  const IntValue* raw_value = NULL;
  const UIntValue* raw_uvalue = NULL;
  EXPECT_FALSE(array_value.GetElementAs<IntValue>(1000, &raw_value));
  EXPECT_TRUE(array_value.GetElementAs<IntValue>(0, &raw_value));
  EXPECT_FALSE(array_value.GetElementAs<UIntValue>(0, &raw_uvalue));

  int32 int_value = 0;
  EXPECT_FALSE(array_value.GetElementAsInteger(1000, &int_value));
  EXPECT_EQ(0, int_value);
  EXPECT_TRUE(array_value.GetElementAsInteger(0, &int_value));
  EXPECT_EQ(42, int_value);

  uint32 uint_value = 0;
  EXPECT_FALSE(array_value.GetElementAsUInteger(1000, &uint_value));
  EXPECT_EQ(0, uint_value);
  EXPECT_TRUE(array_value.GetElementAsUInteger(1, &uint_value));
  EXPECT_EQ(43, uint_value);

  int64 long_value = 0;
  EXPECT_FALSE(array_value.GetElementAsLong(1000, &long_value));
  EXPECT_EQ(0LL, long_value);
  EXPECT_TRUE(array_value.GetElementAsLong(2, &long_value));
  EXPECT_EQ(44LL, long_value);

  uint64 ulong_value = 0;
  EXPECT_FALSE(array_value.GetElementAsULong(1000, &ulong_value));
  EXPECT_EQ(0ULL, ulong_value);
  EXPECT_TRUE(array_value.GetElementAsULong(3, &ulong_value));
  EXPECT_EQ(45ULL, ulong_value);

  double float_value = 0;
  EXPECT_FALSE(array_value.GetElementAsFloating(1000, &float_value));
  EXPECT_EQ(0, float_value);
  EXPECT_TRUE(array_value.GetElementAsFloating(4, &float_value));
  EXPECT_EQ(0.5, float_value);

  std::string str_value;
  EXPECT_FALSE(array_value.GetElementAsString(1000, &str_value));
  EXPECT_TRUE(str_value.empty());
  EXPECT_TRUE(array_value.GetElementAsString(5, &str_value));
  EXPECT_TRUE(str_value == "dummy");

  std::wstring wstr_value;
  EXPECT_FALSE(array_value.GetElementAsWString(1000, &wstr_value));
  EXPECT_TRUE(wstr_value.empty());
  EXPECT_TRUE(array_value.GetElementAsWString(6, &wstr_value));
  EXPECT_TRUE(wstr_value == L"dummy");
}

TEST(ArrayValueTest, Destructor) {
  int count = 0;
  {
    ArrayValue value;
    scoped_ptr<Value> field1(new IncrementOnDelete(41, &count));
    value.Append(field1.Pass());
    scoped_ptr<Value> field2(new IncrementOnDelete(42, &count));
    value.Append(field2.Pass());
    scoped_ptr<Value> field3(new IncrementOnDelete(43, &count));
    value.Append(field3.Pass());
    EXPECT_EQ(0, count);
  }
  EXPECT_EQ(3, count);
}

TEST(StructValueTest, Accessors) {
  StructValue value;
  EXPECT_TRUE(value.IsAggregate());
  EXPECT_FALSE(value.IsScalar());
  EXPECT_FALSE(value.IsInteger());
  EXPECT_FALSE(value.IsFloating());
}

TEST(StructValueTest, Operations) {
  StructValue value;
  const StructValue* const_value = &value;

  EXPECT_FALSE(value.HasField("field"));

  scoped_ptr<Value> field(new IntValue(42));
  Value* raw_field = field.get();
  EXPECT_TRUE(value.AddField("field", field.Pass()));
  EXPECT_TRUE(value.HasField("field"));
  EXPECT_FALSE(value.AddField<IntValue>("field", 42));

  EXPECT_EQ(raw_field, value.GetField("field"));

  const Value* retrieved = NULL;
  EXPECT_TRUE(value.GetField("field", &retrieved));
  EXPECT_EQ(raw_field, retrieved);

  retrieved = NULL;
  EXPECT_FALSE(value.GetField("field_dummy", &retrieved));
  EXPECT_EQ(NULL, retrieved);

  EXPECT_EQ(NULL, const_value->GetField("field_dummy"));
}

TEST(StructValueTest, AddFieldTakesOwnership) {
  StructValue value;
  EXPECT_FALSE(value.HasField("field"));

  scoped_ptr<Value> field(new IntValue(42));
  EXPECT_TRUE(value.AddField("field", field.Pass()));
  EXPECT_TRUE(value.HasField("field"));
  EXPECT_EQ(NULL, field.get());

  scoped_ptr<Value> other(new IntValue(24));
  EXPECT_FALSE(value.AddField("field", other.Pass()));
  EXPECT_EQ(NULL, other.get());
}

TEST(StructValueTest, Iterate) {
  scoped_ptr<Value> v1(new IntValue(42));
  scoped_ptr<Value> v2(new IntValue(43));
  scoped_ptr<Value> v3(new IntValue(44));
  Value* raw_v1 = v1.get();
  Value* raw_v2 = v2.get();
  Value* raw_v3 = v3.get();

  StructValue value;
  value.AddField("field1", v1.Pass());
  value.AddField("field2", v2.Pass());
  value.AddField("field3", v3.Pass());

  StructValue::const_iterator it = value.fields_begin();
  EXPECT_STREQ("field1", it->first.c_str());
  EXPECT_EQ(raw_v1, it->second);
  ++it;
  EXPECT_STREQ("field2", it->first.c_str());
  EXPECT_EQ(raw_v2, it->second);
  ++it;
  EXPECT_STREQ("field3", it->first.c_str());
  EXPECT_EQ(raw_v3, it->second);
  ++it;
  EXPECT_TRUE(it == value.fields_end());
}

TEST(StructValueTest, Instanceof) {
  StructValue value;

  EXPECT_FALSE(IntValue::InstanceOf(&value));
  EXPECT_FALSE(ArrayValue::InstanceOf(&value));
  EXPECT_TRUE(StructValue::InstanceOf(&value));
}

TEST(StructValueTest, Equals) {
  IntValue int_value(42);

  StructValue left;
  StructValue right1;
  StructValue right2;

  EXPECT_FALSE(left.Equals(NULL));
  EXPECT_FALSE(left.Equals(&int_value));
  EXPECT_TRUE(left.Equals(&right1));

  left.AddField<IntValue>("field1", 42);
  EXPECT_FALSE(left.Equals(&right1));

  right1.AddField<IntValue>("field1", 42);
  EXPECT_TRUE(left.Equals(&right1));

  right2.AddField<IntValue>("field1", 43);
  EXPECT_FALSE(left.Equals(&right2));

  left.AddField<IntValue>("field2", 44);
  right1.AddField<IntValue>("dummy", 44);
  EXPECT_FALSE(left.Equals(&right1));
}

TEST(StructValueTest, GetFieldAs) {
  StructValue struct_value;
  struct_value.AddField<LongValue>("integer", 42);
  struct_value.AddField<DoubleValue>("float", 0.5);
  struct_value.AddField<StringValue>("string", "dummy");

  const LongValue* raw_value = NULL;
  EXPECT_FALSE(struct_value.GetFieldAs<LongValue>("string", &raw_value));
  EXPECT_FALSE(struct_value.GetFieldAs<LongValue>("no_field", &raw_value));
  EXPECT_TRUE(struct_value.GetFieldAs<LongValue>("integer", &raw_value));

  int32 int_value = 0;
  EXPECT_TRUE(struct_value.GetFieldAsInteger("integer", &int_value));
  EXPECT_FALSE(struct_value.GetFieldAsInteger("string", &int_value));
  EXPECT_FALSE(struct_value.GetFieldAsInteger("no_field", &int_value));

  uint32 uint_value = 0;
  EXPECT_TRUE(struct_value.GetFieldAsUInteger("integer", &uint_value));
  EXPECT_FALSE(struct_value.GetFieldAsUInteger("string", &uint_value));
  EXPECT_FALSE(struct_value.GetFieldAsUInteger("no_field", &uint_value));

  int64 long_value = 0;
  EXPECT_TRUE(struct_value.GetFieldAsLong("integer", &long_value));
  EXPECT_FALSE(struct_value.GetFieldAsLong("string", &long_value));
  EXPECT_FALSE(struct_value.GetFieldAsLong("no_field", &long_value));

  uint64 ulong_value = 0;
  EXPECT_TRUE(struct_value.GetFieldAsULong("integer", &ulong_value));
  EXPECT_FALSE(struct_value.GetFieldAsULong("string", &ulong_value));
  EXPECT_FALSE(struct_value.GetFieldAsULong("no_field", &ulong_value));

  double float_value = 0;
  EXPECT_TRUE(struct_value.GetFieldAsFloating("float", &float_value));
  EXPECT_FALSE(struct_value.GetFieldAsFloating("string", &float_value));
  EXPECT_FALSE(struct_value.GetFieldAsFloating("no_field", &float_value));

  std::string string_value;
  EXPECT_TRUE(struct_value.GetFieldAsString("string", &string_value));
  EXPECT_FALSE(struct_value.GetFieldAsString("integer", &string_value));
  EXPECT_FALSE(struct_value.GetFieldAsString("no_field", &string_value));

  std::wstring wstring_value;
  EXPECT_TRUE(struct_value.GetFieldAsWString("string", &wstring_value));
  EXPECT_FALSE(struct_value.GetFieldAsWString("integer", &wstring_value));
  EXPECT_FALSE(struct_value.GetFieldAsWString("no_field", &wstring_value));
}

TEST(StructValueTest, Destructor) {
  int count = 0;
  {
    StructValue value;
    scoped_ptr<Value> field1(new IncrementOnDelete(41, &count));
    EXPECT_TRUE(value.AddField("field1", field1.Pass()));
    scoped_ptr<Value> field2(new IncrementOnDelete(42, &count));
    EXPECT_TRUE(value.AddField("field2", field2.Pass()));
    scoped_ptr<Value> field3(new IncrementOnDelete(43, &count));
    EXPECT_TRUE(value.AddField("field3", field3.Pass()));
    EXPECT_EQ(0, count);
  }
  EXPECT_EQ(3, count);
}

}  // namespace event
