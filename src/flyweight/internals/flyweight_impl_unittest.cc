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
// Tests the properties that are common to all implementations of Flyweight.

#include "flyweight/internals/flyweight_tree_map_impl.h"

#include <string>
#include <utility>

#include "base/base.h"
#include "base/observer.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace flyweight {
namespace internals {

namespace {

typedef FlyweightKey<int> IntKey;
typedef FlyweightKey<std::string> StringKey;

class MockObserver {
 public:
  MockObserver() {}
  // This is a workaround for an issue with gmock and std::pair on MSVC.
  // See https://code.google.com/p/googlemock/issues/detail?id=158.
  void ObserveInt(const Flyweight<int>::KeyValuePair& pair) {
    ObserveIntMock(pair.first, pair.second);
  }
  void ObserveString(const Flyweight<std::string>::KeyValuePair& pair) {
    ObserveStringMock(pair.first, pair.second);
  }

  MOCK_METHOD2(ObserveIntMock, void(const IntKey&, const int&));
  MOCK_METHOD2(ObserveStringMock, void(const StringKey&, const std::string&));
  MOCK_METHOD1(ObserveKeysInt, void(const IntKey&));
  MOCK_METHOD1(ObserveValuesInt, void(const int&));
  MOCK_METHOD1(ObserveKeysString, void(const StringKey&));
  MOCK_METHOD1(ObserveValuesString, void(const std::string&));

 private:
  DISALLOW_COPY_AND_ASSIGN(MockObserver);
};

// Carries the types for the int and std::string instantiations of a tested
// Flyweight implementation.
template <typename T1, typename T2>
struct FlyweightImpl {
  typedef T1 Int;
  typedef T2 String;
};

template <typename T>
class FlyweightImplTest : public testing::Test {
};

}  // namespace

// The tests will be executed for all Flyweight implementations specified here.
typedef ::testing::Types<
    FlyweightImpl<FlyweightTreeMapImpl<int>, FlyweightTreeMapImpl<std::string> >
    > FlyweightImplementations;

TYPED_TEST_CASE(FlyweightImplTest, FlyweightImplementations);

TYPED_TEST(FlyweightImplTest, InsertInt) {
  typename TypeParam::Int impl;

  IntKey one = impl.Insert(1);
  IntKey two = impl.Insert(2);

  IntKey other_one = impl.Insert(1);
  IntKey other_two = impl.Insert(2);

  EXPECT_EQ(one, other_one);
  EXPECT_EQ(two, other_two);
}

TYPED_TEST(FlyweightImplTest, InsertString) {
  typename TypeParam::String impl;

  StringKey one = impl.Insert("one");
  StringKey two = impl.Insert("two");

  StringKey other_one = impl.Insert("one");
  StringKey other_two = impl.Insert("two");

  EXPECT_EQ(one, other_one);
  EXPECT_EQ(two, other_two);
}

TYPED_TEST(FlyweightImplTest, InsertManyElements) {
  typename TypeParam::Int impl;
  std::vector<IntKey> keys;

  for (int i = 0; i < 250; ++i)
    keys.push_back(impl.Insert(i));

  for (int i = 0; i < 250; ++i) {
    IntKey other_key = impl.Insert(i);
    ASSERT_EQ(keys.at(i), other_key);
  }
}

TYPED_TEST(FlyweightImplTest, ValueOfInt) {
  typename TypeParam::Int impl;

  IntKey one = impl.Insert(1);
  IntKey two = impl.Insert(2);

  int value_one = impl.ValueOf(one);
  int value_two = impl.ValueOf(two);

  EXPECT_EQ(1, value_one);
  EXPECT_EQ(2, value_two);
}

TYPED_TEST(FlyweightImplTest, ValueOfString) {
  typename TypeParam::String impl;

  StringKey one = impl.Insert("one");
  StringKey two = impl.Insert("two");

  std::string value_one = impl.ValueOf(one);
  std::string value_two = impl.ValueOf(two);

  EXPECT_EQ("one", value_one);
  EXPECT_EQ("two", value_two);
}

TYPED_TEST(FlyweightImplTest, EnumerateInt) {
  typename TypeParam::Int impl;
  MockObserver observer;

  IntKey k1 = impl.Insert(1);
  IntKey k2 = impl.Insert(2);
  IntKey k3 = impl.Insert(3);

  EXPECT_CALL(observer, ObserveIntMock(k1, 1));
  EXPECT_CALL(observer, ObserveIntMock(k2, 2));
  EXPECT_CALL(observer, ObserveIntMock(k3, 3));

  impl.Enumerate(base::MakeObserver(&observer, &MockObserver::ObserveInt));
}

TYPED_TEST(FlyweightImplTest, EnumerateString) {
  typename TypeParam::String impl;
  MockObserver observer;

  StringKey k1 = impl.Insert("one");
  StringKey k2 = impl.Insert("two");
  StringKey k3 = impl.Insert("three");

  EXPECT_CALL(observer, ObserveStringMock(k1, "one"));
  EXPECT_CALL(observer, ObserveStringMock(k2, "two"));
  EXPECT_CALL(observer, ObserveStringMock(k3, "three"));

  impl.Enumerate(base::MakeObserver(&observer, &MockObserver::ObserveString));
}

TYPED_TEST(FlyweightImplTest, EnumerateKeysInt) {
  typename TypeParam::Int impl;
  MockObserver observer;

  IntKey k1 = impl.Insert(1);
  IntKey k2 = impl.Insert(2);
  IntKey k3 = impl.Insert(3);

  EXPECT_CALL(observer, ObserveKeysInt(k1));
  EXPECT_CALL(observer, ObserveKeysInt(k2));
  EXPECT_CALL(observer, ObserveKeysInt(k3));

  impl.EnumerateKeys(
      base::MakeObserver(&observer, &MockObserver::ObserveKeysInt));
}

TYPED_TEST(FlyweightImplTest, EnumerateKeysString) {
  typename TypeParam::String impl;
  MockObserver observer;

  StringKey k1 = impl.Insert("one");
  StringKey k2 = impl.Insert("two");
  StringKey k3 = impl.Insert("three");

  EXPECT_CALL(observer, ObserveKeysString(k1));
  EXPECT_CALL(observer, ObserveKeysString(k2));
  EXPECT_CALL(observer, ObserveKeysString(k3));

  impl.EnumerateKeys(
      base::MakeObserver(&observer, &MockObserver::ObserveKeysString));
}

TYPED_TEST(FlyweightImplTest, EnumerateValuesInt) {
  typename TypeParam::Int impl;
  MockObserver observer;

  impl.Insert(1);
  impl.Insert(2);
  impl.Insert(3);

  EXPECT_CALL(observer, ObserveValuesInt(1));
  EXPECT_CALL(observer, ObserveValuesInt(2));
  EXPECT_CALL(observer, ObserveValuesInt(3));

  impl.EnumerateValues(
      base::MakeObserver(&observer, &MockObserver::ObserveValuesInt));
}

TYPED_TEST(FlyweightImplTest, EnumerateValuesString) {
  typename TypeParam::String impl;
  MockObserver observer;

  impl.Insert("one");
  impl.Insert("two");
  impl.Insert("three");

  EXPECT_CALL(observer, ObserveValuesString("one"));
  EXPECT_CALL(observer, ObserveValuesString("two"));
  EXPECT_CALL(observer, ObserveValuesString("three"));

  impl.EnumerateValues(
      base::MakeObserver(&observer, &MockObserver::ObserveValuesString));
}

}  // namespace internals
}  // namespace flyweight
