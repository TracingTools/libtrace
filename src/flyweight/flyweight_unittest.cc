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

#include "flyweight/flyweight.h"

#include "base/scoped_ptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace flyweight {

namespace {

using testing::Ref;
typedef Flyweight<int> TestedImpl;
typedef TestedImpl::KeyValuePair KeyValuePair;
typedef TestedImpl::Observer Observer;
typedef TestedImpl::ObserverKeys ObserverKeys;
typedef TestedImpl::ObserverValues ObserverValues;
typedef TestedImpl::Key Key;
typedef TestedImpl::Impl Impl;

template <typename T>
class DummyObserver : public base::Observer<T> {
 public:
  void Receive(const T&) const {
  }
};

class MockFlyweightImpl : public FlyweightImpl<int> {
 public:
  MOCK_METHOD1(Insert, const Key&(const int& value));
  MOCK_CONST_METHOD1(ValueOf, const int& (const Key& key));
  MOCK_CONST_METHOD1(Enumerate, void(const Observer& observer));
  MOCK_CONST_METHOD1(EnumerateKeys, void(const ObserverKeys& observer));
  MOCK_CONST_METHOD1(EnumerateValues, void(const ObserverValues& observer));
};

}  // namespace

TEST(FlyweightTest, Insert) {
  scoped_ptr<MockFlyweightImpl> impl(new MockFlyweightImpl());
  EXPECT_CALL(*impl.get(), Insert(testing::_))
      .WillRepeatedly(testing::ReturnRefOfCopy(Key(1)));

  TestedImpl flyweight(impl.PassAs<Impl>());
  flyweight.Insert(42);
}

TEST(FlyweightTest, ValueOf) {
  scoped_ptr<MockFlyweightImpl> impl(new MockFlyweightImpl());
  EXPECT_CALL(*impl.get(), ValueOf(testing::_))
      .WillRepeatedly(testing::ReturnRefOfCopy(1));

  TestedImpl flyweight(impl.PassAs<Impl>());
  Key key(42);
  flyweight.ValueOf(key);
}

TEST(FlyweightTest, Enumerate) {
  DummyObserver<KeyValuePair> observer;
  scoped_ptr<MockFlyweightImpl> impl(new MockFlyweightImpl());
  EXPECT_CALL(*impl.get(), Enumerate(Ref(observer)));

  TestedImpl flyweight(impl.PassAs<Impl>());
  flyweight.Enumerate(observer);
}

TEST(FlyweightTest, EnumerateKeys) {
  DummyObserver<Key> observer;
  scoped_ptr<MockFlyweightImpl> impl(new MockFlyweightImpl());
  EXPECT_CALL(*impl.get(), EnumerateKeys(Ref(observer)));

  TestedImpl flyweight(impl.PassAs<Impl>());
  flyweight.EnumerateKeys(observer);
}

TEST(FlyweightTest, EnumerateValues) {
  DummyObserver<int> observer;
  scoped_ptr<MockFlyweightImpl> impl(new MockFlyweightImpl());
  EXPECT_CALL(*impl.get(), EnumerateValues(Ref(observer)));

  TestedImpl flyweight(impl.PassAs<Impl>());
  flyweight.EnumerateValues(observer);
}

}  // namespace flyweight
