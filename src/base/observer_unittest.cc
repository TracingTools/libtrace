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

#include "base/observer.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace base {

namespace {

using testing::Ref;

struct Dummy { };

class MockObserver {
 public:
  // The value_type definition simulates the interface of an STL container.
  typedef Dummy value_type;
  MOCK_METHOD1(push_back, void(const Dummy&));
  MOCK_METHOD1(push_front, void(const Dummy&));
  MOCK_CONST_METHOD1(Receive, void(const Dummy&));
  MOCK_METHOD1(Process, void(const Dummy&));
  MOCK_CONST_METHOD1(ConstProcess, void(const Dummy&));
};

typedef CallbackObserver<MockObserver, Dummy> Callback;

}  // namespace

TEST(ObserverTest, Receive) {
  Dummy a;
  MockObserver observer;
  EXPECT_CALL(observer, Receive(Ref(a)));
  observer.Receive(a);
}

TEST(ObserverTest, CallbackObserver) {
  Dummy a;
  MockObserver observer;
  Callback callback = MakeObserver(&observer, &MockObserver::Process);
  EXPECT_CALL(observer, Process(Ref(a)));
  callback.Receive(a);
}

TEST(ObserverTest, CallbackObserverWithConstBinding) {
  Dummy a;
  MockObserver observer;
  Callback callback = MakeObserver(&observer, &MockObserver::ConstProcess);
  EXPECT_CALL(observer, ConstProcess(Ref(a)));
  callback.Receive(a);
}

TEST(ObserverTest, BackInserter) {
  Dummy a;
  MockObserver observer;
  Callback callback = BackInserter(&observer);
  EXPECT_CALL(observer, push_back(Ref(a)));
  callback.Receive(a);
}

TEST(ObserverTest, FrontInserter) {
  Dummy a;
  MockObserver observer;
  Callback callback = FrontInserter(&observer);
  EXPECT_CALL(observer, push_front(Ref(a)));
  callback.Receive(a);
}

}  // namespace base
