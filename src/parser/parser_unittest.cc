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

#include "parser/parser.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace parser {

namespace {

using testing::_;
using testing::Ref;
using testing::Return;

class MockParser : public parser::ParserImpl {
 public:
  MOCK_METHOD1(AddTraceFile, bool(const std::string&));
  MOCK_METHOD1(Parse, void(const base::Observer<event::Event>& observer));
};

class MockObserver : public base::Observer<event::Event> {
 public:
  MOCK_CONST_METHOD1(Receive, void(const event::Event& event));
};

}  // namespace

TEST(ParserTest, AddTraceFileWithoutParser) {
  parser::Parser parser;
  EXPECT_FALSE(parser.AddTraceFile("do_not_exist"));
}

TEST(ParserTest, Parse) {
  parser::Parser parser;
  MockObserver observer;

  scoped_ptr<MockParser> impl(new MockParser());
  std::string filename("dummy");

  EXPECT_CALL(*impl.get(), AddTraceFile(Ref(filename)))
     .WillOnce(Return(true));
  EXPECT_CALL(*impl.get(), Parse(Ref(observer)));

  parser.RegisterParser(impl.PassAs<parser::ParserImpl>());
  EXPECT_TRUE(parser.AddTraceFile(filename));

  parser.Parse(observer);
}

}  // namespace parser
