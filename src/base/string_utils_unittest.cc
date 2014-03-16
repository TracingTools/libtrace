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

#include "base/string_utils.h"
#include "gtest/gtest.h"

namespace base {

TEST(StringUtilsTest, StringToWString) {
  std::string str("dummy");
  std::wstring converted = StringToWString(str);
  EXPECT_EQ(0, converted.compare(L"dummy"));
}

TEST(StringUtilsTest, WStringToString) {
  std::wstring str(L"dummy");
  std::string converted = WStringToString(str);
  EXPECT_EQ(0, converted.compare("dummy"));
}

TEST(StringUtilsTest, StringBeginsWith) {
  EXPECT_TRUE(StringBeginsWith("dummy", "dum"));
  EXPECT_TRUE(StringBeginsWith("123 456", ""));
  EXPECT_TRUE(StringBeginsWith("empty", ""));
  EXPECT_TRUE(StringBeginsWith("", ""));

  EXPECT_FALSE(StringBeginsWith("dummy", " dum"));
  EXPECT_FALSE(StringBeginsWith("my", "duh"));
  EXPECT_FALSE(StringBeginsWith("", "dummy"));
}

TEST(StringUtilsTest, WStringBeginsWith) {
  EXPECT_TRUE(WStringBeginsWith(L"dummy", L"dum"));
  EXPECT_TRUE(WStringBeginsWith(L"123 456", L""));
  EXPECT_TRUE(WStringBeginsWith(L"empty", L""));
  EXPECT_TRUE(WStringBeginsWith(L"", L""));

  EXPECT_FALSE(WStringBeginsWith(L"dummy", L" dum"));
  EXPECT_FALSE(WStringBeginsWith(L"my", L"duh"));
  EXPECT_FALSE(WStringBeginsWith(L"", L"dummy"));
}

TEST(StringUtilsTest, StringEndsWith) {
  EXPECT_TRUE(StringEndsWith("dummy", "mmy"));
  EXPECT_TRUE(StringEndsWith("123 456", "6"));
  EXPECT_TRUE(StringEndsWith("empty", ""));
  EXPECT_TRUE(StringEndsWith("", ""));

  EXPECT_FALSE(StringEndsWith("dummy", "mmy "));
  EXPECT_FALSE(StringEndsWith("my", "dummy "));
  EXPECT_FALSE(StringEndsWith("", "dummy"));
}

TEST(StringUtilsTest, WStringEndsWith) {
  EXPECT_TRUE(WStringEndsWith(L"dummy", L"mmy"));
  EXPECT_TRUE(WStringEndsWith(L"123 456", L"6"));
  EXPECT_TRUE(WStringEndsWith(L"empty", L""));
  EXPECT_TRUE(WStringEndsWith(L"", L""));

  EXPECT_FALSE(WStringEndsWith(L"dummy", L"mmy "));
  EXPECT_FALSE(WStringEndsWith(L"my", L"dummy "));
  EXPECT_FALSE(WStringEndsWith(L"", L"dummy"));
}

TEST(StringUtilsTest, StringEscapeSpecialCharacter) {
  std::string result;
  result = StringEscapeSpecialCharacter("dummy");
  EXPECT_STREQ("dummy", result.c_str());
  result = StringEscapeSpecialCharacter("This \"is\" a line\n");
  EXPECT_STREQ("This \\\"is\\\" a line\\n", result.c_str());
  result = StringEscapeSpecialCharacter("Special characters: \\ \t \r ~ \n");
  EXPECT_STREQ("Special characters: \\\\ \\t \\r ~ \\n", result.c_str());
  result = StringEscapeSpecialCharacter("\x8f");
  EXPECT_STREQ("\\x8F", result.c_str());
}

}  // namespace base
