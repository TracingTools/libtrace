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

#include <sstream>

namespace base {

namespace {

template <typename T>
bool StringBeginsWithInternal(const T& str, const T& starting) {
  if (str.compare(0, starting.length(), starting) == 0)
    return true;
  return false;
}

template <typename T>
bool StringEndsWithInternal(const T& str, const T& ending) {
  if (ending.length() > str.length())
    return false;

  if (str.compare(str.length() - ending.length(),
                  ending.length(),
                  ending) == 0) {
    return true;
  }

  return false;
}

}  // namespace

std::wstring StringToWString(const std::string& string) {
  return std::wstring(string.begin(), string.end());
}

std::string WStringToString(const std::wstring& string) {
  return std::string(string.begin(), string.end());
}

bool StringBeginsWith(const std::string& str, const std::string& starting) {
  return StringBeginsWithInternal(str, starting);
}

bool WStringBeginsWith(const std::wstring& str, const std::wstring& starting) {
  return StringBeginsWithInternal(str, starting);
}

bool StringEndsWith(const std::string &str, const std::string &ending) {
  return StringEndsWithInternal(str, ending);
}

bool WStringEndsWith(const std::wstring& str, const std::wstring& ending) {
  return StringEndsWithInternal(str, ending);
}

std::string StringEscapeSpecialCharacter(const std::string& str) {
  std::stringstream ss;
  for (std::string::const_iterator i = str.begin(); i != str.end(); ++i) {
    unsigned char c = *i;
    if (' ' <= c && c <= '~' && c != '\\' && c != '"') {
      ss << c;
      continue;
    }

    ss << '\\';

    switch (c) {
      case '"': ss << '"'; break;
      case '\\': ss << '\\'; break;
      case '\t': ss << 't'; break;
      case '\r': ss << 'r'; break;
      case '\n': ss << 'n'; break;
      default: {
        static char const* const hexdig = "0123456789ABCDEF";
        ss << 'x';
        ss << hexdig[c >> 4];
        ss << hexdig[c & 0xF];
        break;
      }
    }
  }

  return ss.str();
}

}  // namespace base
