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

#ifndef BASE_LOGGING_H_
#define BASE_LOGGING_H_

#include <cstdlib>
#include <sstream>

#include "base/base.h"

namespace base {

enum LogSeverity {
  LOG_INFO,
  LOG_WARNING,
  LOG_ERROR,
  LOG_FATAL
};

class LogMessage {
 public:
  LogMessage(LogSeverity severity, const char* file, int line)
      : severity_(severity), file_(file), line_(line) {
  }

  ~LogMessage();

  std::ostream& stream() { return stream_; }

 private:
  std::ostringstream stream_;
  LogSeverity severity_;
  const char* file_;
  const int line_;

  DISALLOW_COPY_AND_ASSIGN(LogMessage);
};

#define LOG(severity) \
    base::LogMessage(base::LOG_ ## severity, __FILE__, __LINE__).stream()

#ifndef NDEBUG
#define DCHECK(cond) if (!(cond)) LOG(FATAL) << "'" << #cond << "' failed.\n"
#else
#define DCHECK(cond) if (false) LOG(FATAL) << ""
#endif

#define DCHECK_EQ(a, b) DCHECK((a) == (b))
#define DCHECK_NE(a, b) DCHECK((a) != (b))
#define DCHECK_LT(a, b) DCHECK((a) < (b))
#define DCHECK_LE(a, b) DCHECK((a) <= (b))
#define DCHECK_GT(a, b) DCHECK((a) > (b))
#define DCHECK_GE(a, b) DCHECK((a) >= (b))

}  // namespace base

#endif  // BASE_LOGGING_H_
