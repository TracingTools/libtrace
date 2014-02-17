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

#ifndef BASE_WIN_SCOPED_HANDLE_H_
#define BASE_WIN_SCOPED_HANDLE_H_

// Restrict the import to the windows basic includes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>  // NOLINT

#include "base/base.h"

namespace base {
namespace win {

// Wrapper for a Windows handle. Guarantees that the handle is closed when
// the ScopedHandle is deleted (or before if Set() or Close() is called).
class ScopedHandle {
 public:
  ScopedHandle();

  // @param handle handle managed by this object.
  explicit ScopedHandle(HANDLE handle);

  ~ScopedHandle();

  // Set the new handle managed by this object. The previous handle is closed.
  // @param handle new handle managed by this object.
  void Reset(HANDLE handle);

  // Close the handle.
  void Close();

  // @returns the handle.
  HANDLE get() const { return handle_; }

 private:
  // The handle managed by this object.
  HANDLE handle_;

  DISALLOW_COPY_AND_ASSIGN(ScopedHandle);
};

}  // namespace win
}  // namespace base

#endif  // BASE_WIN_SCOPED_HANDLE_H_
