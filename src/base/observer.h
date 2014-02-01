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

#ifndef BASE_OBSERVER_H_
#define BASE_OBSERVER_H_

#include "base/logging.h"

namespace base {

template<class T>
class Observer {
 public:
  virtual void Receive(const T& data) const = 0;
};

template<class B, class T>
class CallbackObserver : public Observer<T> {
 public:
  typedef void (B::*Callback)(const T&);

  CallbackObserver(B* base, Callback thunk)
      : base_(base), thunk_(thunk) {
  }

  virtual void Receive(const T& data) const OVERRIDE {
    DCHECK(base_ != NULL);
    (base_->*thunk_)(data);
  }

 private:
  B* base_;
  Callback thunk_;
};

template<class B, class T>
inline CallbackObserver<B, T>
    MakeObserver(B* base, void (B::*func)(const T&)) {
  return CallbackObserver<B, T>(base, func);
}

template<class B, class T>
inline CallbackObserver<B, T>
    MakeObserver(B* base, void (B::*func)(const T&) const) {
  typedef typename CallbackObserver<B, T>::Callback Callback;
  return CallbackObserver<B, T>(base, reinterpret_cast<Callback>(func));
}

template<class B>
inline CallbackObserver<B, typename B::value_type> BackInserter(B* base) {
  return MakeObserver<B, typename B::value_type>(base, &B::push_back);
}

template<class B>
inline CallbackObserver<B, typename B::value_type> FrontInserter(B* base) {
  return MakeObserver<B, typename B::value_type>(base, &B::push_front);
}

}  // namespace base

#endif  // BASE_OBSERVER_H_
