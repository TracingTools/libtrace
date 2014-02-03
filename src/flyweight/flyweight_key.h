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

#ifndef FLYWEIGHT_FLYWEIGHT_KEY_H_
#define FLYWEIGHT_FLYWEIGHT_KEY_H_

namespace flyweight {

struct DefaultFlyweightTag {};

// A key that is generated when a value is inserted in a flyweight and that can
// be used to retrieve the value from the same flyweight.
template <typename T, typename I = DefaultFlyweightTag>
class FlyweightKey {
 public:
  explicit FlyweightKey(size_t key_value);

  // Compares 2 keys. The values that the keys refer to are equal if the keys
  // are equal and come from the same flyweight. The method assumes that the
  // compared keys always come from the same flyweight.
  // @param flyweight_key the key to compare to this key.
  // @returns true if the keys are equal, false otherwise.
  bool operator==(const FlyweightKey<T, I>& flyweight_key) const;

  // @returns the internal value of the key.
  size_t key_value() const;

 private:
  size_t key_value_;
};

template <typename T, typename I>
FlyweightKey<T, I>::FlyweightKey(size_t key_value) : key_value_(key_value) {
}

template <typename T, typename I>
bool FlyweightKey<T, I>::
    operator==(const FlyweightKey<T, I>& flyweight_key) const {
  return key_value() == flyweight_key.key_value();
}

template <typename T, typename I>
size_t FlyweightKey<T, I>::key_value() const {
  return key_value_;
}

}  // namespace flyweight

#endif  // FLYWEIGHT_FLYWEIGHT_KEY_H_
