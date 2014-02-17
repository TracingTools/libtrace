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

#include "base/scoped_ptr.h"
#include "gtest/gtest.h"

namespace {

struct DummyStruct { int field; };

class DecrementOnDelete {
 public:
  explicit DecrementOnDelete(int* ptr) : ptr_(ptr) { }
  ~DecrementOnDelete() { *ptr_ -= 1; }
 private:
  int* ptr_;
};

class Derive : public DecrementOnDelete {
 public:
  explicit Derive(int* ptr) : DecrementOnDelete(ptr) { }
};

scoped_ptr<DecrementOnDelete> Identity(scoped_ptr<DecrementOnDelete> param) {
  return param.Pass();
}

}  // namespace

TEST(ScopedPtrTest, Constructor) {
  scoped_ptr<int> var1;
  EXPECT_EQ(NULL, var1.get());

  int* var2_content = new int();
  scoped_ptr<int> var2(var2_content);
  EXPECT_EQ(var2_content, var2.get());
}

TEST(ScopedPtrTest, CopyConstructor) {
  int* var1_content = new int();
  scoped_ptr<int> var1(var1_content);
  scoped_ptr<int> var2(var1.Pass());

  EXPECT_EQ(NULL, var1.get());
  EXPECT_EQ(var1_content, var2.get());
}

TEST(ScopedPtrTest, DestructorOnScope) {
  int count = 0;
  {
    DecrementOnDelete* var1_content = new DecrementOnDelete(&count);
    DecrementOnDelete* var2_content = new DecrementOnDelete(&count);
    scoped_ptr<DecrementOnDelete> var1(var1_content);
    scoped_ptr<DecrementOnDelete> var2(var2_content);
  }
  EXPECT_EQ(-2, count);
}

TEST(ScopedPtrTest, CopyAssignment) {
  int* var1_content = new int();
  scoped_ptr<int> var1(var1_content);
  scoped_ptr<int> var2;
  var2 = var1.Pass();

  EXPECT_EQ(NULL, var1.get());
  EXPECT_EQ(var1_content, var2.get());
}

TEST(ScopedPtrTest, Get) {
  int* var1_content = new int();
  scoped_ptr<int> var1(var1_content);
  EXPECT_EQ(var1_content, var1.get());
}

TEST(ScopedPtrTest, GetOperator) {
  scoped_ptr<DummyStruct> var1(new DummyStruct());
  EXPECT_EQ(&var1->field, &var1.get()->field);
}

TEST(ScopedPtrTest, Reset) {
  int count = 0;
  DecrementOnDelete* var1_content = new DecrementOnDelete(&count);
  scoped_ptr<DecrementOnDelete> var1;

  EXPECT_EQ(NULL, var1.get());
  var1.reset(var1_content);
  EXPECT_EQ(var1_content, var1.get());
  var1.reset(var1_content);
  EXPECT_EQ(var1_content, var1.get());
  EXPECT_EQ(0, count);
  var1.reset(NULL);
  EXPECT_EQ(NULL, var1.get());
  EXPECT_EQ(-1, count);
}

TEST(ScopedPtrTest, PassToCopyConstructor) {
  int count = 0;
  DecrementOnDelete* var1_content = new DecrementOnDelete(&count);
  scoped_ptr<DecrementOnDelete> var1(var1_content);
  scoped_ptr<DecrementOnDelete> var2(var1.Pass());

  EXPECT_EQ(0, count);
  EXPECT_EQ(NULL, var1.get());
  EXPECT_EQ(var1_content, var2.get());
}

TEST(ScopedPtrTest, PassToAssignOperator) {
  int count = 0;
  DecrementOnDelete* var1_content = new DecrementOnDelete(&count);
  scoped_ptr<DecrementOnDelete> var1(var1_content);
  scoped_ptr<DecrementOnDelete> var2;
  var2 = var1.Pass();
  EXPECT_EQ(0, count);
  EXPECT_EQ(NULL, var1.get());
  EXPECT_EQ(var1_content, var2.get());
}

TEST(ScopedPtrTest, PassThroughFunction) {
  int count = 0;
  DecrementOnDelete* var1_content = new DecrementOnDelete(&count);
  scoped_ptr<DecrementOnDelete> var1(var1_content);
  scoped_ptr<DecrementOnDelete> var2;
  var2 = Identity(var1.Pass());
  EXPECT_EQ(0, count);
  EXPECT_EQ(NULL, var1.get());
  EXPECT_EQ(var1_content, var2.get());
}

TEST(ScopedPtrTest, DestructorAfterRelease) {
  int count = 0;
  DecrementOnDelete* var1_content = new DecrementOnDelete(&count);
  {
    scoped_ptr<DecrementOnDelete> var1(var1_content);
    DecrementOnDelete* ptr = var1.release();
    EXPECT_EQ(var1_content, ptr);
  }
  EXPECT_EQ(0, count);
  delete var1_content;
  EXPECT_EQ(-1, count);
}

TEST(ScopedPtrTest, PassToConst) {
  scoped_ptr<int> ptr(new int());
  int* expected = ptr.get();
  scoped_ptr<const int> const_ptr(ptr.Pass());
  EXPECT_EQ(NULL, ptr.get());
  EXPECT_EQ(expected, const_ptr.get());
}

TEST(ScopedPtrTest, PassToDerivedConstructor) {
  int count = 0;
  {
    scoped_ptr<Derive> ptr1(new Derive(&count));
    Derive* expected = ptr1.get();
    scoped_ptr<DecrementOnDelete> ptr2(ptr1.Pass());
    EXPECT_EQ(NULL, ptr1.get());
    EXPECT_EQ(expected, ptr2.get());
  }
  EXPECT_EQ(-1, count);
}

TEST(ScopedPtrTest, PassToDerivedAssignOperator) {
  int count = 0;
  {
    scoped_ptr<Derive> ptr1(new Derive(&count));
    scoped_ptr<DecrementOnDelete> ptr2;

    Derive* expected = ptr1.get();
    ptr2 = ptr1.Pass();
    EXPECT_EQ(NULL, ptr1.get());
    EXPECT_EQ(expected, ptr2.get());
  }
  EXPECT_EQ(-1, count);
}
