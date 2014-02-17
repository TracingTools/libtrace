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

#include "base/win/scoped_handle.h"

#include <string>
#include <vector>

#include "base/logging.h"
#include "gtest/gtest.h"

namespace base {
namespace win {

namespace {

// Create a temporary file and open it. The file will be automatically deleted
// when its handle is closed.
// @param file_name absolute path to the temporary file.
// @param file_handle handle of the opened temporary file.
// @returns true if the file is created successfully, false otherwise.
bool CreateTemporaryFile(std::wstring* file_name, HANDLE* file_handle) {
  DCHECK(file_name);
  DCHECK(file_handle);

  // Get the path to a temporary directory.
  std::vector<WCHAR> buffer_path(MAX_PATH);
  DWORD ret = ::GetTempPathW(MAX_PATH, &buffer_path[0]);
  if (ret > MAX_PATH || ret == 0)
    return false;

  // Generate a temporary file name.
  std::vector<WCHAR> buffer_file_name(MAX_PATH);
  ret = ::GetTempFileNameW(&buffer_path[0],
                           L"tes",  // 3 characters prefix of the file name.
                           0,
                           &buffer_file_name[0]);

  if (ret == 0)
    return false;

  *file_name = &buffer_file_name[0];

  // Create a temporary file that will be deleted as soon as all its handles
  // are closed.
  *file_handle = ::CreateFileW(file_name->c_str(),
                               GENERIC_READ,
                               0,
                               NULL,
                               CREATE_ALWAYS,
                               FILE_FLAG_DELETE_ON_CLOSE,
                               NULL);

  if (*file_handle == INVALID_HANDLE_VALUE)
    return false;

  return true;
}

// Indicates whether the specified file exists.
// @param file_name absolute path to the file for which to test existence.
// @returns true if the file exists, false otherwise.
bool FileExists(const std::wstring& file_name) {
  DWORD attrib = GetFileAttributes(file_name.c_str());
  return (attrib != INVALID_FILE_ATTRIBUTES &&
      !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

}  // namespace

class ScopedHandleTest : public testing::Test {
 public:
  ScopedHandleTest() : temp_file_handle_(INVALID_HANDLE_VALUE) {}

 protected:
  // @returns handle to the temporary file created for the test.
  HANDLE temp_file_handle() const {
    return temp_file_handle_;
  }

  // Indicates whether the temporary file created for the test exists.
  // @returns true if the file exists, false otherwise.
  bool TempFileExists() const {
    return FileExists(temp_file_name_.c_str());
  }

 private:
  // Overridden from testing::Test:
  // @{
  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();

    // Create a temporary file for the test.
    ASSERT_TRUE(CreateTemporaryFile(&temp_file_name_, &temp_file_handle_));
  }

  virtual void TearDown() OVERRIDE {
    // Delete the temporary file if it has not already been deleted.
    if (TempFileExists())
      ::DeleteFileW(temp_file_name_.c_str());

    testing::Test::TearDown();
  }
  // @}

  // Name of the temporary file created for the test.
  std::wstring temp_file_name_;

  // Handle to the temporary file created for the test.
  HANDLE temp_file_handle_;
};

TEST_F(ScopedHandleTest, Constructor) {
  ScopedHandle scoped_handle(temp_file_handle());
  EXPECT_EQ(temp_file_handle(), scoped_handle.get());
}

TEST_F(ScopedHandleTest, Destructor) {
  // The handle should be closed when the destructor is called at the end of
  // this scope.
  {
    ScopedHandle scoped_handle(temp_file_handle());
    EXPECT_EQ(temp_file_handle(), scoped_handle.get());
  }

  EXPECT_FALSE(TempFileExists());
}

TEST_F(ScopedHandleTest, Reset) {
  std::wstring other_temp_file_name;
  HANDLE other_temp_file_handle = INVALID_HANDLE_VALUE;
  CreateTemporaryFile(&other_temp_file_name, &other_temp_file_handle);

  {
    ScopedHandle scoped_handle(temp_file_handle());
    EXPECT_EQ(temp_file_handle(), scoped_handle.get());

    scoped_handle.Reset(other_temp_file_handle);

    EXPECT_EQ(other_temp_file_handle, scoped_handle.get());
    EXPECT_FALSE(TempFileExists());
  }

  EXPECT_FALSE(FileExists(other_temp_file_name));
}

TEST_F(ScopedHandleTest, Close) {
  ScopedHandle scoped_handle(temp_file_handle());
  EXPECT_EQ(temp_file_handle(), scoped_handle.get());

  scoped_handle.Close();

  EXPECT_FALSE(TempFileExists());
  EXPECT_EQ(scoped_handle.get(), INVALID_HANDLE_VALUE);
}

}  // namespace win
}  // namespace base
