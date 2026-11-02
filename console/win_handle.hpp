#pragma once
#include <Windows.h>
#include <utility>

namespace guard {
class WinHandle {
 public:
    explicit WinHandle(HANDLE handle = nullptr) : handle_(handle) {}
    ~WinHandle() { Reset(); }
    WinHandle(const WinHandle&) = delete;
    WinHandle& operator=(const WinHandle&) = delete;
    WinHandle(WinHandle&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    WinHandle& operator=(WinHandle&& other) noexcept {
        if (this != &other) { Reset(std::exchange(other.handle_, nullptr)); }
        return *this;
    }
    bool Valid() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }
    HANDLE Get() const { return handle_; }
    void Reset(HANDLE handle = nullptr) { if (Valid()) { CloseHandle(handle_); } handle_ = handle; }
 private:
    HANDLE handle_;
};
}  // namespace guard
