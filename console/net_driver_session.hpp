#pragma once
#include <Windows.h>
#include <string>
#include "protocol.hpp"
#include "win_handle.hpp"

namespace guard {
class NetDriverSession {
 public:
    NetDriverSession(const std::wstring& driver_path, const std::wstring& application);
    ~NetDriverSession();
    NetDriverSession(const NetDriverSession&) = delete;
    NetDriverSession& operator=(const NetDriverSession&) = delete;
    bool Next(NetEvent& event);
    bool Decide(UINT64 flow, bool block, bool source_verified = false);
    NetStatus ReadStatus() const;
 private:
    SC_HANDLE manager_ = nullptr;
    SC_HANDLE service_ = nullptr;
    HANDLE engine_ = nullptr;
    WinHandle device_;
    bool created_ = false;
    bool started_ = false;
    void Install(const std::wstring& path);
    void AddFilters(const std::wstring& application);
    void Shutdown() noexcept;
    static void Check(DWORD error, const char* stage);
};
}  // namespace guard
