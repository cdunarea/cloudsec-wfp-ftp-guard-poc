#pragma once
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <array>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <syncstream>
#include "protocol.hpp"
#include "win_handle.hpp"

namespace guard {
class Diagnostics {
 public:
    static void Line(const std::string& text) { std::osyncstream(std::cout) << text << '\n'; std::cout.flush(); }
    static std::string Utf8(const std::wstring& text) {
        if (text.empty()) { return {}; }
        const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        if (size <= 0) { return "<invalid text>"; }
        std::string bytes(static_cast<size_t>(size), '\0');
        if (WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), bytes.data(), size, nullptr, nullptr) != size) { return "<invalid text>"; }
        return bytes;
    }
    static std::wstring ProcessPath(DWORD pid) {
        WinHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        std::array<wchar_t, 32768> path{};
        DWORD length = static_cast<DWORD>(path.size());
        return process.Valid() && QueryFullProcessImageNameW(process.Get(), 0, path.data(), &length)
                   ? std::wstring(path.data(), length) : L"<unavailable>";
    }
    static std::string Address(USHORT family, const UCHAR* address) {
        std::array<char, INET6_ADDRSTRLEN> text{};
        return InetNtopA(family, address, text.data(), static_cast<DWORD>(text.size())) != nullptr ? text.data() : "?";
    }
    static void Connection(const char* source, const NetEvent& event) {
        const auto path = ProcessPath(static_cast<DWORD>(event.process_id));
        DWORD session = 0;
        ProcessIdToSessionId(static_cast<DWORD>(event.process_id), &session);
        std::ostringstream output;
        output << "[CONNECTION] {source=" << source << ", flow=" << event.flow << ", pid=" << event.process_id
               << ", image=\"" << Utf8(std::filesystem::path(path).filename().wstring()) << "\", path=\"" << Utf8(path)
               << "\", session=" << session << ", local=" << Address(event.family, event.local_address) << ':' << event.local_port
               << ", remote=" << Address(event.family, event.remote_address) << ':' << event.remote_port
               << ", direction=" << ((event.flags & NetInbound) != 0 ? "inbound" : "outbound") << '}';
        Line(output.str());
    }
};
}  // namespace guard
