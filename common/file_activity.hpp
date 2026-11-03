#pragma once
#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <deque>
#include <string>
#include <utility>
#include <vector>

namespace guard {
// Timestamps use 100 ns system-time units. The caller owns synchronization.
class NetFileActivityCache {
 public:
    void Record(std::uint64_t pid, std::uint64_t at, std::wstring path) {
        if (pid == 0 || at == 0 || path.empty()) { return; }
        if (events_.size() >= kCapacity) { events_.pop_front(); }
        events_.push_back({pid, at, std::move(path)});
    }
    std::vector<std::wstring> Paths(std::uint64_t pid, std::uint64_t since, std::uint64_t now) const {
        std::vector<std::wstring> paths;
        for (const auto& event : events_) {
            if (event.pid != pid || event.at < since || event.at > now || now - event.at > kLifetime) { continue; }
            if (std::find(paths.begin(), paths.end(), event.path) == paths.end()) { paths.push_back(event.path); }
        }
        return paths;
    }

 private:
    struct NetOpenedFile { std::uint64_t pid; std::uint64_t at; std::wstring path; };
    static constexpr std::size_t kCapacity = 1024;
    static constexpr std::uint64_t kLifetime = 30ULL * 10000000;
    std::deque<NetOpenedFile> events_;
};
}  // namespace guard
