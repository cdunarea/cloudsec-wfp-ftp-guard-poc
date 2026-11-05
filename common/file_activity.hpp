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
        const auto previous = std::find_if(events_.begin(), events_.end(),
            [&](const auto& event) { return event.pid == pid && event.path == path; });
        if (previous != events_.end()) {
            if (previous->at >= at) { return; }
            events_.erase(previous);
        }
        if (events_.size() >= kCapacity) { events_.pop_front(); ++evictions_; }
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
    std::size_t Evictions() const { return evictions_; }

 private:
    struct NetOpenedFile { std::uint64_t pid; std::uint64_t at; std::wstring path; };
    static constexpr std::size_t kCapacity = 1024;
    static constexpr std::uint64_t kLifetime = 30ULL * 10000000;
    std::deque<NetOpenedFile> events_;
    std::size_t evictions_ = 0;
};
// Associates read events with paths by file-object lifetime, without keeping
// handles alive. A read may be reported without a usable header PID.
class NetFileReadCache {
 public:
    void Open(std::uint64_t pid, std::uint64_t object, std::uint64_t at, std::wstring path) {
        if (pid == 0 || object == 0 || at == 0 || path.empty()) { return; }
        Close(object);
        if (objects_.size() >= kCapacity) { objects_.pop_front(); ++evictions_; }
        objects_.push_back({pid, object, at, std::move(path)});
    }
    bool Read(std::uint64_t pid, std::uint64_t object, std::uint64_t at) {
        for (const auto& file : objects_) {
            if (file.object != object || at < file.at ||
                (pid != 0 && pid != 0xffffffffULL && pid != file.pid)) { continue; }
            reads_.Record(file.pid, at, file.path);
            return true;
        }
        return false;
    }
    void Close(std::uint64_t object) {
        const auto found = std::find_if(objects_.begin(), objects_.end(),
            [object](const auto& file) { return file.object == object; });
        if (found != objects_.end()) { objects_.erase(found); }
    }
    std::vector<std::wstring> Paths(std::uint64_t pid, std::uint64_t since, std::uint64_t now) const {
        return reads_.Paths(pid, since, now);
    }
    std::size_t Evictions() const { return evictions_ + reads_.Evictions(); }

 private:
    struct NetFileObject { std::uint64_t pid; std::uint64_t object; std::uint64_t at; std::wstring path; };
    static constexpr std::size_t kCapacity = 4096;
    std::deque<NetFileObject> objects_;
    NetFileActivityCache reads_;
    std::size_t evictions_ = 0;
};
}  // namespace guard
