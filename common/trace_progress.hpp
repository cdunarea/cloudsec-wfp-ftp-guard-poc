#pragma once
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>

namespace guard {
class NetTraceProgress {
 public:
    void Advance(std::uint64_t buffers) {
        {
            std::lock_guard lock(mutex_);
            buffers_ = (std::max)(buffers_, buffers);
        }
        changed_.notify_all();
    }
    void Finish() {
        {
            std::lock_guard lock(mutex_);
            finished_ = true;
        }
        changed_.notify_all();
    }
    bool Wait(std::uint64_t target, std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        return changed_.wait_for(lock, timeout, [&] { return finished_ || buffers_ >= target; }) &&
               !finished_ && buffers_ >= target;
    }
    std::uint64_t Buffers() const {
        std::lock_guard lock(mutex_);
        return buffers_;
    }
 private:
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    std::uint64_t buffers_ = 0;
    bool finished_ = false;
};
}  // namespace guard
