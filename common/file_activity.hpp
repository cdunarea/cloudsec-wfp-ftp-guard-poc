#pragma once
#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <deque>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace guard {
// FileIo/Create describes an attempt. Only a successful matching OpEnd proves
// an open, including paths probed by Explorer's optional shell components.
class NetFileOpenCache {
 public:
    struct NetOpenedFile { std::uint64_t pid; std::uint64_t object; std::uint64_t at; std::wstring path; };
    void Begin(std::uint64_t pid, std::uint64_t irp, std::uint64_t object, std::uint64_t at, std::wstring path) {
        if (pid == 0 || object == 0 || at == 0 || path.empty()) { return; }
        if (irp == 0) { reliable_ = false; return; }
        const auto previous = Find(irp);
        if (previous != pending_.end()) { pending_.erase(previous); reliable_ = false; }
        if (pending_.size() >= kCapacity) { pending_.pop_front(); reliable_ = false; }
        pending_.push_back({irp, {pid, object, at, std::move(path)}});
    }
    std::optional<NetOpenedFile> Finish(std::uint64_t irp, std::optional<std::uint32_t> status) {
        const auto found = Find(irp);
        if (found == pending_.end()) { return std::nullopt; }
        auto file = std::move(found->file);
        pending_.erase(found);
        if (!status) { reliable_ = false; return std::nullopt; }
        if (*status != 0) { return std::nullopt; }
        return file;
    }
    bool Empty() const { return pending_.empty(); }
    bool Reliable() const { return reliable_; }
 private:
    struct NetPendingOpen { std::uint64_t irp; NetOpenedFile file; };
    static constexpr std::size_t kCapacity = 4096;
    std::deque<NetPendingOpen> pending_;
    bool reliable_ = true;
    std::deque<NetPendingOpen>::iterator Find(std::uint64_t irp) {
        return std::find_if(pending_.begin(), pending_.end(),
            [irp](const auto& pending) { return pending.irp == irp; });
    }
};
// Timestamps use 100 ns system-time units. The caller owns synchronization.
class NetFileActivityCache {
 public:
    void Record(std::uint64_t pid, std::uint64_t at, std::wstring path) {
        if (pid == 0 || at == 0 || path.empty()) { return; }
        Expire(at);
        const auto previous = std::find_if(events_.begin(), events_.end(),
            [&](const auto& event) { return event.pid == pid && event.path == path; });
        if (previous != events_.end()) {
            if (previous->at >= at) { return; }
            events_.erase(previous);
        }
        if (events_.size() >= kCapacity) {
            RecordLoss(events_.front().pid, events_.front().at);
            events_.pop_front();
            ++evictions_;
        }
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
    bool Complete(std::uint64_t pid, std::uint64_t since, std::uint64_t now) const {
        // If even the bounded loss index filled, retain a conservative global
        // watermark. Otherwise a different process cannot poison this query.
        if (LossRelevant(untracked_loss_at_, since, now)) { return false; }
        return std::none_of(losses_.begin(), losses_.end(), [&](const auto& loss) {
            return loss.pid == pid && LossRelevant(loss.at, since, now);
        });
    }

 private:
    struct NetOpenedFile { std::uint64_t pid; std::uint64_t at; std::wstring path; };
    struct NetLostEvidence { std::uint64_t pid; std::uint64_t at; };
    static constexpr std::size_t kCapacity = 1024;
    static constexpr std::uint64_t kLifetime = 30ULL * 10000000;
    std::deque<NetOpenedFile> events_;
    std::deque<NetLostEvidence> losses_;
    std::uint64_t untracked_loss_at_ = 0;
    std::size_t evictions_ = 0;
    static bool Expired(std::uint64_t at, std::uint64_t now) {
        return now >= at && now - at > kLifetime;
    }
    static bool LossRelevant(std::uint64_t at, std::uint64_t since, std::uint64_t now) {
        // A future watermark can hide older losses after out-of-order delivery.
        // Keep it conservative until it falls outside the retained window.
        return at != 0 && at >= since && !Expired(at, now);
    }
    void Expire(std::uint64_t now) {
        std::erase_if(events_, [now](const auto& event) { return Expired(event.at, now); });
        std::erase_if(losses_, [now](const auto& loss) { return Expired(loss.at, now); });
    }
    void RecordLoss(std::uint64_t pid, std::uint64_t at) {
        const auto found = std::find_if(losses_.begin(), losses_.end(),
            [pid](const auto& loss) { return loss.pid == pid; });
        if (found != losses_.end()) { found->at = (std::max)(found->at, at); return; }
        if (losses_.size() >= kCapacity) {
            untracked_loss_at_ = (std::max)(untracked_loss_at_, losses_.front().at);
            losses_.pop_front();
        }
        losses_.push_back({pid, at});
    }
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
    bool Complete(std::uint64_t pid, std::uint64_t since, std::uint64_t now) const {
        // An evicted live object may be read much later. Its missing mapping
        // cannot expire safely just because the path-history window elapsed.
        return evictions_ == 0 && reads_.Complete(pid, since, now);
    }

 private:
    struct NetFileObject { std::uint64_t pid; std::uint64_t object; std::uint64_t at; std::wstring path; };
    static constexpr std::size_t kCapacity = 4096;
    std::deque<NetFileObject> objects_;
    NetFileActivityCache reads_;
    std::size_t evictions_ = 0;
};
}  // namespace guard
