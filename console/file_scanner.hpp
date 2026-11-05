#pragma once
#include <Windows.h>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <utility>
#include "win_handle.hpp"

namespace guard {
enum class ScanVerdict { Clear, SecretName, SecretContent, Incomplete };
struct ScanResult {
    ScanVerdict verdict = ScanVerdict::Clear;
    std::wstring path;
    std::string detail;
    size_t handles = 0;
    size_t files = 0;
    std::uint64_t bytes = 0;
    size_t recent_files = 0;
    size_t cached_files = 0;
    bool recent_match = false;
    bool Block() const { return verdict != ScanVerdict::Clear; }
};

class FileScanner {
 public:
    explicit FileScanner(std::function<ULONGLONG()> cache_clock = {}) : cache_clock_(std::move(cache_clock)) {}
    ScanResult Scan(DWORD process_id, std::uint64_t process_created, DWORD budget_ms = 8000,
                    const std::vector<std::wstring>& recent_files = {}, bool source_paths_only = false,
                    std::uint64_t flow_id = 0) const;
    // Also used by deterministic tests on real Windows file handles.
    ScanResult InspectFile(HANDLE file, DWORD budget_ms = 8000) const;
    static bool SecretFilename(const std::wstring& path);
 private:
    struct NetFileStamp { FILE_ID_INFO identity{}; FILE_BASIC_INFO basic{}; FILE_STANDARD_INFO standard{}; LONGLONG usn = 0; };
    struct NetCachedSource {
        DWORD process_id;
        std::uint64_t process_created;
        std::uint64_t flow;
        std::wstring path;
        NetFileStamp stamp;
        ULONGLONG scanned_at;
    };
    struct NetScanContext { DWORD process_id; std::uint64_t process_created; std::uint64_t flow; };
    mutable std::vector<NetCachedSource> source_cache_;
    std::function<ULONGLONG()> cache_clock_;
    ULONGLONG CacheTime() const { return cache_clock_ ? cache_clock_() : GetTickCount64(); }
    struct NativeHandle {
        void* object;
        ULONG_PTR process_id;
        ULONG_PTR handle;
        ULONG access;
        USHORT trace;
        USHORT type;
        ULONG attributes;
        ULONG reserved;
    };
    struct NativeSnapshot { ULONG_PTR count; ULONG_PTR reserved; NativeHandle handles[1]; };
    static bool Snapshot(std::vector<unsigned char>& storage, std::string& error);
    static std::uint64_t CreationTime(HANDLE process);
    static std::wstring FilePath(HANDLE file);
    static void Incomplete(ScanResult& result, const char* stage, DWORD error);
    static void ReadContent(HANDLE file, ULONGLONG deadline, ScanResult& result);
    static void Inspect(HANDLE file, ULONGLONG deadline, ScanResult& result);
    void InspectRecent(const std::wstring& path, ULONGLONG deadline, ScanResult& result, const NetScanContext& context) const;
    void InspectPaths(const std::vector<std::wstring>& paths, ULONGLONG deadline, ScanResult& result, const NetScanContext& context) const;
    static bool Stamp(HANDLE file, NetFileStamp& stamp);
    static bool FileUsn(HANDLE file, LONGLONG& usn);
    static bool SameStamp(const NetFileStamp& left, const NetFileStamp& right);
    bool Cached(HANDLE file, const std::wstring& path, const NetScanContext& context, ScanResult& result) const;
    void Remember(HANDLE file, const std::wstring& path, const NetFileStamp& before, const NetScanContext& context) const;
};
}  // namespace guard
