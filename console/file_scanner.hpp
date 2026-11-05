#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
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
    bool recent_match = false;
    bool Block() const { return verdict != ScanVerdict::Clear; }
};

class FileScanner {
 public:
    ScanResult Scan(DWORD process_id, std::uint64_t process_created, DWORD budget_ms = 8000,
                    const std::vector<std::wstring>& recent_files = {}, bool source_paths_only = false) const;
    // Also used by deterministic tests on real Windows file handles.
    ScanResult InspectFile(HANDLE file, DWORD budget_ms = 8000) const;
    static bool SecretFilename(const std::wstring& path);
 private:
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
    static void InspectRecent(const std::wstring& path, ULONGLONG deadline, ScanResult& result);
    static void InspectPaths(const std::vector<std::wstring>& paths, ULONGLONG deadline, ScanResult& result);
};
}  // namespace guard
