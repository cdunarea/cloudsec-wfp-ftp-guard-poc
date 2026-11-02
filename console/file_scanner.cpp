#include "file_scanner.hpp"
#include <winternl.h>
#include <algorithm>
#include <array>
#include <cwctype>
#include <filesystem>
#include <limits>
#include "secret_matcher.hpp"

namespace guard {
bool FileScanner::SecretFilename(const std::wstring& path) {
    auto name = std::filesystem::path(path).filename().wstring();
    std::transform(name.begin(), name.end(), name.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return name.find(L"secret") != std::wstring::npos;
}

void FileScanner::Incomplete(ScanResult& result, const char* stage, DWORD error) {
    if (result.verdict == ScanVerdict::Clear) { result.verdict = ScanVerdict::Incomplete; }
    if (result.detail.empty()) { result.detail = std::string(stage) + ": error=" + std::to_string(error); }
}

std::uint64_t FileScanner::CreationTime(HANDLE process) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) { return 0; }
    return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

bool FileScanner::Snapshot(std::vector<unsigned char>& storage, std::string& error) {
    using Query = NTSTATUS(NTAPI*)(ULONG, void*, ULONG, ULONG*);
    const auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (query == nullptr) { error = "NtQuerySystemInformation is unavailable"; return false; }
    constexpr size_t limit = 128 * 1024 * 1024;
    storage.resize(64 * 1024);
    for (;;) {
        ULONG needed = 0;
        const NTSTATUS status = query(64 /* SystemExtendedHandleInformation */, storage.data(), static_cast<ULONG>(storage.size()), &needed);
        if (status >= 0) { break; }
        if (static_cast<ULONG>(status) != 0xc0000004UL && static_cast<ULONG>(status) != 0xc0000023UL) {
            error = "SystemExtendedHandleInformation failed: NTSTATUS=" + std::to_string(static_cast<ULONG>(status));
            return false;
        }
        const auto required = (std::max)(storage.size() * 2, static_cast<size_t>(needed) + 4096);
        if (required > limit) { error = "Handle snapshot exceeds 128 MiB"; return false; }
        storage.resize(required);
    }
    constexpr size_t offset = offsetof(NativeSnapshot, handles);
    if (storage.size() < offset || reinterpret_cast<const NativeSnapshot*>(storage.data())->count >
        (storage.size() - offset) / sizeof(NativeHandle)) { error = "Malformed native handle snapshot"; return false; }
    return true;
}

std::wstring FileScanner::FilePath(HANDLE file) {
    std::vector<wchar_t> name(512);
    for (;;) {
        const DWORD length = GetFinalPathNameByHandleW(file, name.data(), static_cast<DWORD>(name.size()), FILE_NAME_NORMALIZED);
        if (length == 0) { return {}; }
        if (length < name.size()) { return std::wstring(name.data(), length); }
        if (length > 32768) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return {}; }
        name.resize(static_cast<size_t>(length) + 1);
    }
}

void FileScanner::ReadContent(HANDLE file, ULONGLONG deadline, ScanResult& result) {
    WinHandle read(ReOpenFile(file, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN));
    if (!read.Valid()) { Incomplete(result, "ReOpenFile", GetLastError()); return; }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(read.Get(), &size) || size.QuadPart < 0) { Incomplete(result, "GetFileSizeEx", GetLastError()); return; }
    WinHandle ready(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!ready.Valid()) { Incomplete(result, "CreateEvent", GetLastError()); return; }
    std::array<unsigned char, 64 * 1024> bytes{};
    SecretMatcher matcher;
    std::uint64_t offset = 0;
    const auto initial_length = static_cast<std::uint64_t>(size.QuadPart);
    while (offset < initial_length) {
        if (GetTickCount64() >= deadline) { Incomplete(result, "Content scan deadline", ERROR_TIMEOUT); return; }
        OVERLAPPED operation{};
        operation.Offset = static_cast<DWORD>(offset);
        operation.OffsetHigh = static_cast<DWORD>(offset >> 32);
        operation.hEvent = ready.Get();
        ResetEvent(ready.Get());
        const DWORD amount = static_cast<DWORD>((std::min)(initial_length - offset, static_cast<std::uint64_t>(bytes.size())));
        DWORD count = 0;
        if (!ReadFile(read.Get(), bytes.data(), amount, &count, &operation)) {
            const DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING) { Incomplete(result, "ReadFile", error); return; }
            const ULONGLONG now = GetTickCount64();
            const DWORD wait = now >= deadline ? 0 : static_cast<DWORD>((std::min)(deadline - now, 1000ULL));
            if (WaitForSingleObject(ready.Get(), wait) != WAIT_OBJECT_0) {
                CancelIoEx(read.Get(), &operation);
                GetOverlappedResult(read.Get(), &operation, &count, TRUE); // Keep stack/buffer alive until cancellation completes.
                Incomplete(result, "ReadFile wait", ERROR_TIMEOUT);
                return;
            }
            if (!GetOverlappedResult(read.Get(), &operation, &count, FALSE)) { Incomplete(result, "Read completion", GetLastError()); return; }
        }
        if (count == 0) { Incomplete(result, "File changed during scan", ERROR_HANDLE_EOF); return; }
        result.bytes += count;
        if (matcher.Feed(bytes.data(), count)) { result.verdict = ScanVerdict::SecretContent; result.detail = "content contains secret"; return; }
        offset += count;
    }
}

void FileScanner::Inspect(HANDLE file, ULONGLONG deadline, ScanResult& result) {
    SetLastError(ERROR_SUCCESS);
    const DWORD type = GetFileType(file);
    if (type == FILE_TYPE_UNKNOWN) {
        const DWORD error = GetLastError();
        // Device handles can have an unknown type without an API failure.
        if (error != ERROR_SUCCESS) { Incomplete(result, "GetFileType", error); }
        return;
    }
    if (type != FILE_TYPE_DISK) { return; }
    FILE_STANDARD_INFO info{};
    if (!GetFileInformationByHandleEx(file, FileStandardInfo, &info, sizeof(info))) { Incomplete(result, "FileStandardInfo", GetLastError()); return; }
    if (info.Directory) { return; }
    ++result.files;
    const auto name = FilePath(file);
    if (name.empty()) { Incomplete(result, "File name", GetLastError()); return; }
    if (SecretFilename(name)) { result.verdict = ScanVerdict::SecretName; result.path = name; result.detail = "filename contains secret"; return; }
    if (name.rfind(L"\\\\?\\UNC\\", 0) == 0) { result.path = name; Incomplete(result, "Network file content is not scanned by this PoC", ERROR_NOT_SUPPORTED); return; }
    ReadContent(file, deadline, result);
    if (result.verdict == ScanVerdict::SecretContent) { result.path = name; }
    if (result.verdict != ScanVerdict::Clear && result.path.empty()) { result.path = name; }
}

ScanResult FileScanner::InspectFile(HANDLE file, DWORD budget_ms) const {
    ScanResult result;
    Inspect(file, GetTickCount64() + budget_ms, result);
    return result;
}

ScanResult FileScanner::Scan(DWORD process_id, std::uint64_t process_created, DWORD budget_ms) const {
    ScanResult result;
    WinHandle process(OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id));
    if (!process.Valid()) { Incomplete(result, "OpenProcess", GetLastError()); return result; }
    if (process_created == 0 || CreationTime(process.Get()) != process_created) {
        Incomplete(result, "Process identity changed or creation time unavailable", ERROR_INVALID_OWNER);
        return result;
    }
    std::array<wchar_t, 32768> executable{};
    if (GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size())) == 0) {
        Incomplete(result, "Scanner executable path", GetLastError()); return result;
    }
    WinHandle probe(CreateFileW(executable.data(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, 0, nullptr));
    if (!probe.Valid()) { Incomplete(result, "File type probe", GetLastError()); return result; }
    std::vector<unsigned char> snapshot;
    if (!Snapshot(snapshot, result.detail)) { result.verdict = ScanVerdict::Incomplete; return result; }
    const auto* handles = reinterpret_cast<const NativeSnapshot*>(snapshot.data());
    USHORT file_type = 0;
    for (ULONG_PTR i = 0; i < handles->count; ++i) {
        const auto& handle = handles->handles[i];
        if (handle.process_id == GetCurrentProcessId() && handle.handle == reinterpret_cast<ULONG_PTR>(probe.Get())) { file_type = handle.type; break; }
    }
    if (file_type == 0) { Incomplete(result, "File object type was not found", ERROR_NOT_FOUND); return result; }
    const ULONGLONG deadline = GetTickCount64() + budget_ms;
    for (ULONG_PTR i = 0; i < handles->count; ++i) {
        const auto& entry = handles->handles[i];
        if (entry.process_id != process_id || entry.type != file_type ||
            (process_id == GetCurrentProcessId() && entry.handle == reinterpret_cast<ULONG_PTR>(probe.Get()))) { continue; }
        ++result.handles;
        if (GetTickCount64() >= deadline) { Incomplete(result, "Handle scan deadline", ERROR_TIMEOUT); break; }
        HANDLE raw = nullptr;
        if (!DuplicateHandle(process.Get(), reinterpret_cast<HANDLE>(entry.handle), GetCurrentProcess(), &raw, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            const DWORD error = GetLastError();
            if (error != ERROR_INVALID_HANDLE) { Incomplete(result, "DuplicateHandle", error); }
            continue;
        }
        WinHandle file(raw);
        Inspect(file.Get(), deadline, result);
        if (result.verdict == ScanVerdict::SecretName || result.verdict == ScanVerdict::SecretContent) { break; }
    }
    return result;
}
}  // namespace guard
