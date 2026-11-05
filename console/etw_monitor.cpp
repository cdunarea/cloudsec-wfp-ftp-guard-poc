#include "etw_monitor.hpp"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <tdh.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include "diagnostics.hpp"

namespace guard {
const GUID EtwMonitor::kTcpIp = {0x9a280ac0,0xc8e0,0x11d1,{0x84,0xe2,0x00,0xc0,0x4f,0xb9,0x98,0xa2}};
const GUID EtwMonitor::kKernelNetwork = {0x7dd42a49,0x5329,0x4832,{0x8d,0xfd,0x43,0xd9,0x79,0x15,0x3a,0x88}};
const GUID EtwMonitor::kWinInet = {0x43d1a55c,0x76d6,0x4f7e,{0x99,0x5c,0x64,0xc7,0x11,0xe5,0xca,0xfe}};
const GUID EtwMonitor::kFileIo = {0x90cbdc39,0x4a3e,0x11d1,{0x84,0xf4,0x00,0x00,0xf8,0x04,0x64,0xe3}};

EtwMonitor::EtwMonitor(std::wstring application, bool file_history)
    : application_(std::move(application)), file_history_(file_history) {}
EtwMonitor::~EtwMonitor() { Stop(); }

void EtwMonitor::EnableProfilePrivilege() {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &raw)) { return; }
    WinHandle token(raw);
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    if (LookupPrivilegeValueW(nullptr, SE_SYSTEM_PROFILE_NAME, &privileges.Privileges[0].Luid)) {
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token.Get(), FALSE, &privileges, 0, nullptr, nullptr);
    }
}

bool EtwMonitor::StartSession(Session& session, bool kernel) {
    session.owner = this;
    session.name = L"WfpFtpGuard-" + std::to_wstring(GetCurrentProcessId()) + (kernel ? L"-Net-" : L"-WinInet-") + std::to_wstring(GetTickCount64());
    session.properties.resize(sizeof(EVENT_TRACE_PROPERTIES) + (session.name.size() + 1) * sizeof(wchar_t));
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(session.properties.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(session.properties.size());
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 1;
    properties->Wnode.Guid = {0x9ab22000UL ^ GetCurrentProcessId(),0x3df1,0x442e,{0x90,0x21,0x10,0x28,0x33,0x41,0x55,static_cast<UCHAR>(kernel)}};
    properties->BufferSize = 64;
    properties->MinimumBuffers = 4;
    properties->MaximumBuffers = 32;
    properties->FlushTimer = 1;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | (kernel ? EVENT_TRACE_SYSTEM_LOGGER_MODE : 0);
    if (kernel && file_history_) { properties->LogFileMode |= EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING; }
    properties->EnableFlags = kernel ? EVENT_TRACE_FLAG_NETWORK_TCPIP : 0;
    if (kernel && file_history_) {
        properties->EnableFlags |= EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT;
    }
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    const ULONG error = StartTraceW(&session.controller, session.name.c_str(), properties);
    if (error != ERROR_SUCCESS) { Diagnostics::Line("[ETW] StartTrace failed: error=" + std::to_string(error)); session.controller = 0; return false; }
    if (!kernel) {
        const ULONG enable = EnableTraceEx2(session.controller, &kWinInet, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                           TRACE_LEVEL_VERBOSE, ~0ULL, 0, 0, nullptr);
        if (enable != ERROR_SUCCESS) { Diagnostics::Line("[ETW] WinINet provider unavailable: error=" + std::to_string(enable)); return false; }
    }
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = session.name.data();
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = Callback;
    logfile.BufferCallback = BufferCallback;
    logfile.Context = &session;
    session.consumer = OpenTraceW(&logfile);
    if (session.consumer == INVALID_PROCESSTRACE_HANDLE) { Diagnostics::Line("[ETW] OpenTrace failed: error=" + std::to_string(GetLastError())); return false; }
    session.thread = std::thread([&session] {
        const auto error_code = ProcessTrace(&session.consumer, 1, nullptr, nullptr);
        session.progress.Finish();
        if (error_code != ERROR_SUCCESS && error_code != ERROR_CANCELLED) { Diagnostics::Line("[ETW] ProcessTrace ended: error=" + std::to_string(error_code)); }
    });
    return true;
}

bool EtwMonitor::Start() {
    EnableProfilePrivilege();
    const bool network = StartSession(sessions_[0], true);
    const bool wininet = StartSession(sessions_[1], false);
    Diagnostics::Line(std::string("[ETW] TCP/IP=") + (network ? "on" : "unavailable") + ", WinINet=" + (wininet ? "on" : "unavailable") +
        ", file-open history=" + (network && file_history_ ? "on" : "off"));
    return network;
}

void EtwMonitor::Stop() {
    for (auto& session : sessions_) {
        session.progress.Finish();
        if (session.controller != 0) {
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(session.properties.data());
            const ULONG status = ControlTraceW(session.controller, session.name.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
            if (status == ERROR_SUCCESS && properties->EventsLost != 0) { Diagnostics::Line("[ETW] lost events=" + std::to_string(properties->EventsLost)); }
            session.controller = 0;
        }
        if (session.consumer != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(session.consumer); }
        if (session.thread.joinable()) { session.thread.join(); }
        session.consumer = INVALID_PROCESSTRACE_HANDLE;
    }
}

bool EtwMonitor::Relevant(DWORD pid) const {
    return application_.empty() || _wcsicmp(Diagnostics::ProcessPath(pid).c_str(), application_.c_str()) == 0;
}

std::vector<unsigned char> EtwMonitor::Property(EVENT_RECORD* record, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR property{};
    property.PropertyName = reinterpret_cast<ULONGLONG>(name);
    property.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    if (TdhGetPropertySize(record, 0, nullptr, 1, &property, &size) != ERROR_SUCCESS || size == 0 || size > 65536) { return {}; }
    std::vector<unsigned char> value(size);
    if (TdhGetProperty(record, 0, nullptr, 1, &property, size, value.data()) != ERROR_SUCCESS) { return {}; }
    return value;
}

ULONG EtwMonitor::Number(EVENT_RECORD* record, const wchar_t* name) {
    const auto bytes = Property(record, name);
    ULONG number = 0;
    if (!bytes.empty() && bytes.size() <= sizeof(number)) { memcpy_s(&number, sizeof(number), bytes.data(), bytes.size()); }
    return number;
}
UINT64 EtwMonitor::PointerNumber(EVENT_RECORD* record, const wchar_t* name) {
    const auto bytes = Property(record, name);
    UINT64 number = 0;
    if (!bytes.empty() && bytes.size() <= sizeof(number)) { memcpy_s(&number, sizeof(number), bytes.data(), bytes.size()); }
    return number;
}

std::string EtwMonitor::Ansi(EVENT_RECORD* record, const wchar_t* name) {
    const auto bytes = Property(record, name);
    const auto end = std::find(bytes.begin(), bytes.end(), 0);
    return std::string(bytes.begin(), end);
}
std::wstring EtwMonitor::Wide(EVENT_RECORD* record, const wchar_t* name) {
    const auto bytes = Property(record, name);
    if (bytes.empty() || bytes.size() % sizeof(wchar_t) != 0) { return {}; }
    std::wstring value(bytes.size() / sizeof(wchar_t), L'\0');
    memcpy_s(value.data(), bytes.size(), bytes.data(), bytes.size());
    const auto end = value.find(L'\0');
    if (end != std::wstring::npos) { value.resize(end); }
    return value;
}
void EtwMonitor::FileRecord(EVENT_RECORD* record) {
    const auto opcode = record->EventHeader.EventDescriptor.Opcode;
    if (opcode != 64 && opcode != 66 && opcode != 67) { return; }
    const auto pid = record->EventHeader.ProcessId;
    if (pid == GetCurrentProcessId()) { return; } // Scanning must not create its own evidence/decoder backlog.
    const auto object = PointerNumber(record, L"FileObject");
    const auto at = record->EventHeader.TimeStamp.QuadPart;
    if (at <= 0) { return; }
    if (opcode != 64) {
        std::lock_guard lock(mutex_);
        if (opcode == 66) { file_reads_.Close(object); }
        else if (Number(record, L"IoSize") != 0 && file_reads_.Read(pid, object, static_cast<UINT64>(at))) { ++file_reads_observed_; }
        return;
    }
    bool known = false;
    {
        std::lock_guard lock(mutex_);
        known = std::find(file_processes_.begin(), file_processes_.end(), pid) != file_processes_.end();
    }
    // Capture a selected client's opens even before its first TCP connection.
    if (!known && !Relevant(pid)) { return; }
    const auto path = Wide(record, L"OpenPath");
    if (path.empty() || path.back() == L'\\' || (Number(record, L"CreateOptions") & 1U) != 0) { return; }
    std::lock_guard lock(mutex_);
    file_activity_.Record(pid, static_cast<UINT64>(at), path);
    file_reads_.Open(pid, object, static_cast<UINT64>(at), path);
    ++file_opens_;
}
UINT64 EtwMonitor::FileTimeNow() {
    FILETIME time{};
    GetSystemTimePreciseAsFileTime(&time);
    return (static_cast<UINT64>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}
NetFileEvidence EtwMonitor::RecentFiles(const NetEvent& event) {
    if (!file_history_ || sessions_[0].controller == 0 || sessions_[0].consumer == INVALID_PROCESSTRACE_HANDLE) {
        return {{}, false, "file-open history unavailable; transfer inspection cannot certify closed handles"};
    }
    auto& session = sessions_[0];
    auto storage = session.properties;
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(storage.data());
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->LogFileNameOffset = 0;
    const auto started = GetTickCount64();
    const ULONG status = ControlTraceW(session.controller, session.name.c_str(), properties, EVENT_TRACE_CONTROL_FLUSH);
    if (status != ERROR_SUCCESS) { return {{}, false, "ETW flush: error=" + std::to_string(status)}; }
    if (properties->EventsLost != 0 || properties->RealTimeBuffersLost != 0) { return {{}, false, "ETW file evidence lost"}; }
    // BufferCallback runs after every event in a delivered buffer. Wait for the
    // flushed buffer count, rather than guessing when the timer has delivered it.
    const auto target = properties->BuffersWritten;
    bool delivered = session.progress.Wait(target, std::chrono::milliseconds(1000));
    if (!delivered) {
        // A real-time consumer can still have a partial producer buffer. Flush
        // again and wait for the original barrier, without chasing new buffers.
        const ULONG retry = ControlTraceW(session.controller, session.name.c_str(), properties, EVENT_TRACE_CONTROL_FLUSH);
        if (retry != ERROR_SUCCESS || properties->EventsLost != 0 || properties->RealTimeBuffersLost != 0) {
            return {{}, false, "ETW retry flush failed or lost file evidence: error=" + std::to_string(retry)};
        }
        delivered = session.progress.Wait(target, std::chrono::milliseconds(3000));
    }
    Diagnostics::Line("[ETW SYNC] flushed_buffers=" + std::to_string(target) +
        " delivered_buffers=" + std::to_string(session.progress.Buffers()) + " elapsed_ms=" + std::to_string(GetTickCount64() - started) +
        " callbacks=" + std::to_string(session.callbacks.load()));
    if (!delivered) { return {{}, false, "ETW file evidence delivery timed out or consumer stopped"}; }
    std::lock_guard lock(mutex_);
    const auto since = event.file_since != 0 ? event.file_since : event.captured_at;
    const bool data = (event.flags & NetData) != 0;
    if ((data ? file_reads_.Evictions() : file_activity_.Evictions()) != 0) {
        return {{}, false, "bounded file evidence cache evicted records"};
    }
    return {data ? file_reads_.Paths(event.process_id, since, FileTimeNow()) :
                   file_activity_.Paths(event.process_id, since, FileTimeNow()), true, {}};
}

void WINAPI EtwMonitor::Callback(EVENT_RECORD* record) {
    auto* session = static_cast<Session*>(record->UserContext);
    if (session == nullptr || session->owner == nullptr) { return; }
    try { session->owner->Record(record); }
    catch (const std::exception& error) { Diagnostics::Line(std::string("[ETW] decode error: ") + error.what()); }
}
ULONG WINAPI EtwMonitor::BufferCallback(EVENT_TRACE_LOGFILEW* logfile) {
    auto* session = static_cast<Session*>(logfile->Context);
    if (session != nullptr) {
        const auto callbacks = ++session->callbacks;
        if (callbacks <= 3) {
            Diagnostics::Line("[ETW BUFFER] buffers_read=" + std::to_string(logfile->BuffersRead) + " callbacks=" + std::to_string(callbacks));
        }
        session->progress.Advance(logfile->BuffersRead);
    }
    return TRUE;
}

void EtwMonitor::Record(EVENT_RECORD* record) {
    if (IsEqualGUID(record->EventHeader.ProviderId, kFileIo)) { FileRecord(record); return; }
    if (IsEqualGUID(record->EventHeader.ProviderId, kWinInet)) {
        ++wininet_events_;
        if (record->EventHeader.EventDescriptor.Id == 103) { ++wininet_connections_; }
        if (record->EventHeader.EventDescriptor.Id != 103 || !Relevant(record->EventHeader.ProcessId)) { return; }
        auto service = Ansi(record, L"Service");
        std::transform(service.begin(), service.end(), service.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        if (service.find("FTP") == std::string::npos) { return; }
        ++wininet_ftp_;
        Diagnostics::Line("[ETW FTP] source=WinINet/InternetConnect pid=" + std::to_string(record->EventHeader.ProcessId) +
            " image=\"" + Diagnostics::Utf8(Diagnostics::ProcessPath(record->EventHeader.ProcessId)) + "\" server=" +
            Ansi(record, L"ServerName") + ':' + std::to_string(Number(record, L"ServerPort")) + " service=" + service);
        return;
    }
    if (!IsEqualGUID(record->EventHeader.ProviderId, kTcpIp) && !IsEqualGUID(record->EventHeader.ProviderId, kKernelNetwork)) { return; }
    const UCHAR opcode = record->EventHeader.EventDescriptor.Opcode;
    if (opcode != 12 && opcode != 28) { return; } // TcpIp Connect IPv4 / IPv6.
    NetEvent event{};
    event.version = kVersion;
    event.kind = NetEventKind::Flow;
    event.process_id = Number(record, L"PID");
    if (event.process_id == 0) { return; }
    const auto remote = Property(record, L"daddr");
    const auto local = Property(record, L"saddr");
    const size_t length = opcode == 28 ? 16 : 4;
    if (remote.size() != length || local.size() != length) { return; }
    event.family = opcode == 28 ? AF_INET6 : AF_INET;
    memcpy_s(event.remote_address, sizeof(event.remote_address), remote.data(), length);
    memcpy_s(event.local_address, sizeof(event.local_address), local.data(), length);
    event.remote_port = ntohs(static_cast<USHORT>(Number(record, L"dport")));
    event.local_port = ntohs(static_cast<USHORT>(Number(record, L"sport")));
    ++connections_;
    // Correlate even after a short-lived application exits and its image path can no longer be queried.
    Observe(event, false);
    if (Relevant(static_cast<DWORD>(event.process_id))) {
        Diagnostics::Connection("ETW/TCPIP candidate (payload not inspected)", event);
    }
}

bool EtwMonitor::SameTuple(const NetEvent& a, const NetEvent& b) {
    if (a.process_id != b.process_id || a.family != b.family || a.remote_port != b.remote_port || a.local_port != b.local_port) { return false; }
    const size_t bytes = a.family == AF_INET6 ? 16 : 4;
    return std::equal(a.remote_address, a.remote_address + bytes, b.remote_address) &&
           std::equal(a.local_address, a.local_address + bytes, b.local_address);
}

void EtwMonitor::Observe(const NetEvent& event, bool driver) {
    UINT64 matched = 0;
    {
        std::lock_guard lock(mutex_);
        const ULONGLONG now = GetTickCount64();
        while (!observations_.empty() && (now - observations_.front().at > 30000 || observations_.size() >= 1024)) { observations_.pop_front(); }
        for (auto& observed : observations_) {
            if (observed.driver != driver && !observed.correlated && SameTuple(event, observed.event)) {
                observed.correlated = true;
                matched = driver ? event.flow : observed.event.flow;
                ++correlations_;
                break;
            }
        }
        observations_.push_back({event, now, driver, matched != 0});
    }
    if (matched != 0) { Diagnostics::Line("[CORRELATED] ETW/TCPIP <-> WFP flow=" + std::to_string(matched) + " pid=" + std::to_string(event.process_id) + " (PID + full connection tuple)"); }
}

void EtwMonitor::DriverConnection(const NetEvent& event) {
    {
        std::lock_guard lock(mutex_);
        if (file_processes_.size() >= 1024) { file_processes_.pop_front(); }
        file_processes_.push_back(event.process_id);
    }
    Observe(event, true);
}
std::string EtwMonitor::Summary() const {
    return "[ETW SUMMARY] tcp_connections=" + std::to_string(connections_.load()) + " wininet_ftp=" +
           std::to_string(wininet_ftp_.load()) + " correlated=" + std::to_string(correlations_.load()) +
           " wininet_events=" + std::to_string(wininet_events_.load()) + " wininet_connections=" + std::to_string(wininet_connections_.load()) +
           " file_opens=" + std::to_string(file_opens_.load()) + " source_reads=" + std::to_string(file_reads_observed_.load());
}
}  // namespace guard
