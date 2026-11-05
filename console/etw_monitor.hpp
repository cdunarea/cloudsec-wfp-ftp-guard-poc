#pragma once
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <array>
#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "protocol.hpp"
#include "file_activity.hpp"
#include "trace_progress.hpp"

namespace guard {
struct NetFileEvidence {
    std::vector<std::wstring> paths;
    bool complete = true;
    std::string detail;
};
class EtwMonitor {
 public:
    explicit EtwMonitor(std::wstring application, bool file_history = true);
    ~EtwMonitor();
    EtwMonitor(const EtwMonitor&) = delete;
    EtwMonitor& operator=(const EtwMonitor&) = delete;
    bool Start();
    void Stop();
    void DriverConnection(const NetEvent& event);
    std::string Summary() const;
    NetFileEvidence RecentFiles(const NetEvent& event);
 private:
    struct Session {
        EtwMonitor* owner = nullptr;
        NetTraceProgress progress;
        std::atomic<UINT64> callbacks{0};
        std::wstring name;
        std::vector<unsigned char> properties;
        TRACEHANDLE controller = 0;
        TRACEHANDLE consumer = INVALID_PROCESSTRACE_HANDLE;
        std::thread thread;
    };
    struct Observation { NetEvent event; ULONGLONG at; bool driver; bool correlated; };
    std::wstring application_;
    bool file_history_;
    std::array<Session, 2> sessions_;
    std::mutex mutex_;
    std::deque<Observation> observations_;
    std::deque<UINT64> file_processes_;
    NetFileActivityCache file_activity_;
    NetFileReadCache file_reads_;
    std::atomic<UINT64> file_opens_{0};
    std::atomic<UINT64> file_reads_observed_{0};
    std::atomic<UINT64> connections_{0};
    std::atomic<UINT64> correlations_{0};
    std::atomic<UINT64> wininet_ftp_{0};
    std::atomic<UINT64> wininet_events_{0};
    std::atomic<UINT64> wininet_connections_{0};
    static const GUID kTcpIp;
    static const GUID kKernelNetwork;
    static const GUID kWinInet;
    static const GUID kFileIo;
    static void WINAPI Callback(EVENT_RECORD* record);
    static ULONG WINAPI BufferCallback(EVENT_TRACE_LOGFILEW* logfile);
    void Record(EVENT_RECORD* record);
    bool StartSession(Session& session, bool kernel);
    bool Relevant(DWORD pid) const;
    void Observe(const NetEvent& event, bool driver);
    static bool SameTuple(const NetEvent& left, const NetEvent& right);
    static std::vector<unsigned char> Property(EVENT_RECORD* record, const wchar_t* name);
    static ULONG Number(EVENT_RECORD* record, const wchar_t* name);
    static UINT64 PointerNumber(EVENT_RECORD* record, const wchar_t* name);
    static std::string Ansi(EVENT_RECORD* record, const wchar_t* name);
    static std::wstring Wide(EVENT_RECORD* record, const wchar_t* name);
    void FileRecord(EVENT_RECORD* record);
    static UINT64 FileTimeNow();
    static void EnableProfilePrivilege();
};
}  // namespace guard
