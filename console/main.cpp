#include <WinSock2.h>
#include <Windows.h>
#include <atomic>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include "diagnostics.hpp"
#include "net_driver_session.hpp"
#include "etw_monitor.hpp"
#include "file_scanner.hpp"
#include "ftp_transfer.hpp"

class Console {
 public:
    static int Run(int argc, wchar_t** argv) {
        Options options = Parse(argc, argv);
        if (options.help) { Help(); return 0; }
        WSADATA sockets{};
        if (WSAStartup(MAKEWORD(2, 2), &sockets) != 0) { throw std::runtime_error("WSAStartup failed"); }
        struct SocketLifetime { ~SocketLifetime() { WSACleanup(); } } socket_lifetime;
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCtrlHandler(Ctrl, TRUE);
        guard::WinHandle stop_event(CreateEventW(nullptr, TRUE, FALSE,
            options.stop_event.empty() ? nullptr : options.stop_event.c_str()));
        if (!stop_event.Valid()) { throw std::runtime_error("Cannot create shutdown event"); }
        EnableDebugPrivilege();
        guard::EtwMonitor etw(options.application, !options.etw_only);
        if (options.etw && !etw.Start() && options.etw_only) { throw std::runtime_error("ETW network session could not be started (run elevated)"); }
        std::unique_ptr<guard::NetDriverSession> driver;
        if (!options.etw_only) { driver = std::make_unique<guard::NetDriverSession>(options.driver, options.application); }
        guard::Diagnostics::Line("[READY] " + std::string(options.etw_only ? "ETW only; no driver loaded, no blocking" : "WFP enforcement active") +
            "; Ctrl+C to stop; app=" + (options.application.empty() ? "all applications" : guard::Diagnostics::Utf8(options.application)));
        const ULONGLONG deadline = options.seconds == 0 ? 0 : GetTickCount64() + static_cast<ULONGLONG>(options.seconds) * 1000;
        while (!stopping_.load() && WaitForSingleObject(stop_event.Get(), 0) == WAIT_TIMEOUT &&
               (deadline == 0 || GetTickCount64() < deadline)) {
            guard::NetEvent event{};
            if (driver && driver->Next(event)) { Handle(*driver, etw, event); }
            else { WaitForSingleObject(stop_event.Get(), 25); }
        }
        if (driver) {
            const auto status = driver->ReadStatus();
            guard::Diagnostics::Line("[DRIVER SUMMARY] ftp_inspections=" + std::to_string(status.detections) +
                " blocked_flows=" + std::to_string(status.blocked) + " allowed_decisions=" + std::to_string(status.allowed));
            driver.reset();
        }
        etw.Stop();
        guard::Diagnostics::Line(etw.Summary());
        return 0;
    }
 private:
    struct Options {
        std::wstring driver;
        std::wstring application;
        std::wstring stop_event;
        DWORD seconds = 0;
        bool etw = true;
        bool etw_only = false;
        bool help = false;
    };
    inline static std::atomic<bool> stopping_{false};
    inline static guard::FileScanner scanner_;
    static BOOL WINAPI Ctrl(DWORD kind) {
        if (kind == CTRL_C_EVENT || kind == CTRL_BREAK_EVENT || kind == CTRL_CLOSE_EVENT || kind == CTRL_SHUTDOWN_EVENT) { stopping_.store(true); return TRUE; }
        return FALSE;
    }
    static void Help() {
        guard::Diagnostics::Line("ftp-guard [--driver file.sys] [--app full-path.exe] [--seconds N] [--no-etw]\n"
            "ftp-guard --etw-only [--app full-path.exe] [--seconds N]\n"
            "Optional --stop-event Local\\name allows a test controller to request orderly unload.\n"
            "Run elevated. Monitor inbound/outbound IPv4/IPv6 TCP on every port.\n"
            "On-demand scans guard client uploads and server RETR data. Explicit FTPS uses conservative process/peer correlation; TLS is not decrypted.\n"
            "ETW supplies short-lived file-open evidence. --no-etw makes required transfer evidence incomplete (blocked).");
    }
    static Options Parse(int argc, wchar_t** argv) {
        Options options;
        std::array<wchar_t, 32768> path{};
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0 || length >= path.size()) { throw std::runtime_error("Cannot locate executable"); }
        auto directory = std::filesystem::path(path.data()).parent_path();
        for (int i = 0; i < 4; ++i) {
            const auto candidate = directory / L"driver" / L"WfpFtpGuard.sys";
            if (std::filesystem::exists(candidate)) { options.driver = candidate.wstring(); break; }
            directory = directory.parent_path();
        }
        for (int i = 1; i < argc; ++i) {
            const std::wstring option = argv[i];
            if (option == L"--help" || option == L"-h") { options.help = true; }
            else if (option == L"--etw-only") { options.etw_only = true; }
            else if (option == L"--no-etw") { options.etw = false; }
            else if ((option == L"--driver" || option == L"--app" || option == L"--seconds" || option == L"--stop-event") && i + 1 < argc) {
                const std::wstring value = argv[++i];
                if (option == L"--driver") { options.driver = std::filesystem::absolute(value).wstring(); }
                if (option == L"--app") { options.application = std::filesystem::absolute(value).wstring(); }
                if (option == L"--stop-event") { options.stop_event = value; }
                if (option == L"--seconds") {
                    size_t consumed = 0;
                    const auto seconds = std::stoul(value, &consumed);
                    if (consumed != value.size() || seconds > 86400) { throw std::runtime_error("--seconds must be between 0 and 86400"); }
                    options.seconds = static_cast<DWORD>(seconds);
                }
            } else { throw std::runtime_error("Unknown or incomplete option; use --help"); }
        }
        if (options.etw_only && !options.etw) { throw std::runtime_error("--etw-only conflicts with --no-etw"); }
        return options;
    }
    static void EnableDebugPrivilege() {
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &raw)) { return; }
        guard::WinHandle token(raw);
        TOKEN_PRIVILEGES privilege{};
        privilege.PrivilegeCount = 1;
        if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privilege.Privileges[0].Luid)) {
            privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token.Get(), FALSE, &privilege, 0, nullptr, nullptr);
        }
    }
    static void Handle(guard::NetDriverSession& driver, guard::EtwMonitor& etw, const guard::NetEvent& event) {
        if (event.kind == guard::NetEventKind::Flow) { guard::Diagnostics::Connection("WFP", event); etw.DriverConnection(event); return; }
        if (event.kind == guard::NetEventKind::FtpControl || event.kind == guard::NetEventKind::Transfer) {
            guard::Diagnostics::Line(std::string(event.kind == guard::NetEventKind::FtpControl ? "[FTP CONFIRMED]" : "[FTP TRANSFER]") +
                " flow=" + std::to_string(event.flow) + " pid=" + std::to_string(event.process_id) +
                " role=" + ((event.flags & guard::NetServer) != 0 ? "server" : "client") +
                " command=" + event.evidence + ((event.flags & guard::NetExplicitTls) != 0 ? " explicit-ftps=recognized plaintext-after-upgrade=unavailable" : ""));
            return;
        }
        if (event.kind == guard::NetEventKind::InspectFtp) { Inspect(driver, etw, event); return; }
        const char* kind = event.kind == guard::NetEventKind::Blocked ? "BLOCKED" : event.kind == guard::NetEventKind::Allowed ? "ALLOWED" :
                           event.kind == guard::NetEventKind::Closed ? "CLOSED" : "ERROR";
        guard::Diagnostics::Line(std::string("[DRIVER ") + kind + "] flow=" + std::to_string(event.flow) + " pid=" +
            std::to_string(event.process_id) + " detail=" + std::to_string(event.detail) +
            (event.kind == guard::NetEventKind::Error || event.kind == guard::NetEventKind::Closed ? " context=" + std::string(event.evidence) : ""));
    }
    static void Inspect(guard::NetDriverSession& driver, guard::EtwMonitor& etw, const guard::NetEvent& event) {
        guard::Diagnostics::Line("[TRANSFER INSPECTION] flow=" + std::to_string(event.flow) + " pid=" + std::to_string(event.process_id) +
            " role=" + ((event.flags & guard::NetServer) != 0 ? "server" : "client") +
            " trigger=" + event.evidence + " control_flow=" + std::to_string(event.control_flow) +
            ((event.flags & guard::NetData) != 0 ? " association=process-and-peer" : " association=control-command") +
            ((event.flags & guard::NetAmbiguous) != 0 ? " ambiguous=yes" : "") +
            ((event.flags & guard::NetExplicitTls) != 0 ? " control-upgrade=requested data-protection=unavailable decrypted=no" : ""));
        if ((event.flags & guard::NetData) == 0) {
            // Opening an optional shell resource is not proof it is an upload
            // source. Release the qualified command; the separate data flow
            // remains held until actual source-read evidence is inspected.
            const bool accepted = driver.Decide(event.flow, false);
            guard::Diagnostics::Line("[ALLOW] flow=" + std::to_string(event.flow) + " pid=" + std::to_string(event.process_id) +
                " rule=ftp-control-qualified file-inspection=pending-data-read verdict_scope=command" +
                (accepted ? " decision=accepted" : " decision=stale-or-failed error=" + std::to_string(GetLastError())));
            return;
        }
        const auto recent = etw.RecentFiles(event);
        auto result = scanner_.Scan(static_cast<DWORD>(event.process_id), event.process_created, 8000, recent.paths, true,
            (event.flags & guard::NetData) != 0 ? event.flow : 0);
        if (!recent.complete && result.verdict == guard::ScanVerdict::Clear) {
            result.verdict = guard::ScanVerdict::Incomplete;
            result.detail = recent.detail;
        }
        if (result.verdict == guard::ScanVerdict::Clear && result.files == 0 && (event.flags & guard::NetData) != 0) {
            if ((event.flags & guard::NetExplicitTls) == 0) {
                result.verdict = guard::ScanVerdict::Incomplete;
                result.detail = "outgoing FTP data has no observed source read";
            } else {
                guard::Diagnostics::Line("[COVERAGE] flow=" + std::to_string(event.flow) +
                    " explicit FTPS candidate without a source read; passed for handshake compatibility; no content verdict");
            }
        }
        const char* rule = result.verdict == guard::ScanVerdict::SecretName ? "secret-filename" :
                           result.verdict == guard::ScanVerdict::SecretContent ? "secret-content" :
                           result.verdict == guard::ScanVerdict::Incomplete ? "inspection-incomplete" :
                           result.files == 0 ? "no-source-observed" : "source-files-clear";
        const bool verified = guard::NetTransferGate::GrantDataFlow((event.flags & guard::NetData) != 0,
            (event.flags & guard::NetExplicitTls) != 0, result.Block(), result.files);
        const bool accepted = driver.Decide(event.flow, result.Block(), verified);
        guard::Diagnostics::Line(std::string(result.Block() ? "[BLOCK]" : "[ALLOW]") + " flow=" + std::to_string(event.flow) +
            " pid=" + std::to_string(event.process_id) + " rule=" + rule + " file=\"" + guard::Diagnostics::Utf8(result.path) +
            "\" open_file_handles=" + std::to_string(result.handles) + " scanned_files=" + std::to_string(result.files) +
            " scanned_bytes=" + std::to_string(result.bytes) + " recent_files=" + std::to_string(result.recent_files) +
            " cached_files=" + std::to_string(result.cached_files) +
            " file_evidence=" + ((event.flags & guard::NetData) != 0 ? "observed-file-read" : "observed-file-open") + " detail=" + result.detail +
            (verified ? " verdict_scope=data-flow" : " verdict_scope=indication") +
            (accepted ? " decision=accepted" : " decision=stale-or-failed error=" + std::to_string(GetLastError())));
    }
};

int wmain(int argc, wchar_t** argv) {
    try { return Console::Run(argc, argv); }
    catch (const std::exception& error) { guard::Diagnostics::Line(std::string("[FATAL] ") + error.what()); return 1; }
}
