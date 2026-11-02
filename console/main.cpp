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
        EnableDebugPrivilege();
        guard::EtwMonitor etw(options.application);
        if (options.etw && !etw.Start() && options.etw_only) { throw std::runtime_error("ETW network session could not be started (run elevated)"); }
        std::unique_ptr<guard::NetDriverSession> driver;
        if (!options.etw_only) { driver = std::make_unique<guard::NetDriverSession>(options.driver, options.application); }
        guard::Diagnostics::Line("[READY] " + std::string(options.etw_only ? "ETW only; no driver loaded, no blocking" : "WFP enforcement active") +
            "; Ctrl+C to stop; app=" + (options.application.empty() ? "all applications" : guard::Diagnostics::Utf8(options.application)));
        const ULONGLONG deadline = options.seconds == 0 ? 0 : GetTickCount64() + static_cast<ULONGLONG>(options.seconds) * 1000;
        while (!stopping_.load() && (deadline == 0 || GetTickCount64() < deadline)) {
            guard::NetEvent event{};
            if (driver && driver->Next(event)) { Handle(*driver, etw, event); }
            else { Sleep(25); }
        }
        if (driver) {
            const auto status = driver->ReadStatus();
            guard::Diagnostics::Line("[DRIVER SUMMARY] ftp=" + std::to_string(status.detections) + " blocked=" + std::to_string(status.blocked) + " allowed=" + std::to_string(status.allowed));
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
        DWORD seconds = 0;
        bool etw = true;
        bool etw_only = false;
        bool help = false;
    };
    inline static std::atomic<bool> stopping_{false};
    static BOOL WINAPI Ctrl(DWORD kind) {
        if (kind == CTRL_C_EVENT || kind == CTRL_BREAK_EVENT || kind == CTRL_CLOSE_EVENT || kind == CTRL_SHUTDOWN_EVENT) { stopping_.store(true); return TRUE; }
        return FALSE;
    }
    static void Help() {
        guard::Diagnostics::Line("ftp-guard [--driver file.sys] [--app full-path.exe] [--seconds N] [--no-etw]\n"
            "ftp-guard --etw-only [--app full-path.exe] [--seconds N]\n"
            "Run elevated. Default: monitor outbound IPv4/IPv6 TCP on every port.\n"
            "Driver confirms plaintext FTP control commands; ETW alone reports TCP candidates and WinINet FTP API events.");
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
            else if ((option == L"--driver" || option == L"--app" || option == L"--seconds") && i + 1 < argc) {
                const std::wstring value = argv[++i];
                if (option == L"--driver") { options.driver = std::filesystem::absolute(value).wstring(); }
                if (option == L"--app") { options.application = std::filesystem::absolute(value).wstring(); }
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
        if (event.kind == guard::EventKind::Flow) { guard::Diagnostics::Connection("WFP", event); etw.DriverConnection(event); return; }
        if (event.kind == guard::EventKind::InspectFtp) { Inspect(driver, event); return; }
        const char* kind = event.kind == guard::EventKind::Blocked ? "BLOCKED" : event.kind == guard::EventKind::Allowed ? "ALLOWED" : "ERROR";
        guard::Diagnostics::Line(std::string("[DRIVER ") + kind + "] flow=" + std::to_string(event.flow) + " pid=" +
            std::to_string(event.process_id) + " detail=" + std::to_string(event.detail));
    }
    static void Inspect(guard::NetDriverSession& driver, const guard::NetEvent& event) {
        guard::Diagnostics::Line("[FTP CONFIRMED] flow=" + std::to_string(event.flow) + " pid=" + std::to_string(event.process_id) +
            " port=" + std::to_string(event.remote_port) + " control-command=" + std::string(event.evidence));
        const auto result = guard::FileScanner().Scan(static_cast<DWORD>(event.process_id), event.process_created);
        const char* rule = result.verdict == guard::ScanVerdict::SecretName ? "secret-filename" :
                           result.verdict == guard::ScanVerdict::SecretContent ? "secret-content" :
                           result.verdict == guard::ScanVerdict::Incomplete ? "inspection-incomplete" : "no-secret-open-file";
        const bool accepted = driver.Decide(event.flow, result.Block());
        guard::Diagnostics::Line(std::string(result.Block() ? "[BLOCK]" : "[ALLOW]") + " flow=" + std::to_string(event.flow) +
            " pid=" + std::to_string(event.process_id) + " rule=" + rule + " file=\"" + guard::Diagnostics::Utf8(result.path) +
            "\" open_file_handles=" + std::to_string(result.handles) + " scanned_files=" + std::to_string(result.files) +
            " scanned_bytes=" + std::to_string(result.bytes) + " detail=" + result.detail +
            (accepted ? " decision=accepted" : " decision=stale-or-failed error=" + std::to_string(GetLastError())));
    }
};

int wmain(int argc, wchar_t** argv) {
    try { return Console::Run(argc, argv); }
    catch (const std::exception& error) { guard::Diagnostics::Line(std::string("[FATAL] ") + error.what()); return 1; }
}
