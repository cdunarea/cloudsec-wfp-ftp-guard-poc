#include <Windows.h>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include "file_scanner.hpp"
#include "ftp_probe.hpp"
#include "secret_matcher.hpp"

class Tests {
 public:
    static int Run() {
        Parser();
        Matchers();
        Files();
        std::cout << "Assertions=" << checks_ << " failures=" << failures_ << '\n';
        return failures_ == 0 ? 0 : 1;
    }
 private:
    inline static size_t checks_ = 0;
    inline static size_t failures_ = 0;
    static void Check(bool ok, const char* description) {
        ++checks_;
        if (!ok) { ++failures_; std::cerr << "FAIL " << description << '\n'; }
    }
    static guard::ProtocolVerdict Feed(guard::FtpProbe& probe, bool send, const std::string& value) {
        return probe.Feed(send, reinterpret_cast<const unsigned char*>(value.data()), value.size());
    }
    static void Parser() {
        using guard::ProtocolVerdict;
        const std::string greeting = "220 Welcome to the file server\r\n";
        const std::vector<std::string> valid{
            "USER anonymous\r\n", "PASS password\r\n", "ACCT account\r\n", "QUIT\r\n", "NOOP\r\n", "SYST\r\n", "FEAT\r\n",
            "PASV\r\n", "EPSV\r\n", "TYPE I\r\n", "OPTS UTF8 ON\r\n", "RETR a.txt\r\n", "STOR a.txt\r\n", "APPE a.txt\r\n",
            "CWD /\r\n", "CDUP\r\n", "PWD\r\n", "DELE a.txt\r\n", "MKD dir\r\n", "RMD dir\r\n", "RNFR old\r\n", "RNTO new\r\n",
            "PORT 127,0,0,1,1,2\r\n", "EPRT |1|127.0.0.1|4242|\r\n", "AUTH TLS\r\n", "USER Jos\xC3\xA9\r\n"};
        for (auto line : valid) {
            for (int lowercase = 0; lowercase < 2; ++lowercase) {
                if (lowercase) { std::transform(line.begin(), line.end(), line.begin(), [](unsigned char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : static_cast<char>(c); }); }
                for (size_t cut = 0; cut <= line.size(); ++cut) {
                    guard::FtpProbe probe;
                    probe.Reset();
                    Check(Feed(probe, false, greeting) == ProtocolVerdict::Unknown, "greeting alone does not classify client protocol");
                    Feed(probe, true, line.substr(0, cut));
                    Check(Feed(probe, true, line.substr(cut)) == ProtocolVerdict::Ftp, "FTP command across every split");
                    Check(probe.Verb()[0] != '\0' && probe.HasGreeting(), "FTP evidence excludes arguments");
                    Check(Feed(probe, true, "GET / HTTP/1.1\r\n") == ProtocolVerdict::Ftp, "FTP verdict remains stable");
                }
            }
        }
        for (size_t cut = 0; cut <= greeting.size(); ++cut) {
            guard::FtpProbe probe;
            probe.Reset();
            Feed(probe, false, greeting.substr(0, cut)); Feed(probe, false, greeting.substr(cut));
            Check(Feed(probe, true, "USER a\r\n") == ProtocolVerdict::Ftp, "split server greeting");
        }
        const std::vector<std::string> invalid{"GET / HTTP/1.1\r\n", "POST / HTTP/1.1\r\n", "EHLO local\r\n", "SSH-2.0-client\r\n", "USER a\n", "AUTH PLAIN x\r\n", "STOMP\r\n", std::string("\x16\x03\x03",3), std::string("\x7f",1), std::string("\x80",1), std::string(600,'U')};
        for (const auto& line : invalid) {
            guard::FtpProbe probe; probe.Reset(); Feed(probe, false, greeting);
            Check(Feed(probe, true, line) == ProtocolVerdict::Other, "non-FTP and malformed headers rejected");
            Check(Feed(probe, true, "PASV\r\n") == ProtocolVerdict::Other, "HTTP body cannot change a non-FTP verdict");
        }
        guard::FtpProbe probe; probe.Reset();
        Check(Feed(probe, true, "USER a\r\n") == ProtocolVerdict::Other, "ambiguous USER requires 220 greeting");
        probe.Reset(); Feed(probe, false, "+OK POP3 ready\r\n");
        Check(Feed(probe, true, "USER a\r\n") == ProtocolVerdict::Other, "POP3 USER is not FTP");
        probe.Reset();
        Check(Feed(probe, true, "EPSV\r\n") == ProtocolVerdict::Ftp, "distinctive FTP command does not require a banner");
        probe.Reset(); Feed(probe, false, std::string(600,'x'));
        Check(Feed(probe, true, "USER a\r\n") == ProtocolVerdict::Other, "oversized banner bounded");
        probe.Reset(); Feed(probe, false, "220-First line\r\n220 Last line\r\n");
        Check(Feed(probe, true, "USER a\r\n") == ProtocolVerdict::Ftp, "multiline FTP greeting");
        probe.Reset(); Feed(probe, false, greeting);
        Check(Feed(probe, true, "TYPE " + std::string(600,'I')) == ProtocolVerdict::Other, "oversized client header bounded");
    }
    static bool Contains(const std::string& value) {
        const std::vector<std::string> patterns{std::string("secret",6),std::string("s\0e\0c\0r\0e\0t\0",12),std::string("\0s\0e\0c\0r\0e\0t",12)};
        std::string lower = value;
        for (char& c : lower) { if (c >= 'A' && c <= 'Z') { c = static_cast<char>(c + 32); } }
        for (const auto& pattern : patterns) { if (lower.find(pattern) != std::string::npos) { return true; } }
        return false;
    }
    static void Matchers() {
        const std::vector<std::string> samples{"secret", "SeCrEt", "sssssecret", "secresecret", "public", "secre", "", std::string("a\0S\0e\0C\0r\0E\0t\0z",14), std::string("a\0S\0e\0C\0r\0E\0t",13)};
        for (const auto& sample : samples) {
            for (size_t cut = 0; cut <= sample.size(); ++cut) {
                guard::SecretMatcher matcher;
                matcher.Feed(reinterpret_cast<const unsigned char*>(sample.data()), cut);
                Check(matcher.Feed(reinterpret_cast<const unsigned char*>(sample.data() + cut), sample.size() - cut) == Contains(sample), "secret across encoding/chunk boundaries");
                matcher.Reset(); Check(!matcher.Found(), "matcher reset");
            }
        }
        std::mt19937 random(10463);
        for (int round = 0; round < 1000; ++round) {
            std::string value(200, '\0');
            constexpr char alphabet[] = "sSeEcCrRtTXYZ";
            for (char& c : value) { c = (random() % 3 == 0) ? '\0' : alphabet[random() % (sizeof(alphabet) - 1)]; }
            if (round % 2 == 0) { value.replace(random() % 180, 6, "SeCrEt"); }
            guard::SecretMatcher matcher;
            for (char c : value) { const auto byte = static_cast<unsigned char>(c); matcher.Feed(&byte, 1); }
            Check(matcher.Found() == Contains(value), "randomized matcher differential check");
        }
    }
    static void Write(HANDLE handle, const std::string& bytes) {
        DWORD written = 0;
        if (!WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) || written != bytes.size()) { throw std::runtime_error("unit WriteFile"); }
    }
    static void Files() {
        const auto root = std::filesystem::temp_directory_path() / (L"WfpFtpGuard-unit-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
        if (!std::filesystem::create_directory(root)) { throw std::runtime_error("unit temporary directory"); }
        struct TempLifetime {
            std::filesystem::path path;
            ~TempLifetime() {
                std::error_code error;
                const auto resolved = std::filesystem::weakly_canonical(path, error);
                const auto parent = std::filesystem::weakly_canonical(std::filesystem::temp_directory_path(), error);
                if (!error && resolved.parent_path() == parent && resolved.filename().wstring().rfind(L"WfpFtpGuard-unit-",0) == 0) { std::filesystem::remove_all(resolved, error); }
            }
        } temporary{root};
        Check(guard::FileScanner::SecretFilename(L"C:\\folder\\my-SeCrEt.txt"), "case-insensitive filename");
        Check(!guard::FileScanner::SecretFilename(L"C:\\secret-folder\\public.txt"), "only filename, not parent folder");
        guard::FileScanner scanner;
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) { throw std::runtime_error("unit process creation time"); }
        const auto process_created = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        guard::WinHandle device(CreateFileW(L"\\\\.\\Nsi", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
        if (!device.Valid()) { throw std::runtime_error("unit network device handle"); }
        SetLastError(ERROR_SUCCESS);
        Check(GetFileType(device.Get()) == FILE_TYPE_UNKNOWN && GetLastError() == ERROR_SUCCESS,
              "real non-disk device has a valid unknown file type");
        SetLastError(ERROR_ACCESS_DENIED);
        const auto device_result = scanner.InspectFile(device.Get());
        Check(device_result.verdict == guard::ScanVerdict::Clear && device_result.files == 0 && device_result.bytes == 0,
              "non-disk device is ignored even with a stale last-error value");
        {
            const auto path = root / L"mY-SeCrEt-name.txt";
            guard::WinHandle file(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_NEW, 0, nullptr));
            if (!file.Valid()) { throw std::runtime_error("unit secret file"); }
            Write(file.Get(), "public");
            const auto result = scanner.InspectFile(file.Get());
            Check(result.verdict == guard::ScanVerdict::SecretName && result.bytes == 0, "filename match blocks without reading content");
            Check(scanner.Scan(GetCurrentProcessId(), process_created).verdict == guard::ScanVerdict::SecretName, "native process handle snapshot finds named file");
        }
        const std::vector<std::string> contents{"public", "", "prefix SeCrEt suffix", std::string(65533,'a') + "secret", std::string("s\0e\0c\0r\0e\0t\0",12), std::string("\0s\0e\0c\0r\0e\0t",12)};
        for (size_t i = 0; i < contents.size(); ++i) {
            const auto path = root / (L"public-" + std::to_wstring(i) + L".bin");
            guard::WinHandle file(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_NEW, 0, nullptr));
            if (!file.Valid()) { throw std::runtime_error("unit content file"); }
            Write(file.Get(), contents[i]);
            LARGE_INTEGER mark{}; mark.QuadPart = 3;
            SetFilePointerEx(file.Get(), mark, nullptr, FILE_BEGIN);
            const auto result = scanner.InspectFile(file.Get());
            Check(result.verdict == (Contains(contents[i]) ? guard::ScanVerdict::SecretContent : guard::ScanVerdict::Clear), "real-file content verdict");
            if (i == 0 || i == 2) {
                Check(scanner.Scan(GetCurrentProcessId(), process_created).verdict ==
                    (i == 0 ? guard::ScanVerdict::Clear : guard::ScanVerdict::SecretContent), "native process handle snapshot content decision");
            }
            LARGE_INTEGER zero{}, after{};
            Check(SetFilePointerEx(file.Get(), zero, &after, FILE_CURRENT) && after.QuadPart == 3, "inspection preserves original file position");
            if (!contents[i].empty()) { Check(scanner.InspectFile(file.Get(), 0).verdict == guard::ScanVerdict::Incomplete, "scan deadline fails closed"); }
        }
        {
            const auto path = root / L"exclusive.txt";
            guard::WinHandle file(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr));
            if (!file.Valid()) { throw std::runtime_error("unit exclusive file"); }
            Write(file.Get(), "public");
            Check(scanner.InspectFile(file.Get()).verdict == guard::ScanVerdict::Incomplete, "unreadable exclusive file fails closed");
        }
        Check(scanner.InspectFile(INVALID_HANDLE_VALUE).verdict == guard::ScanVerdict::Incomplete, "invalid handle fails closed");
        Check(scanner.Scan(GetCurrentProcessId(), 1).verdict == guard::ScanVerdict::Incomplete, "PID reuse guard");
        Check(scanner.Scan(MAXDWORD, 1).verdict == guard::ScanVerdict::Incomplete, "missing process fails closed");
        guard::WinHandle directory(CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                               nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        Check(directory.Valid() && scanner.InspectFile(directory.Get()).files == 0, "directory handles are not files");
    }
};

int main() { try { return Tests::Run(); } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; } }
