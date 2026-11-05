#include <Windows.h>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "file_scanner.hpp"
#include "ftp_probe.hpp"
#include "ftp_transfer.hpp"
#include "file_activity.hpp"
#include "trace_progress.hpp"
#include <future>
#include "secret_matcher.hpp"

class Tests {
 public:
    static int Run() {
        Parser();
        UploadCommands();
        TransferCommands();
        FileActivity();
        FileReads();
        TraceProgress();
        Matchers();
        MatcherWindows();
        GuardedMatcherPages();
        Files();
        SourceCache();
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
            "PASV\r\n", "EPSV\r\n", "TYPE I\r\n", "OPTS UTF8 ON\r\n", "RETR a.txt\r\n", "STOR a.txt\r\n", "APPE a.txt\r\n", "STOU\r\n",
            "CWD /\r\n", "CDUP\r\n", "PWD\r\n", "DELE a.txt\r\n", "MKD dir\r\n", "RMD dir\r\n", "RNFR old\r\n", "RNTO new\r\n",
            "PORT 127,0,0,1,1,2\r\n", "EPRT |1|127.0.0.1|4242|\r\n", "AUTH TLS\r\n", "AUTH SSL\r\n", "USER Jos\xC3\xA9\r\n"};
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
    static bool FeedUpload(guard::FtpUploadProbe& probe, const std::string& value) {
        return probe.Feed(reinterpret_cast<const unsigned char*>(value.data()), value.size());
    }
    static void UploadCommands() {
        const std::vector<std::pair<std::string, std::string>> uploads{
            {"STOR a.txt\r\n", "STOR"}, {"appe a.txt\r\n", "APPE"}, {"STOU\r\n", "STOU"}, {"stou unique.txt\r\n", "STOU"}};
        for (const auto& [command, verb] : uploads) {
            for (size_t cut = 0; cut < command.size(); ++cut) {
                guard::FtpUploadProbe probe; probe.Reset();
                Check(!FeedUpload(probe, "OPTS UTF8 ON\r\nUSER test\r\nTYPE I\r\n"), "login and mode commands do not request an upload scan");
                Check(!FeedUpload(probe, command.substr(0, cut)), "incomplete upload command is held until the line is complete");
                Check(FeedUpload(probe, command.substr(cut)), "upload command detected across every split after login");
                Check(std::string(probe.Verb()) == verb, "upload evidence contains only the normalized verb");
                Check(!FeedUpload(probe, "NOOP\r\n"), "non-upload command does not reuse a previous decision request");
                Check(FeedUpload(probe, "STOR next.txt\r\n"), "later upload in the same session requests another scan");
            }
        }
        guard::FtpUploadProbe probe; probe.Reset();
        Check(!probe.Feed(nullptr, 0), "empty upload input is safe");
        Check(!FeedUpload(probe, "XYZ STOR hidden.txt\r\nSTORAGE x\r\nSTOR x\n"), "embedded verbs and malformed lines are not upload commands");
        Check(FeedUpload(probe, std::string(600,'X') + "\r\nSTOR next.txt\r\n"), "upload detection recovers after an oversized line");
        Check(FeedUpload(probe, "STOR a\r\nAPPE b\r\n") && std::string(probe.Verb()) == "APPE", "multiple complete commands in one indication preserve upload evidence");
        Check(!FeedUpload(probe, "ST"), "partial command has no decision");
        probe.Reset();
        Check(std::string(probe.Verb()).empty() && !FeedUpload(probe, "OR x\r\n"), "reset discards partial command and old evidence");
        Check(!FeedUpload(probe, "AUTH TLS\r\nSTOR hidden.txt\r\n"), "TLS upgrade stops plaintext upload parsing within the same indication");
        Check(!FeedUpload(probe, "STOR encrypted.txt\r\n"), "TLS upgrade remains outside plaintext inspection");
        probe.Reset();
        Check(FeedUpload(probe, "STOR clear.txt\r\n"), "new connection re-enables upload inspection");
    }
    static void TransferCommands() {
        using guard::NetTransferVerb;
        const std::vector<std::pair<std::string, NetTransferVerb>> commands{
            {"STOR source.dat\r\n", NetTransferVerb::Upload}, {"aPpE source.dat\r\n", NetTransferVerb::Upload},
            {"STOU\r\n", NetTransferVerb::Upload}, {"rEtR source.dat\r\n", NetTransferVerb::Download}};
        for (const auto& [line, expected] : commands) {
            for (size_t cut = 0; cut < line.size(); ++cut) {
                guard::NetFtpTransferProbe probe; probe.Reset();
                Check(!probe.Feed(nullptr, 0), "empty transfer input is safe");
                const std::string prefix = "USER lab\r\nTYPE I\r\n";
                Check(!probe.Feed(reinterpret_cast<const unsigned char*>(prefix.data()), prefix.size()),
                      "login does not request a transfer scan");
                Check(!probe.Feed(reinterpret_cast<const unsigned char*>(line.data()), cut), "partial transfer waits for CRLF");
                Check(probe.Feed(reinterpret_cast<const unsigned char*>(line.data() + cut), line.size() - cut) &&
                      probe.Transfer() == expected && !probe.TlsRequested(), "upload and RETR across every split");
                Check(std::string(probe.Verb()).find("source") == std::string::npos, "transfer evidence excludes file arguments");
            }
        }
        for (const std::string auth : {std::string("AUTH TLS\r\n"), std::string("AUTH SSL\r\n")}) {
        for (size_t cut = 0; cut <= auth.size(); ++cut) {
            guard::NetFtpTransferProbe probe; probe.Reset();
            probe.Feed(reinterpret_cast<const unsigned char*>(auth.data()), cut);
            probe.Feed(reinterpret_cast<const unsigned char*>(auth.data() + cut), auth.size() - cut);
            Check(probe.TlsRequested() && std::string(probe.Verb()) == "AUTH", "explicit TLS transition across every split");
            const std::string opaque = "\x17\x03\x03\x00\x13STOR hidden.dat\r\n";
            Check(!probe.Feed(reinterpret_cast<const unsigned char*>(opaque.data()), opaque.size()) &&
                  probe.Transfer() == NetTransferVerb::None, "encrypted traffic is not parsed as FTP commands");
            probe.Reset();
            Check(!probe.TlsRequested() && probe.Transfer() == NetTransferVerb::None && std::string(probe.Verb()).empty(),
                  "reset removes prior TLS and transfer state");
        }
        }
        guard::NetFtpTransferProbe probe; probe.Reset();
        const std::string malformed = "XYZ RETR hidden\r\nRETR bad\n" + std::string(600, 'X') + "\r\nRETR good\r\n";
        Check(probe.Feed(reinterpret_cast<const unsigned char*>(malformed.data()), malformed.size()) &&
              probe.Transfer() == NetTransferVerb::Download, "transfer parser recovers after invalid and oversized lines");
        for (const bool server : {false, true}) {
            for (const bool tls : {false, true}) {
                for (const auto transfer : {NetTransferVerb::None, NetTransferVerb::Upload, NetTransferVerb::Download}) {
                    const bool sender = (server && transfer == NetTransferVerb::Download) || (!server && transfer == NetTransferVerb::Upload);
                    Check(guard::NetTransferGate::SendsFile(server, transfer) == sender, "local file sender follows logical FTP role");
                    Check(!guard::NetTransferGate::InspectData(server, tls, transfer, 0), "zero-length FIN never requests a file scan");
                    Check(guard::NetTransferGate::InspectData(server, tls, transfer, 1) == (tls || sender),
                          "outgoing data is gated for source transfers and conservative explicit FTPS correlation");
                    const std::string evidence = guard::NetTransferGate::Evidence(server, tls);
                    Check(evidence == (tls ? (server ? "FTPS-SERVER-DATA" : "FTPS-CLIENT-DATA") :
                                            (server ? "RETR-DATA" : "UPLOAD-DATA")), "diagnostics identify sender role and encryption");
                }
            }
        }
        Check(!guard::NetTransferGate::GrantDataFlow(false, false, false, 1), "a control command cannot authorize a data connection");
        Check(!guard::NetTransferGate::GrantDataFlow(true, true, false, 1), "a TLS certificate read cannot authorize later encrypted file data");
        Check(!guard::NetTransferGate::GrantDataFlow(true, false, true, 1), "a denied source never receives a retained grant");
        Check(!guard::NetTransferGate::GrantDataFlow(true, false, false, 0), "missing source evidence cannot authorize a data connection");
        Check(guard::NetTransferGate::GrantDataFlow(true, false, false, 1), "a verified plaintext source can finish its single-file data connection");
        Check(guard::NetTransferGate::DataCandidate(false, false, false, NetTransferVerb::None), "ordinary correlated data remains a candidate");
        Check(!guard::NetTransferGate::DataCandidate(true, false, false, NetTransferVerb::None), "an unrelated greeting without a transfer retains control parsing");
        Check(guard::NetTransferGate::DataCandidate(true, true, false, NetTransferVerb::Download), "server file bytes beginning with 220 cannot bypass RETR inspection");
        Check(guard::NetTransferGate::DataCandidate(true, false, false, NetTransferVerb::Upload), "client file bytes beginning with 220 cannot bypass upload inspection");
        Check(guard::NetTransferGate::DataCandidate(true, true, true, NetTransferVerb::None), "explicit FTPS clear data beginning with 220 remains gated");
    }
    static void FileActivity() {
        constexpr std::uint64_t now = 134000000000000000ULL;
        guard::NetFileActivityCache cache;
        cache.Record(0, now, L"ignored.txt");
        cache.Record(7, 0, L"ignored.txt");
        cache.Record(7, now, L"");
        Check(cache.Paths(7, now - 10, now).empty(), "invalid file-open records are ignored");
        cache.Record(7, now - 20, L"closed-before-connect.txt");
        cache.Record(7, now - 5, L"current.txt");
        cache.Record(7, now - 4, L"current.txt");
        cache.Record(7, now - 5, L"current.txt"); // Late delivery must not move the latest observation backwards.
        cache.Record(8, now - 3, L"other-process.txt");
        cache.Record(7, now + 1, L"future.txt");
        const auto paths = cache.Paths(7, now - 10, now);
        Check(paths.size() == 1 && paths[0] == L"current.txt", "file evidence is PID-scoped, after connection time, deduplicated and not from the future");
        Check(cache.Paths(7, now - 20, now).size() == 2, "connection-time boundary is inclusive");
        Check(cache.Paths(7, 1, now + 31ULL * 10000000).empty(), "old file evidence expires");
        for (std::uint64_t i = 0; i < 1100; ++i) { cache.Record(7, now + i, std::to_wstring(i)); }
        const auto bounded = cache.Paths(7, now, now + 1100);
        Check(bounded.size() == 1024 && bounded.front() == L"76" && bounded.back() == L"1099", "file evidence cache evicts oldest records at its capacity");
    }
    static void FileReads() {
        constexpr std::uint64_t now = 134000000000000000ULL;
        guard::NetFileReadCache cache;
        cache.Open(0, 1, now, L"invalid"); cache.Open(7, 0, now, L"invalid");
        cache.Open(7, 1, 0, L"invalid"); cache.Open(7, 1, now, L"");
        cache.Read(7, 1, now);
        Check(cache.Paths(7, now, now).empty() && cache.Evictions() == 0, "invalid file objects do not create read evidence");
        cache.Open(7, 1, now, L"source.bin");
        cache.Read(8, 1, now); cache.Read(7, 1, now - 1); cache.Read(7, 2, now);
        Check(cache.Paths(7, now - 1, now).empty(), "read evidence requires matching object, owner and lifetime");
        cache.Read(7, 1, now + 1); cache.Read(0, 1, now + 2); cache.Read(0xffffffffULL, 1, now + 3);
        Check(cache.Paths(7, now, now + 3) == std::vector<std::wstring>{L"source.bin"},
              "read events deduplicate and can use the create-event owner when the header PID is unavailable");
        cache.Close(999); cache.Close(1);
        cache.Read(7, 1, now + 4);
        Check(cache.Paths(7, now + 4, now + 4).empty(), "close removes the object association");
        cache.Open(7, 2, now, L"old.bin"); cache.Open(8, 2, now + 1, L"new.bin");
        cache.Read(7, 2, now + 2); cache.Read(8, 2, now + 2);
        Check(cache.Paths(8, now, now + 2) == std::vector<std::wstring>{L"new.bin"}, "object reuse replaces the old owner");
        for (std::uint64_t i = 1; i <= 4097; ++i) { cache.Open(9, i + 10, now, std::to_wstring(i)); }
        cache.Read(9, 11, now + 1);
        Check(cache.Evictions() != 0 && cache.Paths(9, now, now + 1).empty(), "object map eviction is bounded and observable");
        for (std::uint64_t i = 0; i < 1100; ++i) { cache.Read(9, 11 + i, now + 10 + i); }
        Check(cache.Evictions() > 1, "read history eviction is observable independently of object-map capacity");
        Check(cache.Paths(9, now, now + 40ULL * 10000000).empty(), "read evidence expires after thirty seconds");
        guard::NetFileReadCache bulk;
        bulk.Open(7, 1, now, L"large-source.bin");
        for (std::uint64_t i = 0; i < 20000; ++i) { bulk.Read(7, 1, now + i); }
        Check(bulk.Evictions() == 0 && bulk.Paths(7, now, now + 20000).size() == 1,
              "bulk reads coalesce evidence instead of poisoning the bounded history");
    }
    static void TraceProgress() {
        using namespace std::chrono_literals;
        guard::NetTraceProgress progress;
        Check(progress.Wait(0, 0ms), "an already delivered trace needs no wait");
        Check(!progress.Wait(1, 0ms), "missing trace delivery times out");
        progress.Advance(3);
        progress.Advance(2);
        Check(progress.Buffers() == 3 && progress.Wait(3, 0ms), "trace progress is monotonic and notification before wait is retained");
        auto delivered = std::async(std::launch::async, [&] { return progress.Wait(5, 5s); });
        progress.Advance(4);
        Check(!progress.Wait(5, 0ms), "a partial flush cannot release an upload");
        progress.Advance(5);
        Check(delivered.wait_for(1s) == std::future_status::ready && delivered.get(), "complete flush wakes the waiting consumer without a fixed delay");
        auto stopped = std::async(std::launch::async, [&] { return progress.Wait(6, 5s); });
        progress.Finish();
        Check(stopped.wait_for(1s) == std::future_status::ready && !stopped.get(), "consumer shutdown interrupts a trace wait");
        Check(!progress.Wait(0, 0ms), "a stopped consumer cannot certify file evidence");
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
            guard::SecretMatcher chunked;
            size_t at = 0;
            while (at < value.size()) {
                const size_t count = (std::min)(value.size() - at, static_cast<size_t>(1 + random() % 63));
                chunked.Feed(reinterpret_cast<const unsigned char*>(value.data() + at), count); at += count;
            }
            Check(chunked.Found() == Contains(value), "vector-search matcher agrees across random chunk boundaries");
        }
        for (const std::string repeated : {std::string("xxSx"), std::string("SecreX"), std::string("S\0S\0", 4)}) {
            std::string dense;
            while (dense.size() < 256 * 1024) { dense += repeated; }
            guard::SecretMatcher clear;
            Check(!clear.Feed(reinterpret_cast<const unsigned char*>(dense.data()), dense.size()),
                  "dense starts and near-matches remain public without repeated suffix searches");
            for (const std::string marker : {std::string("SeCrEt"), std::string("S\0e\0C\0r\0E\0t\0", 12), std::string("\0S\0e\0C\0r\0E\0t", 12)}) {
                const auto value = dense + marker + std::string(64, 'P');
                guard::SecretMatcher found;
                Check(found.Feed(reinterpret_cast<const unsigned char*>(value.data()), value.size()),
                      "vector windows qualify complete ASCII and both UTF16 encodings after dense public prefixes");
            }
        }
        for (const auto& pattern : {std::string("SeCrEt"), std::string("s\0e\0c\0r\0e\0t\0",12), std::string("\0s\0e\0c\0r\0e\0t",12)}) {
            const std::string value = std::string(1024 * 1024, 'P') + pattern;
            for (size_t cut = value.size() - pattern.size(); cut <= value.size(); ++cut) {
                guard::SecretMatcher matcher;
                matcher.Feed(reinterpret_cast<const unsigned char*>(value.data()), cut);
                Check(matcher.Feed(reinterpret_cast<const unsigned char*>(value.data() + cut), value.size() - cut),
                      "fast skipping preserves late ASCII/UTF16 markers at every split");
            }
        }
    }
    static void MatcherWindows() {
        const std::vector<std::string> markers{"SeCrEt", std::string("S\0e\0C\0r\0E\0t\0", 12), std::string("\0S\0e\0C\0r\0E\0t", 12)};
        for (const auto& marker : markers) {
            for (size_t alignment = 0; alignment < 32; ++alignment) {
                const std::string value = std::string(40 + alignment, 'P') + marker + std::string(40, 'P');
                for (size_t cut = 0; cut <= value.size(); ++cut) {
                    guard::SecretMatcher matcher;
                    matcher.Feed(reinterpret_cast<const unsigned char*>(value.data()), cut);
                    Check(matcher.Feed(reinterpret_cast<const unsigned char*>(value.data() + cut), value.size() - cut) == Contains(value),
                          "vector windows retain every encoding, alignment and input split");
                }
            }
        }
    }
    static void GuardedMatcherPages() {
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        struct NetGuardedRegion {
            void* data = nullptr;
            ~NetGuardedRegion() { if (data != nullptr) { VirtualFree(data, 0, MEM_RELEASE); } }
        } region;
        region.data = VirtualAlloc(nullptr, static_cast<size_t>(system.dwPageSize) * 2, MEM_RESERVE, PAGE_NOACCESS);
        if (region.data == nullptr || VirtualAlloc(region.data, system.dwPageSize, MEM_COMMIT, PAGE_READWRITE) == nullptr) {
            throw std::runtime_error("guarded matcher allocation");
        }
        const std::string marker("\0S\0e\0C\0r\0E\0t", 12);
        for (size_t length = 0; length <= 96; ++length) {
            const auto value = length < marker.size() ? std::string(length, 'P') : std::string(length - marker.size(), 'P') + marker;
            auto* bytes = static_cast<unsigned char*>(region.data) + system.dwPageSize - length;
            std::copy(value.begin(), value.end(), bytes);
            guard::SecretMatcher matcher;
            Check(matcher.Feed(bytes, length) == Contains(value), "vector lookahead stays within the supplied buffer before a protected page");
        }
    }
    static void Write(HANDLE handle, const std::string& bytes) {
        DWORD written = 0;
        if (!WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) || written != bytes.size()) { throw std::runtime_error("unit WriteFile"); }
    }
    static void SourceCache() {
        const auto path = std::filesystem::temp_directory_path() / (L"WfpFtpGuard-cache-" + std::to_wstring(GetCurrentProcessId()) + L".bin");
        const auto extra = std::filesystem::path(path.wstring() + L".other");
        struct Cleanup {
            std::filesystem::path path, extra;
            ~Cleanup() { std::error_code error; std::filesystem::remove(path, error); std::filesystem::remove(extra, error); }
        } cleanup{path, extra};
        const auto replace = [&](const std::filesystem::path& target, const std::string& content) {
            guard::WinHandle file(CreateFileW(target.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, CREATE_ALWAYS, 0, nullptr));
            if (!file.Valid()) { throw std::runtime_error("cache fixture"); }
            Write(file.Get(), content);
        };
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) { throw std::runtime_error("cache identity"); }
        const auto birth = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        ULONGLONG cache_now = 100000;
        guard::FileScanner scanner([&] { return cache_now; });
        const auto scan = [&](std::uint64_t flow, const std::vector<std::wstring>& paths) {
            return scanner.Scan(GetCurrentProcessId(), birth, 8000, paths, true, flow);
        };
        replace(path, "public");
        const auto first = scan(70, {path.wstring()});
        Check(first.verdict == guard::ScanVerdict::Clear && first.bytes == 6 && first.cached_files == 0, "new source receives a complete content scan");
        const auto hit = scan(70, {path.wstring()});
        Check(hit.verdict == guard::ScanVerdict::Clear && hit.bytes == 0 && hit.cached_files == 1, "unchanged same-flow source reuses a checked verdict");
        cache_now += 30001;
        Check(scan(70, {path.wstring()}).cached_files == 0, "expired file verdicts are rescanned without a fixed-delay test");
        Check(scan(71, {path.wstring()}).cached_files == 0, "content cache is scoped to a data flow");
        Check(scanner.Scan(GetCurrentProcessId(), birth, 0, {path.wstring()}, true, 70).verdict == guard::ScanVerdict::Incomplete,
              "a cached verdict cannot bypass the inspection deadline");
        replace(extra, "public");
        const auto latest = scan(70, {path.wstring(), extra.wstring()});
        Check(latest.verdict == guard::ScanVerdict::Clear && latest.path.find(extra.filename().wstring()) != std::wstring::npos,
              "allow diagnostics identify the most recent inspected source rather than an earlier certificate");
        const auto cached_latest = scan(70, {path.wstring(), extra.wstring()});
        Check(cached_latest.cached_files == 2 && cached_latest.path.find(extra.filename().wstring()) != std::wstring::npos,
              "cached source diagnostics retain the latest candidate path");
        replace(extra, "secret");
        const auto new_source = scan(70, {path.wstring(), extra.wstring()});
        Check(new_source.verdict == guard::ScanVerdict::SecretContent && new_source.cached_files == 1,
              "a cached public certificate/source cannot authorize a newly observed secret source");
        replace(path, "secret");
        Check(scan(70, {path.wstring()}).verdict == guard::ScanVerdict::SecretContent, "same-size source modification invalidates the cached verdict");
        replace(path, "public");
        scan(72, {path.wstring()});
        {
            guard::WinHandle writer(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, 0, nullptr));
            if (!writer.Valid()) { throw std::runtime_error("cache writer"); }
            Write(writer.Get(), "secret");
            const auto result = scan(72, {path.wstring()});
            Check(result.verdict == guard::ScanVerdict::SecretContent && result.cached_files == 0, "an outstanding writer prevents cached approval");
        }
        std::filesystem::remove(path);
        replace(path, "secret");
        Check(scan(70, {path.wstring()}).verdict == guard::ScanVerdict::SecretContent, "replacement at the same path is not a cached file identity");
        Check(scanner.Scan(GetCurrentProcessId(), 1, 8000, {path.wstring()}, true, 70).verdict == guard::ScanVerdict::Incomplete,
              "cache reuse never bypasses process-instance verification");
        replace(path, "public");
        for (std::uint64_t flow = 1000; flow <= 1064; ++flow) { scan(flow, {path.wstring()}); }
        Check(scan(1000, {path.wstring()}).cached_files == 0, "the bounded content cache evicts old grants conservatively");
        guard::FileScanner real_clock;
        real_clock.Scan(GetCurrentProcessId(), birth, 8000, {path.wstring()}, true, 9000);
        Check(real_clock.Scan(GetCurrentProcessId(), birth, 8000, {path.wstring()}, true, 9000).cached_files == 1,
              "normal cache timing uses the monotonic system clock");
        FILE_BASIC_INFO original{};
        {
            guard::WinHandle file(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, 0, nullptr));
            if (!GetFileInformationByHandleEx(file.Get(), FileBasicInfo, &original, sizeof(original))) { throw std::runtime_error("cache original times"); }
        }
        scan(1100, {path.wstring()});
        replace(path, "secret");
        {
            guard::WinHandle file(CreateFileW(path.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, 0, nullptr));
            if (!SetFileInformationByHandle(file.Get(), FileBasicInfo, &original, sizeof(original))) { throw std::runtime_error("cache restored times"); }
        }
        const auto restored = scan(1100, {path.wstring()});
        Check(restored.verdict == guard::ScanVerdict::SecretContent && restored.cached_files == 0,
              "NTFS change-journal identity invalidates modified content even when timestamps are restored");
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
            Check(scanner.Scan(GetCurrentProcessId(), process_created, 8000, {path.wstring()}, true).verdict == guard::ScanVerdict::SecretName,
                  "on-demand scan checks the observed transfer source");
            Check(scanner.Scan(GetCurrentProcessId(), process_created, 8000, {}, true).verdict == guard::ScanVerdict::Clear,
                  "an unrelated long-lived open file does not become an on-demand transfer source");
        }
        {
            const auto path = root / L"secret-write-only-log.txt";
            guard::WinHandle log(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                             nullptr, CREATE_NEW, 0, nullptr));
            if (!log.Valid()) { throw std::runtime_error("unit write-only log"); }
            Write(log.Get(), "secret diagnostic log");
            Check(scanner.Scan(GetCurrentProcessId(), process_created, 8000, {}, true).verdict == guard::ScanVerdict::Clear,
                  "write-only logs are not outgoing source handles");
            Check(scanner.Scan(GetCurrentProcessId(), process_created).verdict == guard::ScanVerdict::SecretName,
                  "legacy all-handle scan remains available for diagnostics");
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
        const auto closed_name = scanner.Scan(GetCurrentProcessId(), process_created, 8000, {(root / L"mY-SeCrEt-name.txt").wstring()});
        Check(closed_name.verdict == guard::ScanVerdict::SecretName && closed_name.recent_match && closed_name.recent_files == 1,
              "recently opened source is checked after its file handle closes");
        const auto closed_content = scanner.Scan(GetCurrentProcessId(), process_created, 8000, {(root / L"public-2.bin").wstring()});
        Check(closed_content.verdict == guard::ScanVerdict::SecretContent && closed_content.recent_match,
              "recent source content is checked independently of live handles");
        Check(scanner.Scan(GetCurrentProcessId(), process_created, 8000, {(root / L"public-0.bin").wstring()}).verdict == guard::ScanVerdict::Clear,
              "recent public source remains allowed");
        Check(scanner.Scan(GetCurrentProcessId(), process_created, 8000, {(root / L"missing.bin").wstring()}).verdict == guard::ScanVerdict::Incomplete,
              "unavailable recent source fails closed");
        Check(scanner.Scan(GetCurrentProcessId(), process_created, 8000, {L"\\Device\\NamedPipe\\ignored"}).verdict == guard::ScanVerdict::Clear,
              "non-disk file telemetry is ignored");
        Check(scanner.Scan(GetCurrentProcessId(), process_created, 0, {(root / L"public-0.bin").wstring()}).verdict == guard::ScanVerdict::Incomplete,
              "recent-file processing respects its scan deadline");
        {
            const auto path = root / L"public-2.bin";
            guard::WinHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
            std::vector<wchar_t> native(32768);
            const DWORD length = GetFinalPathNameByHandleW(file.Get(), native.data(), static_cast<DWORD>(native.size()), VOLUME_NAME_NT);
            if (length == 0 || length >= native.size()) { throw std::runtime_error("unit native file path"); }
            const std::wstring native_path(native.data(), length);
            file.Reset();
            const auto result = scanner.Scan(GetCurrentProcessId(), process_created, 8000, {native_path});
            Check(result.verdict == guard::ScanVerdict::SecretContent && result.recent_match, "native ETW disk path is opened through GLOBALROOT");
        }
        guard::WinHandle directory(CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                               nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        Check(directory.Valid() && scanner.InspectFile(directory.Get()).files == 0, "directory handles are not files");
    }
};

int main() { try { return Tests::Run(); } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; } }
