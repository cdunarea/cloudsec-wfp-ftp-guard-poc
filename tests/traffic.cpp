#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <wininet.h>
#include <array>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

class Traffic {
 public:
    static int Run(int argc, wchar_t** argv) {
        const Options options = Parse(argc, argv);
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2,2), &data) != 0) { throw std::runtime_error("WSAStartup"); }
        struct Lifetime { ~Lifetime() { WSACleanup(); } } lifetime;
        return options.server ? Server(options) : Client(options);
    }
 private:
    struct Options {
        bool server = false;
        bool ipv6 = false;
        bool fragmented = false;
        bool close_file = false;
        bool expected_block = false;
        bool http = false;
        bool wininet = false;
        USHORT port = 2121;
        DWORD seconds = 120;
        std::wstring file;
    };
    class Socket {
     public:
        explicit Socket(SOCKET value) : value_(value) {}
        ~Socket() { if (value_ != INVALID_SOCKET) { closesocket(value_); } }
        Socket(const Socket&) = delete;
        Socket& operator=(const Socket&) = delete;
        SOCKET Get() const { return value_; }
     private:
        SOCKET value_;
    };
    static Options Parse(int argc, wchar_t** argv) {
        Options options;
        for (int i = 1; i < argc; ++i) {
            const std::wstring argument = argv[i];
            if (argument == L"--server") { options.server = true; }
            else if (argument == L"--ipv6") { options.ipv6 = true; }
            else if (argument == L"--fragment") { options.fragmented = true; }
            else if (argument == L"--close-file") { options.close_file = true; }
            else if (argument == L"--http") { options.http = true; }
            else if (argument == L"--wininet") { options.wininet = true; }
            else if ((argument == L"--port" || argument == L"--seconds" || argument == L"--file" || argument == L"--expect") && i + 1 < argc) {
                const std::wstring value = argv[++i];
                if (argument == L"--file") { options.file = value; }
                else if (argument == L"--expect") {
                    if (value != L"blocked" && value != L"allowed") { throw std::runtime_error("--expect blocked|allowed"); }
                    options.expected_block = value == L"blocked";
                } else {
                    size_t consumed = 0;
                    const auto number = std::stoul(value, &consumed);
                    if (consumed != value.size() || number == 0 || number > 65535) { throw std::runtime_error("Invalid numeric argument"); }
                    if (argument == L"--port") { options.port = static_cast<USHORT>(number); }
                    else { options.seconds = number; }
                }
            } else { throw std::runtime_error("Unknown/incomplete traffic option"); }
        }
        return options;
    }
    static void Timeout(SOCKET socket) {
        const DWORD timeout = 5000;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        const BOOL nodelay = TRUE;
        setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    }
    static bool Send(SOCKET socket, const std::string& value) {
        size_t offset = 0;
        while (offset < value.size()) {
            const int count = send(socket, value.data() + offset, static_cast<int>(value.size() - offset), 0);
            if (count <= 0) { return false; }
            offset += static_cast<size_t>(count);
        }
        return true;
    }
    static std::string Line(SOCKET socket) {
        std::string line;
        while (line.size() < 4096) {
            char c = 0;
            if (recv(socket, &c, 1, 0) != 1) { return {}; }
            line.push_back(c);
            if (c == '\n') { return line; }
        }
        return {};
    }
    static void Serve(SOCKET accepted, bool http) {
        Socket client(accepted);
        Timeout(client.Get());
        if (!http && !Send(client.Get(), "220 WfpFtpGuard FTP test server ready\r\n")) { return; }
        for (int commands = 0; commands < 20; ++commands) {
            const auto line = Line(client.Get());
            if (line.empty()) { std::cout << "SERVER_CLOSED_WITHOUT_COMMAND\n" << std::flush; return; }
            const auto space = line.find_first_of(" \r\n");
            const std::string verb = line.substr(0, space);
            std::cout << "SERVER_RECEIVED " << verb << '\n' << std::flush;
            if (http) {
                // Consume all request headers before closing; unread request data can cause TCP RST.
                for (;;) { const auto header = Line(client.Get()); if (header == "\r\n") { break; } if (header.empty()) { return; } }
                if (Send(client.Get(), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")) {
                    shutdown(client.Get(), SD_SEND);
                    char byte = 0;
                    while (recv(client.Get(), &byte, 1, 0) > 0) {}
                }
                return;
            }
            std::string reply = "200 OK\r\n";
            if (verb == "USER") { reply = "331 Password required\r\n"; }
            if (verb == "PASS") { reply = "230 Logged in\r\n"; }
            if (verb == "SYST") { reply = "215 UNIX Type: L8\r\n"; }
            if (verb == "PWD") { reply = "257 \"/\" is current directory\r\n"; }
            if (verb == "FEAT") { reply = "211 No features\r\n"; }
            if (verb == "QUIT") { Send(client.Get(), "221 Goodbye\r\n"); return; }
            if (!Send(client.Get(), reply)) { return; }
        }
    }
    static int Server(const Options& options) {
        Socket server(socket(options.ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (server.Get() == INVALID_SOCKET) { throw std::runtime_error("socket server"); }
        if (options.ipv6) {
            sockaddr_in6 address{};
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(options.port);
            address.sin6_addr = in6addr_loopback;
            if (bind(server.Get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) { throw std::runtime_error("bind IPv6: " + std::to_string(WSAGetLastError())); }
        } else {
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_port = htons(options.port);
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (bind(server.Get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) { throw std::runtime_error("bind IPv4: " + std::to_string(WSAGetLastError())); }
        }
        if (listen(server.Get(), SOMAXCONN) != 0) { throw std::runtime_error("listen"); }
        std::cout << "SERVER_READY port=" << options.port << " ipv6=" << options.ipv6 << " http=" << options.http << '\n' << std::flush;
        const auto deadline = GetTickCount64() + static_cast<ULONGLONG>(options.seconds) * 1000;
        std::vector<std::jthread> clients;
        while (GetTickCount64() < deadline) {
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(server.Get(), &readable);
            timeval wait{0,100000};
            if (select(0, &readable, nullptr, nullptr, &wait) <= 0) { continue; }
            const SOCKET accepted = accept(server.Get(), nullptr, nullptr);
            if (accepted != INVALID_SOCKET) { clients.emplace_back([accepted, http = options.http] { Serve(accepted, http); }); }
        }
        return 0;
    }
    static bool NativeClient(const Options& options) {
        Socket client(socket(options.ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (client.Get() == INVALID_SOCKET) { throw std::runtime_error("socket client"); }
        Timeout(client.Get());
        int connected = SOCKET_ERROR;
        if (options.ipv6) {
            sockaddr_in6 address{};
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(options.port);
            address.sin6_addr = in6addr_loopback;
            connected = connect(client.Get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address));
        } else {
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_port = htons(options.port);
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            connected = connect(client.Get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address));
        }
        if (connected != 0) { throw std::runtime_error("TCP connect failed before FTP inspection: " + std::to_string(WSAGetLastError())); }
        if (!options.http && Line(client.Get()).rfind("220 ", 0) != 0) { throw std::runtime_error("FTP greeting was not received"); }
        bool sent = true;
        if (options.http) { sent = Send(client.Get(), "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); }
        else if (options.fragmented) { sent = Send(client.Get(), "US"); Sleep(75); sent = Send(client.Get(), "ER poc\r\n") && sent; }
        else { sent = Send(client.Get(), "USER poc\r\n"); }
        const auto response = sent ? Line(client.Get()) : std::string{};
        if (response.empty()) {
            const int error = WSAGetLastError();
            if (error == WSAETIMEDOUT) { throw std::runtime_error("Timed out; this is not proof of an enforced block"); }
            return true;
        }
        if (response.rfind(options.http ? "HTTP/1.1 200" : "331 ", 0) != 0) { throw std::runtime_error("Unexpected application response"); }
        if (options.http) {
            for (;;) { const auto header = Line(client.Get()); if (header == "\r\n") { break; } if (header.empty()) { throw std::runtime_error("Incomplete HTTP response headers"); } }
            std::string body;
            while (body.size() < 2) { char byte = 0; if (recv(client.Get(), &byte, 1, 0) != 1) { throw std::runtime_error("Incomplete HTTP response body"); } body.push_back(byte); }
            if (body != "OK") { throw std::runtime_error("Unexpected HTTP response body"); }
        }
        return false;
    }
    static bool WinInetClient(const Options& options) {
        const HINTERNET root = InternetOpenW(L"WfpFtpGuard test", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
        if (root == nullptr) { throw std::runtime_error("InternetOpen"); }
        const DWORD timeout = 5000;
        InternetSetOptionW(root, INTERNET_OPTION_CONNECT_TIMEOUT, const_cast<DWORD*>(&timeout), sizeof(timeout));
        InternetSetOptionW(root, INTERNET_OPTION_RECEIVE_TIMEOUT, const_cast<DWORD*>(&timeout), sizeof(timeout));
        const HINTERNET ftp = InternetConnectW(root, options.ipv6 ? L"::1" : L"127.0.0.1", options.port,
            L"anonymous", nullptr, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
        const bool blocked = ftp == nullptr;
        if (ftp != nullptr) { InternetCloseHandle(ftp); }
        InternetCloseHandle(root);
        return blocked;
    }
    static int Client(const Options& options) {
        HANDLE file = INVALID_HANDLE_VALUE;
        if (!options.file.empty()) {
            file = CreateFileW(options.file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
            if (file == INVALID_HANDLE_VALUE) { throw std::runtime_error("Open held file: " + std::to_string(GetLastError())); }
            LARGE_INTEGER position{};
            position.QuadPart = 3;
            SetFilePointerEx(file, position, nullptr, FILE_BEGIN);
            if (options.close_file) { CloseHandle(file); file = INVALID_HANDLE_VALUE; }
        }
        struct FileLifetime { HANDLE file; ~FileLifetime() { if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); } } } lifetime{file};
        const bool blocked = options.wininet ? WinInetClient(options) : NativeClient(options);
        if (file != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER zero{}, position{};
            if (!SetFilePointerEx(file, zero, &position, FILE_CURRENT) || position.QuadPart != 3) { throw std::runtime_error("Inspector changed the application's file position"); }
        }
        std::cout << "CLIENT_RESULT " << (blocked ? "blocked" : "allowed") << " pid=" << GetCurrentProcessId()
                  << " port=" << options.port << " file_position=unchanged\n" << std::flush;
        Sleep(1500); // Keep process details queryable while real-time ETW buffers flush.
        return blocked == options.expected_block ? 0 : 2;
    }
};

int wmain(int argc, wchar_t** argv) {
    try { return Traffic::Run(argc, argv); }
    catch (const std::exception& error) { std::cerr << "TRAFFIC_ERROR " << error.what() << '\n'; return 1; }
}
