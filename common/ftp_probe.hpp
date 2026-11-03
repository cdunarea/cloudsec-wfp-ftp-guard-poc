#pragma once
#include <stddef.h>

namespace guard {
enum class ProtocolVerdict { Unknown, Ftp, Other };

// Fixed-size, allocation-free parser shared by the kernel callout and user-mode tests.
// Inspect application control headers, never infer FTP from a TCP port number.
class FtpProbe {
 public:
    void Reset() {
        sent_ = received_ = 0;
        greeting_ = false;
        server_done_ = false;
        verdict_ = ProtocolVerdict::Unknown;
        verb_[0] = '\0';
    }
    ProtocolVerdict Feed(bool sending, const unsigned char* bytes, size_t count) {
        if (verdict_ != ProtocolVerdict::Unknown) { return verdict_; }
        for (size_t i = 0; i < count && verdict_ == ProtocolVerdict::Unknown; ++i) {
            if (sending) { ClientByte(bytes[i]); } else { ServerByte(bytes[i]); }
        }
        return verdict_;
    }
    ProtocolVerdict Verdict() const { return verdict_; }
    const char* Verb() const { return verb_; }
    bool HasGreeting() const { return greeting_; }
    bool IsUpload() const {
        return verdict_ == ProtocolVerdict::Ftp &&
            (TokenEquals("STOR", 4) || TokenEquals("APPE", 4) || TokenEquals("STOU", 4));
    }
    bool IsTlsUpgrade() const { return verdict_ == ProtocolVerdict::Ftp && TokenEquals("AUTH", 4); }

 private:
    static constexpr size_t kLimit = 512;
    char client_[kLimit];
    char server_[kLimit];
    size_t sent_;
    size_t received_;
    bool greeting_;
    bool server_done_;
    ProtocolVerdict verdict_;
    char verb_[8];

    static unsigned char Upper(unsigned char c) {
        return c >= 'a' && c <= 'z' ? static_cast<unsigned char>(c - ('a' - 'A')) : c;
    }
    bool TokenEquals(const char* token, size_t length) const {
        size_t i = 0;
        for (; i < length && token[i] != '\0'; ++i) {
            if (Upper(static_cast<unsigned char>(client_[i])) != static_cast<unsigned char>(token[i])) { return false; }
        }
        return i == length && token[i] == '\0';
    }
    bool PossibleCommand() const {
        static const char* const commands[] = {
            "USER", "PASS", "ACCT", "SYST", "FEAT", "PASV", "EPSV", "TYPE", "OPTS", "RETR", "STOR", "APPE", "STOU",
            "CWD", "CDUP", "PWD", "DELE", "MKD", "RMD", "RNFR", "RNTO", "PORT", "EPRT", "AUTH", "QUIT", "NOOP"
        };
        for (const char* command : commands) {
            size_t i = 0;
            while (i < sent_ && command[i] != '\0' && Upper(static_cast<unsigned char>(client_[i])) == static_cast<unsigned char>(command[i])) { ++i; }
            if (i == sent_ || (command[i] == '\0' && i < sent_ && (client_[i] == ' ' || client_[i] == '\r'))) { return true; }
        }
        return false;
    }
    void ServerByte(unsigned char byte) {
        if (server_done_) { return; }
        if (received_ == kLimit) { server_done_ = true; return; }
        server_[received_++] = static_cast<char>(byte);
        if (byte == '\n') {
            greeting_ = received_ >= 5 && server_[0] == '2' && server_[1] == '2' && server_[2] == '0' &&
                        (server_[3] == ' ' || server_[3] == '-') && server_[received_ - 2] == '\r';
            server_done_ = true;
        }
    }
    void ClientByte(unsigned char byte) {
        if (sent_ == kLimit || (byte < 0x20 && byte != '\r' && byte != '\n') || byte == 0x7f) {
            verdict_ = ProtocolVerdict::Other;
            return;
        }
        client_[sent_++] = static_cast<char>(byte);
        if (byte == '\n') { FinishLine(); return; }
        if (!PossibleCommand()) { verdict_ = ProtocolVerdict::Other; }
    }
    void FinishLine() {
        if (sent_ < 3 || client_[sent_ - 2] != '\r') { verdict_ = ProtocolVerdict::Other; return; }
        size_t token = 0;
        while (token < sent_ - 2 && client_[token] != ' ') { ++token; }
        static const char* const distinctive[] = {
            "SYST", "FEAT", "PASV", "EPSV", "TYPE", "OPTS", "RETR", "STOR", "APPE", "STOU", "CWD", "CDUP", "PWD",
            "DELE", "MKD", "RMD", "RNFR", "RNTO", "PORT", "EPRT"
        };
        bool ftp = false;
        for (const char* command : distinctive) { if (TokenEquals(command, token)) { ftp = true; break; } }
        if (greeting_ && (TokenEquals("USER", token) || TokenEquals("PASS", token) || TokenEquals("ACCT", token) ||
                          TokenEquals("QUIT", token) || TokenEquals("NOOP", token))) { ftp = true; }
        if (TokenEquals("AUTH", token) && sent_ == 10 && client_[4] == ' ' &&
            Upper(static_cast<unsigned char>(client_[5])) == 'T' && Upper(static_cast<unsigned char>(client_[6])) == 'L' &&
            Upper(static_cast<unsigned char>(client_[7])) == 'S') { ftp = true; }
        verdict_ = ftp ? ProtocolVerdict::Ftp : ProtocolVerdict::Other;
        if (ftp) {
            const size_t copy = token < sizeof(verb_) - 1 ? token : sizeof(verb_) - 1;
            for (size_t i = 0; i < copy; ++i) { verb_[i] = static_cast<char>(Upper(static_cast<unsigned char>(client_[i]))); }
            verb_[copy] = '\0';
        }
    }
};

// Reuse the command grammar on a confirmed FTP control flow. A later upload
// needs a fresh file-handle decision; clients may open the source after login.
class FtpUploadProbe {
 public:
    void Reset() { command_.Reset(); disabled_ = false; verb_[0] = '\0'; }
    bool Feed(const unsigned char* bytes, size_t count) {
        if (disabled_) { return false; }
        bool upload = false;
        for (size_t i = 0; i < count && !disabled_; ++i) {
            command_.Feed(true, bytes + i, 1);
            if (bytes[i] != '\n') { continue; }
            if (command_.IsUpload()) { CopyVerb(); upload = true; }
            disabled_ = command_.IsTlsUpgrade();
            command_.Reset();
        }
        return upload;
    }
    const char* Verb() const { return verb_; }

 private:
    FtpProbe command_;
    bool disabled_;
    char verb_[8];
    void CopyVerb() {
        const char* source = command_.Verb();
        size_t i = 0;
        while (source[i] != '\0' && i + 1 < sizeof(verb_)) { verb_[i] = source[i]; ++i; }
        verb_[i] = '\0';
    }
};
}  // namespace guard
