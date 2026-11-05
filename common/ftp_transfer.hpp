#pragma once
#include "ftp_probe.hpp"

namespace guard {
enum class NetTransferVerb { None, Upload, Download };

// Parses only clear FTP command lines. TLS bytes are never treated as commands.
class NetFtpTransferProbe {
 public:
    void Reset() { command_.Reset(); transfer_ = NetTransferVerb::None; tls_ = false; verb_[0] = '\0'; }
    bool Feed(const unsigned char* bytes, size_t count) {
        bool changed = false;
        for (size_t i = 0; i < count && !tls_; ++i) {
            command_.Feed(true, bytes + i, 1);
            if (bytes[i] != '\n') { continue; }
            if (command_.IsUpload() || command_.IsDownload()) {
                transfer_ = command_.IsUpload() ? NetTransferVerb::Upload : NetTransferVerb::Download;
                CopyVerb(); changed = true;
            }
            if (command_.IsTlsUpgrade()) { tls_ = true; CopyVerb(); changed = true; }
            command_.Reset();
        }
        return changed;
    }
    NetTransferVerb Transfer() const { return transfer_; }
    bool TlsRequested() const { return tls_; }
    const char* Verb() const { return verb_; }

 private:
    FtpProbe command_;
    NetTransferVerb transfer_;
    bool tls_;
    char verb_[8];
    void CopyVerb() {
        const char* source = command_.Verb();
        size_t i = 0;
        while (source[i] != '\0' && i + 1 < sizeof(verb_)) { verb_[i] = source[i]; ++i; }
        verb_[i] = '\0';
    }
};

class NetTransferGate {
 public:
    static bool DataCandidate(bool greeting, bool server, bool explicit_tls, NetTransferVerb transfer) {
        return !greeting || explicit_tls || SendsFile(server, transfer);
    }
    static bool GrantDataFlow(bool data, bool explicit_tls, bool blocked, size_t files) {
        return data && !explicit_tls && !blocked && files != 0;
    }
    static bool SendsFile(bool server, NetTransferVerb transfer) {
        return server ? transfer == NetTransferVerb::Download : transfer == NetTransferVerb::Upload;
    }
    static bool InspectData(bool server, bool explicit_tls, NetTransferVerb transfer, size_t length) {
        return length != 0 && (explicit_tls || SendsFile(server, transfer));
    }
    static const char* Evidence(bool server, bool explicit_tls) {
        if (explicit_tls) { return server ? "FTPS-SERVER-DATA" : "FTPS-CLIENT-DATA"; }
        return server ? "RETR-DATA" : "UPLOAD-DATA";
    }
};
}  // namespace guard
