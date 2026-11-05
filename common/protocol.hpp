#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#include <winioctl.h>
#endif

namespace guard {
inline constexpr ULONG kVersion = 3;
inline constexpr wchar_t kDeviceName[] = L"\\Device\\WfpFtpGuard";
inline constexpr wchar_t kDosName[] = L"\\DosDevices\\WfpFtpGuard";
inline constexpr wchar_t kUserDevice[] = L"\\\\.\\WfpFtpGuard";
inline constexpr wchar_t kServiceName[] = L"WfpFtpGuardPoc";
inline constexpr ULONG kGetEvent = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);
inline constexpr ULONG kSetDecision = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS);
inline constexpr ULONG kStop = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS);
inline constexpr ULONG kStatus = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS);
enum class NetEventKind : ULONG { Flow = 1, InspectFtp = 2, Allowed = 3, Blocked = 4, Error = 5, Closed = 6, FtpControl = 7, Transfer = 8 };
enum NetFlowFlags : USHORT { NetServer = 1, NetData = 2, NetExplicitTls = 4, NetInbound = 8, NetAmbiguous = 16 };
struct NetEvent {
    ULONG version;
    NetEventKind kind;
    UINT64 flow;
    UINT64 process_id;
    UINT64 process_created;
    UINT64 captured_at;
    ULONG detail;
    USHORT family;
    USHORT remote_port;
    USHORT local_port;
    USHORT flags;
    UCHAR remote_address[16];
    UCHAR local_address[16];
    char evidence[80];
    UINT64 control_flow;
    UINT64 file_since;
};
struct NetDecision {
    ULONG version;
    ULONG block;
    UINT64 flow;
    ULONG source_verified;
    ULONG reserved;
};
struct NetStatus {
    ULONG version;
    ULONG stopping;
    LONG flows;
    LONG queued_events;
    UINT64 detections;
    UINT64 blocked;
    UINT64 allowed;
};
static_assert(sizeof(NetEvent) == 184);
static_assert(sizeof(NetDecision) == 24);
}  // namespace guard
