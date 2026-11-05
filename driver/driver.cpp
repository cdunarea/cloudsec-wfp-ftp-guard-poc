#pragma warning(push)
#pragma warning(disable:4324) // WDK NDIS structures intentionally use explicit alignment.
#include <ntifs.h>
#include <ndis.h>
#include <fwpsk.h>
#include <wdmsec.h>
#pragma warning(pop)
#include <initguid.h>
#include "ids.hpp"
#include "protocol.hpp"
#include "ftp_probe.hpp"
#include "ftp_transfer.hpp"

extern "C" DRIVER_INITIALIZE DriverEntry;

namespace {
constexpr ULONG kTag = 'pFtW';
constexpr ULONG kMaxFlows = 64;
constexpr SIZE_T kMaxQueuedBytes = 16 * 1024 * 1024;
enum class Verdict : LONG { Unknown, Waiting, Allow, Block, Closed };

struct Flow;
struct Segment {
    LIST_ENTRY link;
    NET_BUFFER_LIST* buffers;
    SIZE_T length;
    UINT32 flags;
    volatile LONG completions;
    Flow* owner;
};
struct Flow {
    LIST_ENTRY link;
    volatile LONG references;
    KSPIN_LOCK lock;
    LIST_ENTRY sending;
    LIST_ENTRY receiving;
    SIZE_T queued;
    UINT64 handle;
    UINT64 id;
    UINT32 callout;
    UINT16 layer;
    guard::NetEvent event;
    guard::FtpProbe probe;
    guard::NetFtpTransferProbe transfers;
    guard::NetTransferVerb transfer;
    BOOLEAN server;
    BOOLEAN explicit_tls;
    BOOLEAN data_flow;
    BOOLEAN source_verified;
    Verdict verdict;
    UINT64 waiting_since;
    UINT64 probe_since;
    BOOLEAN announced;
    BOOLEAN inspection_sent;
    BOOLEAN abort_sent;
    BOOLEAN ftp_confirmed;
    BOOLEAN closing;
    volatile LONG injection_status;
    BOOLEAN receiving_active;
    ULONG sending_injections;
    ULONG receiving_injections;
};
struct EventNode { LIST_ENTRY link; guard::NetEvent event; };
struct State {
    PDEVICE_OBJECT device;
    HANDLE injection;
    HANDLE worker;
    UINT32 callouts[4];
    KSPIN_LOCK flows_lock;
    LIST_ENTRY flows;
    volatile LONG flow_count;
    volatile LONG stopping;
    KEVENT wake;
    KEVENT flows_gone;
    KEVENT stopped;
    KSPIN_LOCK events_lock;
    LIST_ENTRY events;
    LONG event_count;
    volatile LONG64 sequence;
    volatile LONG64 detections;
    volatile LONG64 blocked;
    volatile LONG64 allowed;
    KSPIN_LOCK injections_lock;
    LONG injections;
    LONG classifies;
    KEVENT injections_gone;
};
State state{};

class Driver {
 public:
    static NTSTATUS Start(PDRIVER_OBJECT object) {
        KeInitializeSpinLock(&state.flows_lock);
        KeInitializeSpinLock(&state.events_lock);
        KeInitializeSpinLock(&state.injections_lock);
        InitializeListHead(&state.flows);
        InitializeListHead(&state.events);
        KeInitializeEvent(&state.wake, SynchronizationEvent, FALSE);
        KeInitializeEvent(&state.flows_gone, NotificationEvent, TRUE);
        KeInitializeEvent(&state.stopped, NotificationEvent, FALSE);
        KeInitializeEvent(&state.injections_gone, NotificationEvent, TRUE);
        UNICODE_STRING device = RTL_CONSTANT_STRING(L"\\Device\\WfpFtpGuard");
        UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        NTSTATUS status = IoCreateDeviceSecure(object, 0, &device, FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN, TRUE, &sddl, &GuardDeviceId, &state.device);
        if (!NT_SUCCESS(status)) { return status; }
        state.device->Flags |= DO_BUFFERED_IO;
        for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) { object->MajorFunction[i] = Dispatch; }
        object->DriverUnload = Unload;
        status = FwpsInjectionHandleCreate0(AF_UNSPEC, FWPS_INJECTION_TYPE_STREAM, &state.injection);
        if (NT_SUCCESS(status)) { status = RegisterCallout(GuardStreamV4, true, &state.callouts[2]); }
        if (NT_SUCCESS(status)) { status = RegisterCallout(GuardStreamV6, true, &state.callouts[3]); }
        if (NT_SUCCESS(status)) { status = RegisterCallout(GuardFlowV4, false, &state.callouts[0]); }
        if (NT_SUCCESS(status)) { status = RegisterCallout(GuardFlowV6, false, &state.callouts[1]); }
        if (NT_SUCCESS(status)) {
            OBJECT_ATTRIBUTES attributes;
            InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
            status = PsCreateSystemThread(&state.worker, THREAD_ALL_ACCESS, &attributes, nullptr, nullptr, Worker, nullptr);
        }
        if (NT_SUCCESS(status)) {
            UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\WfpFtpGuard");
            status = IoCreateSymbolicLink(&link, &device);
        }
        if (!NT_SUCCESS(status)) { Unload(object); return status; }
        state.device->Flags &= ~DO_DEVICE_INITIALIZING;
        return STATUS_SUCCESS;
    }

 private:
    static UINT64 Now() { return KeQueryInterruptTime(); }
    static void Reference(Flow* flow) { InterlockedIncrement(&flow->references); }
    static void Release(Flow* flow) { if (InterlockedDecrement(&flow->references) == 0) { ExFreePoolWithTag(flow, kTag); } }
    class FlowScope {
     public:
        explicit FlowScope(Flow* flow) : flow_(flow) {
            Reference(flow_);
            KIRQL irql;
            KeAcquireSpinLock(&state.injections_lock, &irql);
            ++state.classifies;
            KeClearEvent(&state.injections_gone);
            KeReleaseSpinLock(&state.injections_lock, irql);
        }
        ~FlowScope() {
            Release(flow_);
            KIRQL irql;
            KeAcquireSpinLock(&state.injections_lock, &irql);
            if (--state.classifies == 0 && state.injections == 0) { KeSetEvent(&state.injections_gone, IO_NO_INCREMENT, FALSE); }
            KeReleaseSpinLock(&state.injections_lock, irql);
        }
        FlowScope(const FlowScope&) = delete;
        FlowScope& operator=(const FlowScope&) = delete;
     private:
        Flow* flow_;
    };
    static void Discard(Segment* segment) {
        if (segment->buffers != nullptr) {
            FwpsDiscardClonedStreamData0(segment->buffers, 0, KeGetCurrentIrql() == DISPATCH_LEVEL);
        }
        ExFreePoolWithTag(segment, kTag);
    }
    static void DiscardList(LIST_ENTRY* list) {
        while (!IsListEmpty(list)) { Discard(CONTAINING_RECORD(RemoveHeadList(list), Segment, link)); }
    }
    static bool QueueEvent(Flow* flow, guard::NetEventKind kind, ULONG detail = 0, const char* context = nullptr) {
        auto* node = static_cast<EventNode*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EventNode), kTag));
        if (node == nullptr) { return false; }
        node->event = flow->event;
        node->event.kind = kind;
        node->event.detail = detail;
        if (context != nullptr) {
            SIZE_T i = 0;
            for (; i + 1 < sizeof(node->event.evidence) && context[i] != 0; ++i) { node->event.evidence[i] = context[i]; }
            node->event.evidence[i] = 0;
        }
        KIRQL irql;
        KeAcquireSpinLock(&state.events_lock, &irql);
        const bool room = state.event_count < 256;
        if (room) { InsertTailList(&state.events, &node->link); ++state.event_count; }
        KeReleaseSpinLock(&state.events_lock, irql);
        if (!room) { ExFreePoolWithTag(node, kTag); }
        return room;
    }
    static NTSTATUS NTAPI Notify(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, FWPS_FILTER0*) { return STATUS_SUCCESS; }
    static NTSTATUS RegisterCallout(const GUID& key, bool stream, UINT32* id) {
        FWPS_CALLOUT0 callout{};
        callout.calloutKey = key;
        callout.classifyFn = stream ? StreamClassify : FlowClassify;
        callout.notifyFn = Notify;
        callout.flowDeleteFn = stream ? FlowDelete : nullptr;
        callout.flags = stream ? FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW : 0;
        return FwpsCalloutRegister0(state.device, &callout, id);
    }
    static void NTAPI FlowClassify(const FWPS_INCOMING_VALUES0* values, const FWPS_INCOMING_METADATA_VALUES0* metadata,
                                   void*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0* result) {
        if ((result->rights & FWPS_RIGHT_ACTION_WRITE) != 0) { result->actionType = FWP_ACTION_CONTINUE; }
        if (InterlockedCompareExchange(&state.stopping, 0, 0) != 0 ||
            !FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_FLOW_HANDLE) ||
            !FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_PROCESS_ID)) { return; }
        const bool ipv6 = values->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6;
        const UINT direction = ipv6 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION;
        auto* flow = static_cast<Flow*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(Flow), kTag));
        if (flow == nullptr) { return; }
        InitializeListHead(&flow->sending);
        InitializeListHead(&flow->receiving);
        KeInitializeSpinLock(&flow->lock);
        flow->references = 1;
        flow->handle = metadata->flowHandle;
        flow->id = static_cast<UINT64>(InterlockedIncrement64(&state.sequence));
        flow->callout = state.callouts[ipv6 ? 3 : 2];
        flow->layer = static_cast<UINT16>(ipv6 ? FWPS_LAYER_STREAM_V6 : FWPS_LAYER_STREAM_V4);
        flow->probe.Reset();
        flow->transfers.Reset();
        flow->transfer = guard::NetTransferVerb::None;
        flow->server = values->incomingValue[direction].value.uint32 == FWP_DIRECTION_INBOUND;
        flow->event.version = guard::kVersion;
        flow->event.flow = flow->id;
        flow->event.process_id = metadata->processId;
        flow->event.flags = flow->server ? guard::NetServer | guard::NetInbound : 0;
        LARGE_INTEGER captured;
        KeQuerySystemTimePrecise(&captured);
        flow->event.captured_at = static_cast<UINT64>(captured.QuadPart);
        flow->event.file_since = flow->event.captured_at;
        FillEndpoint(flow->event, values, ipv6);
        KIRQL irql;
        KeAcquireSpinLock(&state.flows_lock, &irql);
        if (state.flow_count >= static_cast<LONG>(kMaxFlows) || state.stopping != 0) {
            KeReleaseSpinLock(&state.flows_lock, irql);
            Release(flow);
            return;
        }
        InsertTailList(&state.flows, &flow->link);
        InterlockedIncrement(&state.flow_count);
        KeClearEvent(&state.flows_gone);
        // Hold the list lock until association finishes; unload cannot miss this context.
        const NTSTATUS status = FwpsFlowAssociateContext0(flow->handle, flow->layer, flow->callout, reinterpret_cast<UINT64>(flow));
        if (!NT_SUCCESS(status)) {
            RemoveEntryList(&flow->link);
            if (InterlockedDecrement(&state.flow_count) == 0) { KeSetEvent(&state.flows_gone, IO_NO_INCREMENT, FALSE); }
        }
        KeReleaseSpinLock(&state.flows_lock, irql);
        if (!NT_SUCCESS(status)) { Release(flow); }
        KeSetEvent(&state.wake, IO_NO_INCREMENT, FALSE);
    }
    static void FillEndpoint(guard::NetEvent& event, const FWPS_INCOMING_VALUES0* values, bool ipv6) {
        const UINT remote = ipv6 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS;
        const UINT local = ipv6 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS;
        const UINT port = ipv6 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT;
        const UINT local_port = ipv6 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT;
        event.family = ipv6 ? AF_INET6 : AF_INET;
        event.remote_port = values->incomingValue[port].value.uint16;
        event.local_port = values->incomingValue[local_port].value.uint16;
        if (ipv6) {
            RtlCopyMemory(event.remote_address, values->incomingValue[remote].value.byteArray16->byteArray16, 16);
            RtlCopyMemory(event.local_address, values->incomingValue[local].value.byteArray16->byteArray16, 16);
        } else {
            const ULONG peer = RtlUlongByteSwap(values->incomingValue[remote].value.uint32);
            const ULONG own = RtlUlongByteSwap(values->incomingValue[local].value.uint32);
            RtlCopyMemory(event.remote_address, &peer, sizeof(peer));
            RtlCopyMemory(event.local_address, &own, sizeof(own));
        }
    }
    static void RequestInspection(Flow* flow, const char* verb) {
        flow->verdict = Verdict::Waiting;
        flow->waiting_since = Now();
        flow->inspection_sent = FALSE;
        InterlockedIncrement64(&state.detections);
        ULONG i = 0;
        while (verb[i] != '\0' && i + 1 < sizeof(flow->event.evidence)) { flow->event.evidence[i] = verb[i]; ++i; }
        flow->event.evidence[i] = '\0';
    }
    static void InspectProtocol(Flow* flow, bool sending, const UCHAR* prefix, SIZE_T copied, UINT32 flags) {
        const bool client_command = sending != (flow->server != FALSE);
        const bool changed = client_command && flow->transfers.Feed(prefix, copied);
        flow->transfer = flow->transfers.Transfer();
        if (flow->transfers.TlsRequested()) {
            flow->explicit_tls = TRUE;
            flow->event.flags |= guard::NetExplicitTls;
        }
        if (flow->verdict == Verdict::Unknown) {
            const auto protocol = flow->probe.Feed(client_command, prefix, copied);
            if (protocol == guard::ProtocolVerdict::Other) { flow->verdict = Verdict::Allow; }
            if (protocol == guard::ProtocolVerdict::Ftp) {
                flow->ftp_confirmed = TRUE;
                flow->verdict = Verdict::Allow;
                QueueEvent(flow, guard::NetEventKind::FtpControl, 0, flow->probe.Verb());
            }
            if (flow->verdict == Verdict::Unknown && (flags & FWPS_STREAM_FLAG_SEND_DISCONNECT) != 0) {
                flow->verdict = Verdict::Allow;
            }
        }
        if (changed && flow->ftp_confirmed) {
            QueueEvent(flow, guard::NetEventKind::Transfer, 0, flow->transfers.Verb());
            // Client uploads may already have an open/briefly opened source.
            // Server RETR must reach the server first so it can open that source.
            if (!flow->server && flow->transfer == guard::NetTransferVerb::Upload &&
                !flow->explicit_tls && flow->verdict == Verdict::Allow) {
                RequestInspection(flow, flow->transfers.Verb());
            }
        }
    }
    static bool SamePeer(const Flow* left, const Flow* right) {
        const auto& a = left->event;
        const auto& b = right->event;
        return a.process_id == b.process_id && a.family == b.family &&
            RtlCompareMemory(a.remote_address, b.remote_address, a.family == AF_INET6 ? 16 : 4) ==
                static_cast<SIZE_T>(a.family == AF_INET6 ? 16 : 4);
    }
    static void AssociateData(Flow* flow, bool greeting) {
        // PoC correlation, not decrypted FTP negotiation: same owning process
        // and peer as a live recognized control flow. Ambiguity is reported.
        Flow* parent = nullptr;
        ULONG matches = 0;
        KIRQL irql;
        KeAcquireSpinLock(&state.flows_lock, &irql);
        for (auto* entry = state.flows.Flink; entry != &state.flows; entry = entry->Flink) {
            auto* candidate = CONTAINING_RECORD(entry, Flow, link);
            if (candidate == flow || !SamePeer(candidate, flow)) { continue; }
            KeAcquireSpinLockAtDpcLevel(&candidate->lock);
            const bool match = candidate->ftp_confirmed && !candidate->data_flow && !candidate->closing &&
                candidate->verdict != Verdict::Closed && candidate->verdict != Verdict::Block &&
                (candidate->server ? candidate->event.local_port != flow->event.local_port :
                                     candidate->event.remote_port != flow->event.remote_port);
            KeReleaseSpinLockFromDpcLevel(&candidate->lock);
            if (match) { parent = candidate; ++matches; }
        }
        if (parent != nullptr) {
            KeAcquireSpinLockAtDpcLevel(&parent->lock);
            const BOOLEAN server = parent->server;
            const BOOLEAN tls = parent->explicit_tls;
            const auto transfer = parent->transfer;
            const auto id = parent->id;
            const auto since = parent->event.captured_at;
            KeReleaseSpinLockFromDpcLevel(&parent->lock);
            KeAcquireSpinLockAtDpcLevel(&flow->lock);
            if (!flow->ftp_confirmed && !flow->probe.HasGreeting() &&
                guard::NetTransferGate::DataCandidate(greeting, server != FALSE, tls != FALSE, transfer)) {
                flow->data_flow = TRUE;
                flow->server = server;
                flow->explicit_tls = tls;
                flow->transfer = transfer;
                flow->event.flags = static_cast<USHORT>((flow->event.flags & guard::NetInbound) | guard::NetData |
                    (server ? guard::NetServer : 0) | (tls ? guard::NetExplicitTls : 0) | (matches > 1 ? guard::NetAmbiguous : 0));
                flow->event.control_flow = matches == 1 ? id : 0;
                flow->event.file_since = since;
            }
            KeReleaseSpinLockFromDpcLevel(&flow->lock);
        }
        KeReleaseSpinLock(&state.flows_lock, irql);
    }
    static void NTAPI StreamClassify(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*,
                                     void* layer_data, const FWPS_FILTER0*, UINT64 context, FWPS_CLASSIFY_OUT0* result) {
        auto* packet = static_cast<FWPS_STREAM_CALLOUT_IO_PACKET0*>(layer_data);
        auto* flow = reinterpret_cast<Flow*>(context);
        result->actionType = FWP_ACTION_PERMIT;
        if (packet == nullptr || packet->streamData == nullptr || flow == nullptr) { return; }
        const FlowScope scope(flow);
        auto* data = packet->streamData;
        packet->streamAction = FWPS_STREAM_ACTION_NONE;
        packet->countBytesEnforced = 0; // Consume the entire indication, including disconnect state.
        packet->countBytesRequired = 0;
        if (TrackDisconnect(flow, data->flags)) { return; }
        if (data->dataLength == 0 && (data->flags & (FWPS_STREAM_FLAG_SEND_DISCONNECT | FWPS_STREAM_FLAG_RECEIVE_DISCONNECT)) == 0) { return; }
        auto* segment = static_cast<Segment*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(Segment), kTag));
        if (segment == nullptr) { Drop(packet, result); return; }
        segment->flags = data->flags;
        segment->length = data->dataLength;
        // FIN carries a zero-length NBL. Clone it too, retaining the stream's lifetime until reinjection.
        if (!NT_SUCCESS(FwpsCloneStreamData0(data, nullptr, nullptr, 0, &segment->buffers))) {
            Discard(segment); Drop(packet, result); return;
        }
        UCHAR prefix[512];
        SIZE_T copied = 0;
        if (data->dataLength != 0) {
            FwpsCopyStreamDataToBuffer0(data, prefix, data->dataLength < sizeof(prefix) ? data->dataLength : sizeof(prefix), &copied);
        }
        const bool sending = (data->flags & FWPS_STREAM_FLAG_SEND) != 0;
        const bool greeting = copied >= 4 && prefix[0] == '2' && prefix[1] == '2' && prefix[2] == '0' &&
            (prefix[3] == ' ' || prefix[3] == '-');
        AssociateData(flow, greeting);
        KIRQL irql;
        KeAcquireSpinLock(&flow->lock, &irql);
        const bool reject = RejectSegment(flow, segment->length);
        if (!reject) {
            if (sending && flow->probe_since == 0) { flow->probe_since = Now(); }
            if (flow->data_flow) {
                if (flow->verdict == Verdict::Unknown) { flow->verdict = Verdict::Allow; }
                if (sending && flow->verdict == Verdict::Allow && !flow->source_verified &&
                    guard::NetTransferGate::InspectData(flow->server != FALSE, flow->explicit_tls != FALSE, flow->transfer, segment->length)) {
                    RequestInspection(flow, guard::NetTransferGate::Evidence(flow->server != FALSE, flow->explicit_tls != FALSE));
                }
            } else { InspectProtocol(flow, sending, prefix, copied, data->flags); }
            InsertTailList(sending ? &flow->sending : &flow->receiving, &segment->link);
            flow->queued += segment->length;
        }
        KeReleaseSpinLock(&flow->lock, irql);
        if (reject) { Discard(segment); Drop(packet, result); return; }
        // Always clone/absorb/reinject both directions, for the whole lifetime of a tracked flow.
        // Switching back to inline processing after an asynchronous decision violates WFP's contract.
        result->actionType = FWP_ACTION_BLOCK;
        if (!sending) { DrainReceiving(flow); }
        KeSetEvent(&state.wake, IO_NO_INCREMENT, FALSE);
    }
    static bool TrackDisconnect(Flow* flow, UINT32 flags) {
        const bool abort = (flags & (FWPS_STREAM_FLAG_SEND_ABORT | FWPS_STREAM_FLAG_RECEIVE_ABORT)) != 0;
        if (!abort && (flags & (FWPS_STREAM_FLAG_SEND_DISCONNECT | FWPS_STREAM_FLAG_RECEIVE_DISCONNECT)) == 0) { return false; }
        KIRQL irql;
        KeAcquireSpinLock(&flow->lock, &irql);
        flow->closing = TRUE;
        if (abort) { flow->verdict = Verdict::Closed; }
        if (abort) { QueueEvent(flow, guard::NetEventKind::Closed, flags, (flags & FWPS_STREAM_FLAG_RECEIVE_ABORT) != 0 ? "peer-abort" : "local-abort"); }
        KeReleaseSpinLock(&flow->lock, irql);
        return abort;
    }
    // Called with the per-flow lock held. Both queued and in-flight clones count.
    static bool RejectSegment(Flow* flow, SIZE_T length) {
        if (state.stopping != 0 || flow->verdict == Verdict::Closed || flow->verdict == Verdict::Block) { return true; }
        if (length <= kMaxQueuedBytes - flow->queued) { return false; }
        flow->verdict = Verdict::Block;
        QueueEvent(flow, guard::NetEventKind::Error, static_cast<ULONG>(STATUS_INSUFFICIENT_RESOURCES), "stream-queue-limit");
        return true;
    }
    static void Drop(FWPS_STREAM_CALLOUT_IO_PACKET0* packet, FWPS_CLASSIFY_OUT0* result) {
        packet->streamAction = FWPS_STREAM_ACTION_DROP_CONNECTION;
        result->actionType = FWP_ACTION_NONE;
    }
    static void NTAPI FlowDelete(UINT16, UINT32, UINT64 context) {
        auto* flow = reinterpret_cast<Flow*>(context);
        KIRQL irql;
        KeAcquireSpinLock(&state.flows_lock, &irql);
        RemoveEntryList(&flow->link);
        if (InterlockedDecrement(&state.flow_count) == 0) { KeSetEvent(&state.flows_gone, IO_NO_INCREMENT, FALSE); }
        KeReleaseSpinLock(&state.flows_lock, irql);
        KeAcquireSpinLock(&flow->lock, &irql);
        flow->verdict = Verdict::Closed;
        KeReleaseSpinLock(&flow->lock, irql);
        // The worker may own one in-flight segment, but the detached queues belong to this callback.
        LIST_ENTRY outgoing, incoming;
        InitializeListHead(&outgoing);
        InitializeListHead(&incoming);
        KeAcquireSpinLock(&flow->lock, &irql);
        DetachQueued(flow, &flow->sending, &outgoing);
        DetachQueued(flow, &flow->receiving, &incoming);
        KeReleaseSpinLock(&flow->lock, irql);
        DiscardList(&outgoing);
        DiscardList(&incoming);
        Release(flow);
    }
    static void DetachQueued(Flow* flow, LIST_ENTRY* source, LIST_ENTRY* target) {
        while (!IsListEmpty(source)) {
            auto* entry = RemoveHeadList(source);
            flow->queued -= CONTAINING_RECORD(entry, Segment, link)->length;
            InsertTailList(target, entry);
        }
    }
    static void BeginInjection() {
        KIRQL irql;
        KeAcquireSpinLock(&state.injections_lock, &irql);
        ++state.injections;
        KeClearEvent(&state.injections_gone);
        KeReleaseSpinLock(&state.injections_lock, irql);
    }
    static void CompleteSegment(Segment* segment) {
        if (InterlockedDecrement(&segment->completions) != 0) { return; }
        auto* flow = segment->owner;
        KIRQL irql;
        KeAcquireSpinLock(&flow->lock, &irql);
        flow->queued -= segment->length;
        const bool drained = (segment->flags & FWPS_STREAM_FLAG_SEND) != 0 ? --flow->sending_injections == 0 : --flow->receiving_injections == 0;
        KeReleaseSpinLock(&flow->lock, irql);
        if (drained) { KeSetEvent(&state.wake, IO_NO_INCREMENT, FALSE); }
        ExFreePoolWithTag(segment, kTag);
        Release(flow);
        KeAcquireSpinLock(&state.injections_lock, &irql);
        if (--state.injections == 0 && state.classifies == 0) { KeSetEvent(&state.injections_gone, IO_NO_INCREMENT, FALSE); }
        KeReleaseSpinLock(&state.injections_lock, irql);
    }
    static void NTAPI InjectionComplete(void* context, NET_BUFFER_LIST* buffers, BOOLEAN) {
        auto* segment = static_cast<Segment*>(context);
        const auto status = static_cast<NTSTATUS>(NET_BUFFER_LIST_STATUS(buffers));
        if (!NT_SUCCESS(status)) {
            InterlockedCompareExchange(&segment->owner->injection_status, status, STATUS_SUCCESS);
            KeSetEvent(&state.wake, IO_NO_INCREMENT, FALSE);
        }
        FwpsFreeCloneNetBufferList0(buffers, 0);
        CompleteSegment(segment);
    }
    static NTSTATUS Inject(Flow* flow, Segment* segment, bool& submission_failed) {
        submission_failed = false;
        KIRQL irql;
        KeAcquireSpinLock(&flow->lock, &irql);
        const bool closed = flow->verdict == Verdict::Closed;
        if (!closed) {
            if ((segment->flags & FWPS_STREAM_FLAG_SEND) != 0) { ++flow->sending_injections; }
            else { ++flow->receiving_injections; }
        }
        KeReleaseSpinLock(&flow->lock, irql);
        if (closed) {
            KeAcquireSpinLock(&flow->lock, &irql);
            flow->queued -= segment->length;
            KeReleaseSpinLock(&flow->lock, irql);
            Discard(segment); return STATUS_CANCELLED;
        }
        segment->owner = flow;
        Reference(flow);
        // The submitter reference prevents an inline callback from freeing the
        // segment before FwpsStreamInjectAsync0 has returned.
        segment->completions = 1;
        for (auto* buffer = segment->buffers; buffer != nullptr; buffer = NET_BUFFER_LIST_NEXT_NBL(buffer)) { ++segment->completions; }
        BeginInjection();
        const UINT32 flags = segment->flags | ((segment->flags & FWPS_STREAM_FLAG_SEND) != 0 ? FWPS_STREAM_FLAG_SEND_NODELAY : FWPS_STREAM_FLAG_RECEIVE_PUSH);
        const NTSTATUS status = FwpsStreamInjectAsync0(state.injection, nullptr, 0, flow->handle, flow->callout, flow->layer,
            flags, segment->buffers, segment->length, InjectionComplete, segment);
        if (!NT_SUCCESS(status)) {
            submission_failed = true;
            if (segment->buffers != nullptr) { FwpsDiscardClonedStreamData0(segment->buffers, 0, KeGetCurrentIrql() == DISPATCH_LEVEL); }
            segment->completions = 1; // No callback runs for a failed submission.
        }
        CompleteSegment(segment);
        return status;
    }
    static bool OriginExited(const Flow* flow) {
        PEPROCESS process = nullptr;
        const NTSTATUS lookup = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(flow->event.process_id), &process);
        if (!NT_SUCCESS(lookup)) { return lookup == STATUS_INVALID_CID; }
        const bool exited = PsGetProcessExitStatus(process) != STATUS_PENDING ||
            static_cast<UINT64>(PsGetProcessCreateTimeQuadPart(process)) > flow->event.captured_at;
        ObDereferenceObject(process);
        return exited;
    }
    static bool TransportClosed(NTSTATUS status) {
        return status == STATUS_CONNECTION_RESET || status == STATUS_CONNECTION_DISCONNECTED ||
            status == STATUS_CONNECTION_ABORTED || status == STATUS_LOCAL_DISCONNECT || status == STATUS_REMOTE_DISCONNECT;
    }
    static void InjectionFailed(Flow* flow, NTSTATUS status, bool zero_fin, bool submission_failed) {
        // A synchronous lookup failure means there is no stream left to inject
        // into. Keep that terminal transport outcome distinct from policy blocks.
        const bool origin_exited = status == STATUS_INVALID_DEVICE_STATE && OriginExited(flow);
        KIRQL irql;
        KeAcquireSpinLock(&flow->lock, &irql);
        const bool unavailable = TransportClosed(status) || (submission_failed && status == STATUS_NOT_FOUND) ||
                                 ((flow->closing || origin_exited) && status == STATUS_INVALID_DEVICE_STATE);
        const bool closed = flow->verdict == Verdict::Closed;
        if (!closed) { flow->verdict = unavailable ? Verdict::Closed : Verdict::Block; }
        KeReleaseSpinLock(&flow->lock, irql);
        const char* context = origin_exited ? "origin-exited-invalid-state" : zero_fin ? (submission_failed ? "fin-submit" : "fin-complete") :
                                        (submission_failed ? "data-submit" : "data-complete");
        if (!closed) {
            QueueEvent(flow, unavailable ? guard::NetEventKind::Closed : guard::NetEventKind::Error, static_cast<ULONG>(status), context);
        }
    }
    static void Announce(Flow* flow) {
        if (flow->announced) { return; }
        PEPROCESS process = nullptr;
        if (NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(flow->event.process_id), &process))) {
            const auto created = static_cast<UINT64>(PsGetProcessCreateTimeQuadPart(process));
            if (created <= flow->event.captured_at) { flow->event.process_created = created; }
            ObDereferenceObject(process);
        }
        flow->announced = TRUE;
        QueueEvent(flow, guard::NetEventKind::Flow);
    }
    static void Process(Flow* flow) {
        Announce(flow);
        DrainReceiving(flow);
        const auto failed = static_cast<NTSTATUS>(InterlockedExchange(&flow->injection_status, STATUS_SUCCESS));
        if (!NT_SUCCESS(failed)) { InjectionFailed(flow, failed, false, false); }
        for (ULONG budget = 0; budget < 32; ++budget) {
            KIRQL irql;
            KeAcquireSpinLock(&flow->lock, &irql);
            if (flow->verdict == Verdict::Unknown && flow->probe_since != 0 && Now() - flow->probe_since > 3ULL * 10000000) {
                flow->verdict = Verdict::Allow;
            }
            if (flow->verdict == Verdict::Waiting && !flow->inspection_sent) {
                flow->inspection_sent = TRUE;
                if (!QueueEvent(flow, guard::NetEventKind::InspectFtp)) { flow->verdict = Verdict::Block; }
            }
            if (flow->verdict == Verdict::Waiting && Now() - flow->waiting_since > 15ULL * 10000000) {
                flow->verdict = Verdict::Block;
                QueueEvent(flow, guard::NetEventKind::Error, STATUS_TIMEOUT);
            }
            if (flow->verdict == Verdict::Block && !flow->abort_sent) {
                flow->abort_sent = TRUE;
                KeReleaseSpinLock(&flow->lock, irql);
                InterlockedIncrement64(&state.blocked);
                QueueEvent(flow, guard::NetEventKind::Blocked);
                FwpsFlowAbort0(flow->handle);
                return;
            }
            Segment* segment = nullptr;
            if (flow->verdict == Verdict::Allow || (flow->verdict == Verdict::Unknown && flow->server)) {
                LIST_ENTRY* queue = &flow->sending;
                if (!IsListEmpty(queue)) {
                    auto* next = CONTAINING_RECORD(queue->Flink, Segment, link);
                    if (!Disconnect(next) || flow->sending_injections == 0) { segment = CONTAINING_RECORD(RemoveHeadList(queue), Segment, link); }
                }
            }
            KeReleaseSpinLock(&flow->lock, irql);
            if (segment == nullptr) { return; }
            const bool zero_fin = segment->length == 0 &&
                (segment->flags & (FWPS_STREAM_FLAG_SEND_DISCONNECT | FWPS_STREAM_FLAG_RECEIVE_DISCONNECT)) != 0;
            bool submission_failed = false;
            const NTSTATUS status = Inject(flow, segment, submission_failed);
            if (!NT_SUCCESS(status)) { InjectionFailed(flow, status, zero_fin, submission_failed); return; }
        }
        KeSetEvent(&state.wake, IO_NO_INCREMENT, FALSE); // More queued work must not wait for the timer.
    }
    static void DrainReceiving(Flow* flow) {
        KIRQL irql;
        KeAcquireSpinLock(&flow->lock, &irql);
        if (flow->receiving_active) { KeReleaseSpinLock(&flow->lock, irql); return; }
        flow->receiving_active = TRUE;
        KeReleaseSpinLock(&flow->lock, irql);
        // Incoming TLS records do not carry local file data. Keep the same
        // clone/block/inject model, but never wait for an outgoing file verdict.
        bool waiting_completion = false;
        for (ULONG budget = 0; budget < 32; ++budget) {
            KeAcquireSpinLock(&flow->lock, &irql);
            Segment* segment = nullptr;
            if (flow->verdict != Verdict::Closed && flow->verdict != Verdict::Block && !IsListEmpty(&flow->receiving)) {
                auto* next = CONTAINING_RECORD(flow->receiving.Flink, Segment, link);
                waiting_completion = Disconnect(next) && flow->receiving_injections != 0;
                if (!waiting_completion) { segment = CONTAINING_RECORD(RemoveHeadList(&flow->receiving), Segment, link); }
            }
            KeReleaseSpinLock(&flow->lock, irql);
            if (segment == nullptr) { break; }
            bool failed_submission = false;
            const auto status = Inject(flow, segment, failed_submission);
            if (!NT_SUCCESS(status)) {
                InterlockedCompareExchange(&flow->injection_status, status, STATUS_SUCCESS);
                break;
            }
        }
        KeAcquireSpinLock(&flow->lock, &irql);
        flow->receiving_active = FALSE;
        const bool more = flow->verdict != Verdict::Closed && flow->verdict != Verdict::Block && !IsListEmpty(&flow->receiving);
        KeReleaseSpinLock(&flow->lock, irql);
        if (more && !waiting_completion) { KeSetEvent(&state.wake, IO_NO_INCREMENT, FALSE); }
    }
    static bool Disconnect(const Segment* segment) {
        return (segment->flags & (FWPS_STREAM_FLAG_SEND_DISCONNECT | FWPS_STREAM_FLAG_RECEIVE_DISCONNECT)) != 0;
    }
    static ULONG Snapshot(Flow** batch) {
        ULONG count = 0;
        KIRQL irql;
        KeAcquireSpinLock(&state.flows_lock, &irql);
        for (auto* entry = state.flows.Flink; entry != &state.flows && count < kMaxFlows; entry = entry->Flink) {
            batch[count] = CONTAINING_RECORD(entry, Flow, link);
            Reference(batch[count++]);
        }
        KeReleaseSpinLock(&state.flows_lock, irql);
        return count;
    }
    static void NTAPI Worker(void*) {
        LARGE_INTEGER wait;
        wait.QuadPart = -1000000; // 100 ms, also drives bounded probe/decision timeouts.
        for (;;) {
            KeWaitForSingleObject(&state.wake, Executive, KernelMode, FALSE, &wait);
            Flow* batch[kMaxFlows];
            const ULONG count = Snapshot(batch);
            for (ULONG i = 0; i < count; ++i) { Process(batch[i]); Release(batch[i]); }
            if (state.stopping != 0 && state.flow_count == 0) { break; }
        }
        PsTerminateSystemThread(STATUS_SUCCESS);
    }
    static void Stop() {
        if (InterlockedCompareExchange(&state.stopping, 1, 0) != 0) {
            KeWaitForSingleObject(&state.stopped, Executive, KernelMode, FALSE, nullptr);
            return;
        }
        Flow* batch[kMaxFlows];
        const ULONG count = Snapshot(batch);
        for (ULONG i = 0; i < count; ++i) {
            FwpsFlowAbort0(batch[i]->handle);
            FwpsFlowRemoveContext0(batch[i]->handle, batch[i]->layer, batch[i]->callout);
            Release(batch[i]);
        }
        KeSetEvent(&state.wake, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(&state.flows_gone, Executive, KernelMode, FALSE, nullptr);
        if (state.worker != nullptr) { ZwWaitForSingleObject(state.worker, FALSE, nullptr); ZwClose(state.worker); state.worker = nullptr; }
        KeWaitForSingleObject(&state.injections_gone, Executive, KernelMode, FALSE, nullptr);
        KeSetEvent(&state.stopped, IO_NO_INCREMENT, FALSE);
    }
    static NTSTATUS SetDecision(const guard::NetDecision& decision) {
        if (decision.version != guard::kVersion || decision.block > 1 || decision.source_verified > 1 ||
            decision.reserved != 0 || (decision.block != 0 && decision.source_verified != 0)) { return STATUS_INVALID_PARAMETER; }
        Flow* target = nullptr;
        KIRQL irql;
        KeAcquireSpinLock(&state.flows_lock, &irql);
        for (auto* entry = state.flows.Flink; entry != &state.flows; entry = entry->Flink) {
            auto* flow = CONTAINING_RECORD(entry, Flow, link);
            if (flow->id == decision.flow) { target = flow; Reference(flow); break; }
        }
        KeReleaseSpinLock(&state.flows_lock, irql);
        if (target == nullptr) { return STATUS_NOT_FOUND; }
        KeAcquireSpinLock(&target->lock, &irql);
        const bool pending = target->verdict == Verdict::Waiting &&
            (decision.source_verified == 0 || (target->data_flow && !target->explicit_tls));
        if (pending) {
            target->verdict = decision.block ? Verdict::Block : Verdict::Allow;
            target->source_verified = decision.source_verified != 0;
        }
        KeReleaseSpinLock(&target->lock, irql);
        if (pending && !decision.block) { InterlockedIncrement64(&state.allowed); QueueEvent(target, guard::NetEventKind::Allowed); }
        Release(target);
        KeSetEvent(&state.wake, IO_NO_INCREMENT, FALSE);
        return pending ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
    }
    static NTSTATUS ReadEvent(void* output, ULONG capacity, ULONG_PTR& written) {
        if (capacity < sizeof(guard::NetEvent)) { return STATUS_BUFFER_TOO_SMALL; }
        KIRQL irql;
        KeAcquireSpinLock(&state.events_lock, &irql);
        EventNode* node = nullptr;
        if (!IsListEmpty(&state.events)) { node = CONTAINING_RECORD(RemoveHeadList(&state.events), EventNode, link); --state.event_count; }
        KeReleaseSpinLock(&state.events_lock, irql);
        if (node == nullptr) { return STATUS_NO_MORE_ENTRIES; }
        RtlCopyMemory(output, &node->event, sizeof(node->event));
        written = sizeof(node->event);
        ExFreePoolWithTag(node, kTag);
        return STATUS_SUCCESS;
    }
    static NTSTATUS Control(PIRP irp, const IO_STACK_LOCATION* stack, ULONG_PTR& written) {
        const auto& request = stack->Parameters.DeviceIoControl;
        void* buffer = irp->AssociatedIrp.SystemBuffer;
        switch (request.IoControlCode) {
        case guard::kGetEvent: return ReadEvent(buffer, request.OutputBufferLength, written);
        case guard::kSetDecision:
            if (request.InputBufferLength != sizeof(guard::NetDecision)) { return STATUS_INFO_LENGTH_MISMATCH; }
            return SetDecision(*static_cast<const guard::NetDecision*>(buffer));
        case guard::kStop: Stop(); return STATUS_SUCCESS;
        case guard::kStatus: {
            if (request.OutputBufferLength < sizeof(guard::NetStatus)) { return STATUS_BUFFER_TOO_SMALL; }
            const guard::NetStatus status{guard::kVersion, static_cast<ULONG>(state.stopping), state.flow_count, state.event_count,
                static_cast<UINT64>(state.detections), static_cast<UINT64>(state.blocked), static_cast<UINT64>(state.allowed)};
            RtlCopyMemory(buffer, &status, sizeof(status));
            written = sizeof(status);
            return STATUS_SUCCESS;
        }
        default: return STATUS_INVALID_DEVICE_REQUEST;
        }
    }
    static NTSTATUS NTAPI Dispatch(PDEVICE_OBJECT, PIRP irp) {
        auto* stack = IoGetCurrentIrpStackLocation(irp);
        NTSTATUS status = STATUS_SUCCESS;
        ULONG_PTR written = 0;
        if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) { status = Control(irp, stack, written); }
        else if (stack->MajorFunction == IRP_MJ_CLEANUP) { Stop(); }
        else if (stack->MajorFunction != IRP_MJ_CREATE && stack->MajorFunction != IRP_MJ_CLOSE) { status = STATUS_INVALID_DEVICE_REQUEST; }
        irp->IoStatus.Status = status;
        irp->IoStatus.Information = written;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    }
    static void NTAPI Unload(PDRIVER_OBJECT) {
        Stop();
        for (UINT32 callout : state.callouts) { if (callout != 0) { FwpsCalloutUnregisterById0(callout); } }
        if (state.injection != nullptr) { FwpsInjectionHandleDestroy0(state.injection); }
        while (!IsListEmpty(&state.events)) { ExFreePoolWithTag(CONTAINING_RECORD(RemoveHeadList(&state.events), EventNode, link), kTag); }
        UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\WfpFtpGuard");
        IoDeleteSymbolicLink(&link);
        IoDeleteDevice(state.device);
    }
};
}  // namespace

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT object, PUNICODE_STRING) { return Driver::Start(object); }
