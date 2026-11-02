#include "net_driver_session.hpp"
#include <WinSock2.h>
#include <fwpmu.h>
#include <initguid.h>
#include <array>
#include <filesystem>
#include <system_error>
#include <vector>
#include "ids.hpp"
#include "diagnostics.hpp"

namespace guard {
void NetDriverSession::Check(DWORD error, const char* stage) {
    if (error != ERROR_SUCCESS) { throw std::system_error(static_cast<int>(error), std::system_category(), stage); }
}

NetDriverSession::NetDriverSession(const std::wstring& driver_path, const std::wstring& application) {
    try {
        Install(driver_path);
        device_.Reset(CreateFileW(kUserDevice, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        if (!device_.Valid()) { Check(GetLastError(), "Open driver device"); }
        if (ReadStatus().stopping != 0) { throw std::runtime_error("Driver is stopping; restart the loader"); }
        AddFilters(application);
        Diagnostics::Line("[DRIVER] loaded; IPv4/IPv6 outbound TCP streams monitored on all ports");
    } catch (...) { Shutdown(); throw; }
}

NetDriverSession::~NetDriverSession() { Shutdown(); }

void NetDriverSession::Install(const std::wstring& path) {
    const auto full_path = std::filesystem::absolute(path).wstring();
    if (!std::filesystem::is_regular_file(full_path)) { throw std::runtime_error("Driver .sys file was not found"); }
    manager_ = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (manager_ == nullptr) { Check(GetLastError(), "OpenSCManager (run as administrator)"); }
    constexpr DWORD access = SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | DELETE;
    service_ = CreateServiceW(manager_, kServiceName, L"WFP FTP Guard proof of concept", access, SERVICE_KERNEL_DRIVER,
                             SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, full_path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (service_ != nullptr) { created_ = true; }
    else {
        Check(GetLastError() == ERROR_SERVICE_EXISTS ? ERROR_SUCCESS : GetLastError(), "Create driver service");
        service_ = OpenServiceW(manager_, kServiceName, access);
        if (service_ == nullptr) { Check(GetLastError(), "Open existing driver service"); }
        DWORD size = 0;
        QueryServiceConfigW(service_, nullptr, 0, &size);
        std::vector<unsigned char> storage(size);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
        if (!QueryServiceConfigW(service_, config, size, &size)) { Check(GetLastError(), "Query driver service"); }
        if (_wcsicmp(config->lpBinaryPathName, full_path.c_str()) != 0) {
            throw std::runtime_error("Existing service has a different binary; refusing to change it");
        }
    }
    SERVICE_STATUS current{};
    if (!QueryServiceStatus(service_, &current)) { Check(GetLastError(), "Query driver state"); }
    if (current.dwCurrentState != SERVICE_STOPPED) { throw std::runtime_error("Another instance of the driver is already running"); }
    if (!StartServiceW(service_, 0, nullptr)) { Check(GetLastError(), "Load signed kernel driver"); }
    started_ = true;
}

void NetDriverSession::AddFilters(const std::wstring& application) {
    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t*>(L"WfpFtpGuard temporary filters");
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    Check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine_), "FwpmEngineOpen");
    FWP_BYTE_BLOB* app_id = nullptr;
    if (!application.empty()) { Check(FwpmGetAppIdFromFileName0(std::filesystem::absolute(application).c_str(), &app_id), "Resolve --app"); }
    try {
        Check(FwpmTransactionBegin0(engine_, 0), "Begin filter transaction");
        FWPM_SUBLAYER0 sublayer{};
        sublayer.subLayerKey = GuardSublayer;
        sublayer.displayData.name = const_cast<wchar_t*>(L"WFP FTP Guard PoC");
        sublayer.weight = 0x100;
        Check(FwpmSubLayerAdd0(engine_, &sublayer, nullptr), "Add sublayer");
        const GUID* keys[] = {&GuardFlowV4, &GuardFlowV6, &GuardStreamV4, &GuardStreamV6};
        const GUID* layers[] = {&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
                                &FWPM_LAYER_STREAM_V4, &FWPM_LAYER_STREAM_V6};
        for (size_t i = 0; i < std::size(keys); ++i) {
            FWPM_CALLOUT0 callout{};
            callout.calloutKey = *keys[i];
            callout.displayData.name = const_cast<wchar_t*>(L"WFP FTP Guard callout");
            callout.applicableLayer = *layers[i];
            Check(FwpmCalloutAdd0(engine_, &callout, nullptr, nullptr), "Add callout");
            FWPM_FILTER0 filter{};
            filter.displayData.name = const_cast<wchar_t*>(L"FTP control-stream inspection (no port condition)");
            filter.layerKey = *layers[i];
            filter.subLayerKey = GuardSublayer;
            filter.weight.type = FWP_UINT8;
            filter.weight.uint8 = 10;
            filter.action.type = i < 2 ? FWP_ACTION_CALLOUT_INSPECTION : FWP_ACTION_CALLOUT_UNKNOWN;
            filter.action.calloutKey = *keys[i];
            std::array<FWPM_FILTER_CONDITION0, 3> conditions{};
            if (i < 2) {
                conditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                conditions[0].matchType = FWP_MATCH_EQUAL;
                conditions[0].conditionValue.type = FWP_UINT8;
                conditions[0].conditionValue.uint8 = IPPROTO_TCP;
                conditions[1].fieldKey = FWPM_CONDITION_DIRECTION;
                conditions[1].matchType = FWP_MATCH_EQUAL;
                conditions[1].conditionValue.type = FWP_UINT32;
                conditions[1].conditionValue.uint32 = FWP_DIRECTION_OUTBOUND;
                filter.numFilterConditions = 2;
                if (app_id != nullptr) {
                    conditions[2].fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    conditions[2].matchType = FWP_MATCH_EQUAL;
                    conditions[2].conditionValue.type = FWP_BYTE_BLOB_TYPE;
                    conditions[2].conditionValue.byteBlob = app_id;
                    filter.numFilterConditions = 3;
                }
                filter.filterCondition = conditions.data();
            }
            Check(FwpmFilterAdd0(engine_, &filter, nullptr, nullptr), "Add filter");
        }
        Check(FwpmTransactionCommit0(engine_), "Commit filter transaction");
    } catch (...) {
        FwpmTransactionAbort0(engine_);
        if (app_id != nullptr) { FwpmFreeMemory0(reinterpret_cast<void**>(&app_id)); }
        throw;
    }
    if (app_id != nullptr) { FwpmFreeMemory0(reinterpret_cast<void**>(&app_id)); }
}

bool NetDriverSession::Next(NetEvent& event) {
    DWORD returned = 0;
    if (DeviceIoControl(device_.Get(), kGetEvent, nullptr, 0, &event, sizeof(event), &returned, nullptr)) {
        if (returned != sizeof(event) || event.version != kVersion) { throw std::runtime_error("Invalid driver event ABI"); }
        return true;
    }
    const DWORD error = GetLastError();
    if (error == ERROR_NO_MORE_ITEMS) { return false; }
    Check(error, "Read driver event");
    return false;
}

bool NetDriverSession::Decide(UINT64 flow, bool block) {
    const NetDecision decision{kVersion, block ? 1UL : 0UL, flow};
    DWORD returned = 0;
    return DeviceIoControl(device_.Get(), kSetDecision, const_cast<NetDecision*>(&decision), sizeof(decision), nullptr, 0, &returned, nullptr) != FALSE;
}

NetStatus NetDriverSession::ReadStatus() const {
    NetStatus status{};
    DWORD returned = 0;
    if (!DeviceIoControl(device_.Get(), kStatus, nullptr, 0, &status, sizeof(status), &returned, nullptr)) { Check(GetLastError(), "Read driver status"); }
    if (returned != sizeof(status) || status.version != kVersion) { throw std::runtime_error("Invalid driver status ABI"); }
    return status;
}

void NetDriverSession::Shutdown() noexcept {
    if (device_.Valid()) {
        DWORD returned = 0;
        if (!DeviceIoControl(device_.Get(), kStop, nullptr, 0, nullptr, 0, &returned, nullptr)) {
            Diagnostics::Line("[CLEANUP] driver drain failed: error=" + std::to_string(GetLastError()));
        }
    }
    if (engine_ != nullptr) { FwpmEngineClose0(engine_); engine_ = nullptr; }
    device_.Reset();
    if (started_ && service_ != nullptr) {
        SERVICE_STATUS status{};
        if (!ControlService(service_, SERVICE_CONTROL_STOP, &status)) {
            Diagnostics::Line("[CLEANUP] driver stop failed: error=" + std::to_string(GetLastError()));
        } else { Diagnostics::Line("[DRIVER] unloaded"); }
        started_ = false;
    }
    if (created_ && service_ != nullptr) { DeleteService(service_); created_ = false; }
    if (service_ != nullptr) { CloseServiceHandle(service_); service_ = nullptr; }
    if (manager_ != nullptr) { CloseServiceHandle(manager_); manager_ = nullptr; }
}
}  // namespace guard
