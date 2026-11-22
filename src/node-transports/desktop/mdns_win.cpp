#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <windns.h>

#pragma comment(lib, "dnsapi.lib")

#include "lan/tanit_mdns.hpp"
#include "string/string_utils.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace media_cli::mdns {
namespace {

using media::strutil::utf8_to_wide;

std::wstring dns_label(std::wstring in)
{
    std::wstring o;
    for (wchar_t c : in) {
        if ((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9'))
            o.push_back(c);
        else if (!o.empty() && o.back() != L'-')
            o.push_back(L'-');
    }
    while (!o.empty() && o.back() == L'-')
        o.pop_back();
    if (o.size() > 40)
        o.resize(40);
    while (!o.empty() && o.back() == L'-')
        o.pop_back();
    if (o.empty())
        o = L"Tanit";
    return o;
}

std::wstring computer_name_w()
{
    wchar_t buf[256];
    DWORD n = 256;
    if (!GetComputerNameW(buf, &n) || n == 0)
        return L"Tanit";
    return std::wstring(buf, n);
}

struct Wait {
    HANDLE event = nullptr;
    DWORD status = ERROR_IO_PENDING;
};

void WINAPI complete(DWORD status, PVOID ctx, PDNS_SERVICE_INSTANCE)
{
    auto* wait = static_cast<Wait*>(ctx);
    if (!wait)
        return;
    wait->status = status;
    if (wait->event)
        SetEvent(wait->event);
}

std::string service_type_clean(std::string type)
{
    while (!type.empty() && type.back() == '.')
        type.pop_back();
    return type;
}

} // namespace

struct Publisher::Impl {
    PDNS_SERVICE_INSTANCE inst = nullptr;
    DNS_SERVICE_REGISTER_REQUEST req{};
    Wait wait;
    bool registered = false;
};

Publisher::Publisher() : impl_(new Impl) {}

Publisher::~Publisher()
{
    stop();
    delete impl_;
    impl_ = nullptr;
}

bool Publisher::start(const Publication& pub, std::string& err)
{
    stop();
    if (!impl_)
        impl_ = new Impl;
    if (pub.port <= 0 || pub.port > 65535) {
        err = "mDNS port is out of range";
        return false;
    }
    const std::string type = service_type_clean(pub.service_type);
    if (type.size() < 6 || type.front() != '_') {
        err = "mDNS service type is missing";
        return false;
    }
    if (!impl_->wait.event)
        impl_->wait.event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    const std::wstring computer = computer_name_w();
    const std::wstring label = dns_label(pub.instance_name.empty() ? computer : utf8_to_wide(pub.instance_name));
    const std::wstring host = pub.host.empty()
        ? dns_label(computer) + L".local"
        : utf8_to_wide(pub.host);
    const std::wstring instance = label + L"." + utf8_to_wide(type) + L".local";

    std::vector<std::wstring> keys_owned;
    std::vector<std::wstring> values_owned;
    keys_owned.reserve(pub.txt.size());
    values_owned.reserve(pub.txt.size());
    std::vector<PCWSTR> keys;
    std::vector<PCWSTR> values;
    for (const auto& row : pub.txt) {
        if (row.first.empty())
            continue;
        keys_owned.push_back(utf8_to_wide(row.first));
        values_owned.push_back(utf8_to_wide(row.second));
    }
    keys.reserve(keys_owned.size());
    values.reserve(values_owned.size());
    for (size_t i = 0; i < keys_owned.size(); ++i) {
        keys.push_back(keys_owned[i].c_str());
        values.push_back(values_owned[i].c_str());
    }

    impl_->inst = DnsServiceConstructInstance(
        instance.c_str(), host.c_str(), nullptr, nullptr, static_cast<WORD>(pub.port), 0, 0,
        static_cast<DWORD>(keys.size()), keys.empty() ? nullptr : keys.data(),
        values.empty() ? nullptr : values.data());
    if (!impl_->inst) {
        err = "DnsServiceConstructInstance failed";
        return false;
    }
    ResetEvent(impl_->wait.event);
    impl_->wait.status = ERROR_IO_PENDING;
    std::memset(&impl_->req, 0, sizeof(impl_->req));
    impl_->req.Version = DNS_QUERY_REQUEST_VERSION1;
    impl_->req.InterfaceIndex = 0;
    impl_->req.pServiceInstance = impl_->inst;
    impl_->req.pRegisterCompletionCallback = complete;
    impl_->req.pQueryContext = &impl_->wait;
    impl_->req.unicastEnabled = FALSE;
    const DWORD rc = DnsServiceRegister(&impl_->req, nullptr);
    if (rc != ERROR_SUCCESS && rc != DNS_REQUEST_PENDING) {
        DnsServiceFreeInstance(impl_->inst);
        impl_->inst = nullptr;
        err = "DnsServiceRegister failed (" + std::to_string(rc) + ")";
        return false;
    }
    WaitForSingleObject(impl_->wait.event, 3000);
    if (impl_->wait.status != ERROR_SUCCESS) {
        DnsServiceFreeInstance(impl_->inst);
        impl_->inst = nullptr;
        err = "mDNS registration failed (" + std::to_string(impl_->wait.status) + ")";
        return false;
    }
    impl_->registered = true;
    return true;
}

void Publisher::stop()
{
    if (!impl_)
        return;
    if (!impl_->registered && !impl_->inst) {
        if (impl_->wait.event) {
            CloseHandle(impl_->wait.event);
            impl_->wait.event = nullptr;
        }
        return;
    }
    if (impl_->registered && impl_->wait.event) {
        ResetEvent(impl_->wait.event);
        impl_->wait.status = ERROR_IO_PENDING;
        DNS_SERVICE_REGISTER_REQUEST req = impl_->req;
        req.pRegisterCompletionCallback = complete;
        req.pQueryContext = &impl_->wait;
        DnsServiceDeRegister(&req, nullptr);
        WaitForSingleObject(impl_->wait.event, 2000);
    }
    if (impl_->inst) {
        DnsServiceFreeInstance(impl_->inst);
        impl_->inst = nullptr;
    }
    impl_->registered = false;
    if (impl_->wait.event) {
        CloseHandle(impl_->wait.event);
        impl_->wait.event = nullptr;
    }
}

bool bind_is_loopback(const std::string& host)
{
    return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]";
}

namespace {

std::string wide_to_utf8(const wchar_t* text)
{
    if (!text || !*text)
        return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1)
        return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), n, nullptr, nullptr);
    return out;
}

std::string txt_value(PDNS_SERVICE_INSTANCE inst, const wchar_t* key)
{
    if (!inst || !inst->keys || !inst->values || !key)
        return {};
    for (DWORD i = 0; i < inst->dwPropertyCount; ++i) {
        if (inst->keys[i] && _wcsicmp(inst->keys[i], key) == 0)
            return wide_to_utf8(inst->values[i]);
    }
    return {};
}

struct BrowseBox {
    std::mutex mu;
    std::vector<std::wstring> names;
    HANDLE event = nullptr;
};

std::wstring ptr_target(PDNS_RECORD it)
{
    if (!it || it->wType != DNS_TYPE_PTR)
        return {};
    // CharSet selects the wide or narrow record. The UNICODE macro only
    // changes which of those PDNS_RECORD names, so read the explicit type.
    if (it->Flags.S.CharSet == DnsCharSetUnicode) {
        const wchar_t* wide = reinterpret_cast<const DNS_RECORDW*>(it)->Data.PTR.pNameHost;
        return wide && wide[0] ? std::wstring(wide) : std::wstring{};
    }
    const char* narrow = reinterpret_cast<const DNS_RECORDA*>(it)->Data.PTR.pNameHost;
    if (!narrow || !narrow[0])
        return {};
    if (it->Flags.S.CharSet == DnsCharSetAnsi) {
        const int n = MultiByteToWideChar(CP_ACP, 0, narrow, -1, nullptr, 0);
        if (n <= 1)
            return {};
        std::wstring wide(static_cast<size_t>(n - 1), L'\0');
        MultiByteToWideChar(CP_ACP, 0, narrow, -1, wide.data(), n);
        return wide;
    }
    return utf8_to_wide(narrow);
}

void WINAPI on_browse(DWORD status, PVOID ctx, PDNS_RECORD rec)
{
    auto* box = static_cast<BrowseBox*>(ctx);
    if (!box)
        return;
    if (status == ERROR_SUCCESS) {
        std::lock_guard<std::mutex> lock(box->mu);
        for (PDNS_RECORD it = rec; it; it = it->pNext) {
            std::wstring name = ptr_target(it);
            if (!name.empty())
                box->names.push_back(std::move(name));
        }
    }
    if (status == ERROR_CANCELLED && box->event)
        SetEvent(box->event);
}

struct ResolveBox {
    HANDLE event = nullptr;
    DWORD status = ERROR_IO_PENDING;
    Sight sight;
};

void WINAPI on_resolve(DWORD status, PVOID ctx, PDNS_SERVICE_INSTANCE inst)
{
    auto* box = static_cast<ResolveBox*>(ctx);
    if (!box)
        return;
    box->status = status;
    if (status == ERROR_SUCCESS && inst) {
        box->sight.host = wide_to_utf8(inst->pszHostName);
        while (!box->sight.host.empty() && box->sight.host.back() == '.')
            box->sight.host.pop_back();
        box->sight.port = inst->wPort;
        box->sight.name = txt_value(inst, L"name");
        box->sight.role = txt_value(inst, L"role");
        if (box->sight.name.empty())
            box->sight.name = wide_to_utf8(inst->pszInstanceName);
        DnsServiceFreeInstance(inst);
    }
    if (box->event)
        SetEvent(box->event);
}

} // namespace

bool browse(const std::string& service_type, int wait_ms, std::vector<Sight>& out, std::string& err)
{
    out.clear();
    err.clear();
    const std::string type = service_type_clean(service_type);
    if (type.size() < 6 || type.front() != '_') {
        err = "mDNS service type is missing";
        return false;
    }
    const std::wstring query = utf8_to_wide(type) + L".local";
    BrowseBox box;
    box.event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!box.event) {
        err = "could not browse this network";
        return false;
    }
    DNS_SERVICE_BROWSE_REQUEST req{};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0;
    req.QueryName = query.c_str();
    req.pBrowseCallback = on_browse;
    req.pQueryContext = &box;
    DNS_SERVICE_CANCEL cancel{};
    const DWORD rc = DnsServiceBrowse(&req, &cancel);
    if (rc != ERROR_SUCCESS && rc != DNS_REQUEST_PENDING) {
        CloseHandle(box.event);
        err = "DnsServiceBrowse failed (" + std::to_string(rc) + ")";
        return false;
    }
    WaitForSingleObject(box.event, wait_ms > 0 ? static_cast<DWORD>(wait_ms) : 1200);
    DnsServiceBrowseCancel(&cancel);
    WaitForSingleObject(box.event, 500);
    CloseHandle(box.event);
    std::vector<std::wstring> names;
    {
        std::lock_guard<std::mutex> lock(box.mu);
        names.swap(box.names);
    }
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    if (names.size() > 8)
        names.resize(8);
    for (std::wstring name : names) {
        ResolveBox resolved;
        resolved.event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!resolved.event)
            continue;
        DNS_SERVICE_RESOLVE_REQUEST resolve{};
        resolve.Version = DNS_QUERY_REQUEST_VERSION1;
        resolve.InterfaceIndex = 0;
        resolve.QueryName = name.data();
        resolve.pResolveCompletionCallback = on_resolve;
        resolve.pQueryContext = &resolved;
        DNS_SERVICE_CANCEL resolve_cancel{};
        const DWORD rr = DnsServiceResolve(&resolve, &resolve_cancel);
        if (rr == ERROR_SUCCESS || rr == DNS_REQUEST_PENDING)
            WaitForSingleObject(resolved.event, 1500);
        DnsServiceResolveCancel(&resolve_cancel);
        WaitForSingleObject(resolved.event, 500);
        CloseHandle(resolved.event);
        if (resolved.status != ERROR_SUCCESS || resolved.sight.host.empty() || resolved.sight.port <= 0)
            continue;
        if (resolved.sight.role.empty())
            resolved.sight.role = "computer";
        out.push_back(std::move(resolved.sight));
    }
    return true;
}

} // namespace media_cli::mdns
