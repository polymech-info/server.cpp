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

#include <cstring>
#include <string>
#include <vector>

namespace media_cli::mdns {
namespace {

std::wstring utf8_to_wide(const std::string& s)
{
    if (s.empty())
        return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0)
        return {};
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

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

} // namespace media_cli::mdns
