// Phones connect to the TLS port. This proxy terminates TLS with the desktop
// identity and forwards bytes to the loopback HTTP server, injecting
// X-Tanit-Lan-Hop so a proxied phone is never treated as a local client.
// mDNS TXT records carry the name, port, and key fingerprint — never a secret.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include "json/json_utils.hpp"
#include "fs/path_sanitizer.hpp"
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <shellapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef SP_PROT_TLS1_3_SERVER
#define SP_PROT_TLS1_3_SERVER 0x1000
#endif

#include "lan/mesh_consent.hpp"
#include "lan/mesh_consent_ui_win.hpp"
#include "lan/pair_store.hpp"
#include "vfs/phone_peers.hpp"
#include "vfs/peer_dial.hpp"
#include "pm/node/sessions.hpp"
#include "lan/tanit_lan.hpp"
#include "lan/tanit_lan_qr.hpp"
#include "lan/tanit_mdns.hpp"

#include "core/settings_store.hpp"
#include "logging/logger.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "string/string_utils.hpp"

namespace media_cli::lan {
namespace {

namespace fs = std::filesystem;

// Not the CNG container TanitLanIdentity.v1. That name is an ECDSA key, and the
// legacy CSP opens it by the same name, then CertCreateSelfSignCertificate fails.
constexpr wchar_t k_key_container[] = L"TanitLanIdentity.rsa.v1";
constexpr int k_max_devices = 64;
constexpr int k_max_clients = 32;

bool ieq(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        unsigned char ca = static_cast<unsigned char>(a[i]);
        unsigned char cb = static_cast<unsigned char>(b[i]);
        if (ca >= 'A' && ca <= 'Z')
            ca = static_cast<unsigned char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = static_cast<unsigned char>(cb - 'A' + 'a');
        if (ca != cb)
            return false;
    }
    return true;
}

std::wstring utf8_to_wide(std::string_view s)
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

std::string wide_to_utf8(std::wstring_view w)
{
    if (w.empty())
        return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0,
                                      nullptr, nullptr);
    if (n <= 0)
        return {};
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::string b64url(const std::uint8_t* p, size_t n)
{
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string o;
    o.reserve((n + 2) / 3 * 4);
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = static_cast<unsigned>(p[i]) << 16;
        if (i + 1 < n)
            v |= static_cast<unsigned>(p[i + 1]) << 8;
        if (i + 2 < n)
            v |= p[i + 2];
        o.push_back(t[(v >> 18) & 63]);
        o.push_back(t[(v >> 12) & 63]);
        if (i + 1 < n)
            o.push_back(t[(v >> 6) & 63]);
        if (i + 2 < n)
            o.push_back(t[v & 63]);
    }
    return o;
}

std::string colon_fingerprint(const std::string& hex)
{
    std::string o;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        if (!o.empty())
            o.push_back(':');
        o.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(hex[i]))));
        o.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(hex[i + 1]))));
    }
    return o;
}

bool random_bytes(std::uint8_t* p, size_t n)
{
    return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, p, static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

bool sha256_hex(const std::uint8_t* p, size_t n, std::string& hex)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return false;
    std::uint8_t hash[32];
    const NTSTATUS st = BCryptHash(alg, nullptr, 0, const_cast<PUCHAR>(p), static_cast<ULONG>(n), hash, 32);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!BCRYPT_SUCCESS(st))
        return false;
    hex = media::strutil::to_hex(hash, 32);
    return true;
}

std::string iso_now()
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::string iso_after(int seconds)
{
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    u.QuadPart += static_cast<unsigned long long>(seconds) * 10000000ULL;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    SYSTEMTIME st{};
    FileTimeToSystemTime(&ft, &st);
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::string url_encode(std::string_view s)
{
    static const char* h = "0123456789ABCDEF";
    std::string o;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            o.push_back(static_cast<char>(c));
        else {
            o.push_back('%');
            o.push_back(h[c >> 4]);
            o.push_back(h[c & 0x0F]);
        }
    }
    return o;
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

std::string clean_text(std::string_view in, size_t maxn)
{
    std::string o;
    for (unsigned char c : in) {
        if (c < 0x20 || c == 0x7F)
            continue;
        o.push_back(static_cast<char>(c));
        if (o.size() >= maxn)
            break;
    }
    return media::strutil::trim(std::move(o));
}

bool pin_ok(const std::string& s)
{
    if (s.size() != 64)
        return false;
    for (unsigned char c : s) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
    }
    return true;
}

std::wstring key_container_for_process()
{
    const char* extra = std::getenv("TANIT_LAN_KEY_ID");
    if (!extra || !*extra)
        return k_key_container;
    std::wstring suffix;
    for (const char* p = extra; *p && suffix.size() < 32; ++p) {
        const unsigned char c = static_cast<unsigned char>(*p);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
            suffix.push_back(static_cast<wchar_t>(c));
    }
    if (suffix.empty())
        return k_key_container;
    return std::wstring(k_key_container) + L"." + suffix;
}

bool device_id_ok(const std::string& s)
{
    if (s.empty() || s.size() > 64)
        return false;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '.' || c == '_' || c == '-' || c == ':')
            continue;
        return false;
    }
    return true;
}

std::wstring computer_name_w()
{
    wchar_t buf[256];
    DWORD n = 256;
    if (!GetComputerNameW(buf, &n) || n == 0)
        return L"Tanit";
    return std::wstring(buf, n);
}

fs::path config_lan_dir(std::string& err)
{
    try {
        const fs::path dir = media::settings::get_config_dir() / "lan";
        std::error_code ec;
        fs::create_directories(dir, ec);
        if (ec) {
            err = "could not create the LAN config folder";
            return {};
        }
        return dir;
    } catch (const std::exception& ex) {
        err = ex.what();
        return {};
    }
}

bool write_text_file(const fs::path& path, const std::string& text, std::string& err)
{
    const fs::path tmp = path.wstring() + L".tmp";
    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            err = "could not write " + wide_to_utf8(path.wstring());
            return false;
        }
        ofs.write(text.data(), static_cast<std::streamsize>(text.size()));
        if (!ofs) {
            err = "could not write " + wide_to_utf8(path.wstring());
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        fs::remove(path, ec);
        fs::rename(tmp, path, ec);
    }
    if (ec) {
        err = "could not replace " + wide_to_utf8(path.wstring());
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

bool read_text_file(const fs::path& path, std::string& text)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs)
        return false;
    text.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    return true;
}

// One pass over a ticket-scope file. A bad id or an unknown scope leaves the
// file untouched. After this returns, the file is version 2 and this parser
// is not used again.
bool import_ticket_file(const fs::path& path, std::string& err)
{
    err.clear();
    std::string text;
    if (!read_text_file(path, text)) {
        err = "could not read paired devices";
        return false;
    }
    const nlohmann::json j = media::json::try_parse(text);
    if (!j.is_object() || !j.contains("devices") || !j["devices"].is_array()) {
        err = "paired devices file is not valid JSON";
        return false;
    }
    const std::string identity = j.value("identity", std::string{});
    std::vector<pm::lan::Peer> peers;
    for (const auto& item : j["devices"]) {
        if (!item.is_object()) {
            err = "paired devices file is not valid JSON";
            return false;
        }
        pm::lan::Peer peer;
        peer.id = item.value("id", std::string{});
        if (!pm::lan::peer_id_valid(peer.id)) {
            err = "paired devices file has a device id that is not valid";
            return false;
        }
        peer.name = item.value("name", std::string{});
        peer.token_sha256 = item.value("token_sha256", std::string{});
        if (peer.token_sha256.size() != 64) {
            err = "paired devices file is not valid JSON";
            return false;
        }
        peer.created = item.value("created", std::string{});
        peer.last_seen = item.value("last_seen", std::string{});
        peer.trust = item.value("revoked", false) ? pm::lan::Trust::Revoked : pm::lan::Trust::Paired;
        if (item.contains("scopes")) {
            if (!item["scopes"].is_array()) {
                err = "paired devices file has a scope that is not valid";
                return false;
            }
            for (const auto& scope : item["scopes"]) {
                if (!scope.is_string() ||
                    !pm::lan::grant_set_scope(peer.allow_peer, scope.get<std::string>())) {
                    err = "paired devices file has a scope that is not valid";
                    return false;
                }
            }
        }
        peers.push_back(std::move(peer));
    }
    if (peers.size() > static_cast<std::size_t>(k_max_devices)) {
        err = "too many paired devices";
        return false;
    }
    return pm::lan::PairStore(path, static_cast<std::size_t>(k_max_devices)).write(identity, peers, err);
}

struct AdapterIp {
    std::string text;
    unsigned char bytes[4]{};
    int rank = 5;
};

int ip_rank(const unsigned char b[4])
{
    if (b[0] == 192 && b[1] == 168)
        return 0;
    if (b[0] == 10)
        return 1;
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
        return 2;
    if (b[0] == 169 && b[1] == 254)
        return 9;
    return 5;
}

std::vector<AdapterIp> lan_ipv4()
{
    std::vector<AdapterIp> found;
    ULONG bytes = 16 * 1024;
    std::vector<unsigned char> buf(bytes);
    auto* list = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG rc = GetAdaptersAddresses(AF_INET, flags, nullptr, list, &bytes);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bytes);
        list = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
        rc = GetAdaptersAddresses(AF_INET, flags, nullptr, list, &bytes);
    }
    if (rc != NO_ERROR)
        return found;
    for (auto* a = list; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp)
            continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET)
                continue;
            auto* sin = reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr);
            AdapterIp ip;
            std::memcpy(ip.bytes, &sin->sin_addr, 4);
            if (ip.bytes[0] == 127)
                continue;
            char text[64];
            if (!inet_ntop(AF_INET, &sin->sin_addr, text, sizeof(text)))
                continue;
            ip.text = text;
            ip.rank = ip_rank(ip.bytes);
            found.push_back(ip);
        }
    }
    std::sort(found.begin(), found.end(), [](const AdapterIp& a, const AdapterIp& b) {
        if (a.rank != b.rank)
            return a.rank < b.rank;
        return a.text < b.text;
    });
    const bool has_real = std::any_of(found.begin(), found.end(), [](const AdapterIp& ip) {
        return ip.rank < 9;
    });
    if (has_real) {
        found.erase(std::remove_if(found.begin(), found.end(),
                                   [](const AdapterIp& ip) { return ip.rank >= 9; }),
                    found.end());
    }
    if (found.size() > 8)
        found.resize(8);
    return found;
}

bool send_all(SOCKET s, const char* data, size_t n)
{
    while (n > 0) {
        const int chunk = static_cast<int>(std::min(n, static_cast<size_t>(1 << 20)));
        const int w = send(s, data, chunk, 0);
        if (w <= 0)
            return false;
        data += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

bool connect_upstream(const std::string& host, int port, SOCKET& out, std::string& err)
{
    out = INVALID_SOCKET;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    const std::string port_s = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0 || !res) {
        err = "could not resolve the local HTTP listener";
        return false;
    }
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        err = "could not open a socket to the HTTP listener";
        return false;
    }
    BOOL nodelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&nodelay), sizeof(nodelay));
    if (connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
        closesocket(s);
        freeaddrinfo(res);
        err = "HTTP listener is not accepting";
        return false;
    }
    freeaddrinfo(res);
    out = s;
    return true;
}

class RequestForwarder {
public:
    RequestForwarder(std::string hop, std::string peer)
        : hop_(std::move(hop)), peer_(std::move(peer))
    {
    }

    bool take(const char* data, size_t n, std::string& upstream)
    {
        buf_.append(data, n);
        if (buf_.size() > (2u << 20))
            return false;
        for (;;) {
            if (phase_ == 0) {
                const auto end = buf_.find("\r\n\r\n");
                if (end == std::string::npos)
                    return buf_.size() <= 65536;
                const std::string head = buf_.substr(0, end);
                buf_.erase(0, end + 4);
                std::string rewritten;
                if (!rewrite(head, rewritten) || !begin_body(head))
                    return false;
                upstream += rewritten;
                upstream += "\r\n";
            } else if (phase_ == 1) {
                const size_t ntake = std::min(buf_.size(), remain_);
                upstream.append(buf_, 0, ntake);
                buf_.erase(0, ntake);
                remain_ -= ntake;
                if (remain_ == 0)
                    phase_ = 0;
                else
                    return true;
            } else if (phase_ == 2) {
                const auto end = buf_.find("\r\n");
                if (end == std::string::npos)
                    return buf_.size() <= 256;
                size_t sz = 0;
                for (size_t i = 0; i < end; ++i) {
                    const char c = buf_[i];
                    if (c == ';')
                        break;
                    int v = -1;
                    if (c >= '0' && c <= '9')
                        v = c - '0';
                    else if (c >= 'a' && c <= 'f')
                        v = c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F')
                        v = c - 'A' + 10;
                    else
                        return false;
                    sz = (sz << 4) + static_cast<size_t>(v);
                }
                upstream.append(buf_, 0, end + 2);
                buf_.erase(0, end + 2);
                chunk_left_ = sz;
                phase_ = sz == 0 ? 5 : 3;
            } else if (phase_ == 3) {
                const size_t ntake = std::min(buf_.size(), chunk_left_);
                upstream.append(buf_, 0, ntake);
                buf_.erase(0, ntake);
                chunk_left_ -= ntake;
                if (chunk_left_ == 0)
                    phase_ = 4;
                else
                    return true;
            } else if (phase_ == 4) {
                if (buf_.size() < 2)
                    return true;
                if (buf_[0] != '\r' || buf_[1] != '\n')
                    return false;
                upstream += "\r\n";
                buf_.erase(0, 2);
                phase_ = 2;
            } else {
                const auto end = buf_.find("\r\n");
                if (end == std::string::npos)
                    return buf_.size() <= 8192;
                upstream.append(buf_, 0, end + 2);
                const bool blank = end == 0;
                buf_.erase(0, end + 2);
                if (blank)
                    phase_ = 0;
            }
        }
    }

private:
    bool rewrite(const std::string& head, std::string& out) const
    {
        size_t pos = 0;
        bool first = true;
        out.clear();
        while (pos < head.size()) {
            auto eol = head.find("\r\n", pos);
            if (eol == std::string::npos)
                eol = head.size();
            const std::string line = head.substr(pos, eol - pos);
            pos = std::min(head.size(), eol + 2);
            if (first) {
                if (line.empty())
                    return false;
                out += line;
                out += "\r\n";
                out += "X-Tanit-Lan-Hop: ";
                out += hop_;
                out += "\r\nX-Tanit-Lan-Peer: ";
                out += peer_;
                out += "\r\n";
                first = false;
                continue;
            }
            const auto colon = line.find(':');
            if (colon == std::string::npos)
                continue;
            const std::string name = line.substr(0, colon);
            if (ieq(name, k_hop_header) || ieq(name, k_peer_header))
                continue;
            out += line;
            out += "\r\n";
        }
        return !first;
    }

    bool begin_body(const std::string& head)
    {
        const auto line_end = head.find("\r\n");
        const std::string req = line_end == std::string::npos ? head : head.substr(0, line_end);
        const auto sp = req.find(' ');
        const std::string method = sp == std::string::npos ? req : req.substr(0, sp);
        bool has_len = false;
        bool chunked = false;
        size_t len = 0;
        size_t pos = line_end == std::string::npos ? head.size() : line_end + 2;
        while (pos < head.size()) {
            auto eol = head.find("\r\n", pos);
            if (eol == std::string::npos)
                eol = head.size();
            const std::string line = head.substr(pos, eol - pos);
            pos = std::min(head.size(), eol + 2);
            const auto colon = line.find(':');
            if (colon == std::string::npos)
                continue;
            const std::string name = media::strutil::trim(line.substr(0, colon));
            const std::string value = media::strutil::trim(line.substr(colon + 1));
            if (ieq(name, "Content-Length")) {
                has_len = true;
                try {
                    len = static_cast<size_t>(std::stoull(value));
                } catch (...) {
                    return false;
                }
            } else if (ieq(name, "Transfer-Encoding")) {
                std::string lower = value;
                lower = media::strutil::lower_ascii(std::move(lower));
                if (lower.find("chunked") != std::string::npos)
                    chunked = true;
            }
        }
        if (has_len && chunked)
            return false;
        if (chunked) {
            phase_ = 2;
            return true;
        }
        if (has_len) {
            remain_ = len;
            phase_ = len == 0 ? 0 : 1;
            return true;
        }
        if (ieq(method, "POST") || ieq(method, "PUT") || ieq(method, "PATCH"))
            return false;
        phase_ = 0;
        return true;
    }

    std::string hop_;
    std::string peer_;
    std::string buf_;
    int phase_ = 0;
    size_t remain_ = 0;
    size_t chunk_left_ = 0;
};

struct TlsServer {
    CredHandle cred{};
    bool have_cred = false;
    SecPkgContext_StreamSizes sizes{};
};

bool tls_send(TlsServer& tls, CtxtHandle& ctx, std::mutex& schannel_mu, SOCKET sock, const char* data,
              size_t n)
{
    size_t off = 0;
    while (off < n) {
        const size_t chunk = std::min(n - off, static_cast<size_t>(tls.sizes.cbMaximumMessage));
        std::vector<char> buf(tls.sizes.cbHeader + chunk + tls.sizes.cbTrailer);
        std::memcpy(buf.data() + tls.sizes.cbHeader, data + off, chunk);
        SecBuffer bufs[4];
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].cbBuffer = tls.sizes.cbHeader;
        bufs[0].pvBuffer = buf.data();
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].cbBuffer = static_cast<ULONG>(chunk);
        bufs[1].pvBuffer = buf.data() + tls.sizes.cbHeader;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].cbBuffer = tls.sizes.cbTrailer;
        bufs[2].pvBuffer = buf.data() + tls.sizes.cbHeader + chunk;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        bufs[3].cbBuffer = 0;
        bufs[3].pvBuffer = nullptr;
        SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};
        SECURITY_STATUS st;
        {
            std::lock_guard lock(schannel_mu);
            st = EncryptMessage(&ctx, 0, &desc, 0);
        }
        if (st != SEC_E_OK)
            return false;
        const size_t total = static_cast<size_t>(bufs[0].cbBuffer) + bufs[1].cbBuffer + bufs[2].cbBuffer;
        if (!send_all(sock, buf.data(), total))
            return false;
        off += chunk;
    }
    return true;
}

bool tls_handshake(TlsServer& tls, CtxtHandle& ctx, SOCKET sock, std::vector<char>& extra)
{
    std::vector<char> incoming;
    bool have_ctx = false;
    extra.clear();
    SecInvalidateHandle(&ctx);
    auto fail = [&]() {
        if (have_ctx)
            DeleteSecurityContext(&ctx);
        have_ctx = false;
        return false;
    };
    while (incoming.size() < (64u << 10)) {
        char tmp[8192];
        const int n = recv(sock, tmp, sizeof(tmp), 0);
        if (n <= 0)
            return fail();
        incoming.insert(incoming.end(), tmp, tmp + n);
        for (;;) {
            SecBuffer in_bufs[2];
            in_bufs[0].BufferType = SECBUFFER_TOKEN;
            in_bufs[0].pvBuffer = incoming.data();
            in_bufs[0].cbBuffer = static_cast<ULONG>(incoming.size());
            in_bufs[1].BufferType = SECBUFFER_EMPTY;
            in_bufs[1].pvBuffer = nullptr;
            in_bufs[1].cbBuffer = 0;
            SecBufferDesc in_desc{SECBUFFER_VERSION, 2, in_bufs};
            SecBuffer out_bufs[1];
            out_bufs[0].BufferType = SECBUFFER_TOKEN;
            out_bufs[0].pvBuffer = nullptr;
            out_bufs[0].cbBuffer = 0;
            SecBufferDesc out_desc{SECBUFFER_VERSION, 1, out_bufs};
            ULONG attrs = 0;
            const SECURITY_STATUS st = AcceptSecurityContext(
                &tls.cred, have_ctx ? &ctx : nullptr, &in_desc,
                ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM | ASC_REQ_CONFIDENTIALITY | ASC_REQ_REPLAY_DETECT
                    | ASC_REQ_SEQUENCE_DETECT,
                SECURITY_NATIVE_DREP, &ctx, &out_desc, &attrs, nullptr);
            if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED || st == SEC_I_COMPLETE_NEEDED
                || st == SEC_I_COMPLETE_AND_CONTINUE)
                have_ctx = true;
            if (out_bufs[0].cbBuffer && out_bufs[0].pvBuffer) {
                const bool sent = send_all(sock, static_cast<char*>(out_bufs[0].pvBuffer), out_bufs[0].cbBuffer);
                FreeContextBuffer(out_bufs[0].pvBuffer);
                if (!sent)
                    return fail();
            }
            if (st == SEC_E_INCOMPLETE_MESSAGE)
                break;
            if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED && st != SEC_I_COMPLETE_NEEDED
                && st != SEC_I_COMPLETE_AND_CONTINUE)
                return fail();
            if (st == SEC_I_COMPLETE_NEEDED || st == SEC_I_COMPLETE_AND_CONTINUE)
                CompleteAuthToken(&ctx, &out_desc);
            std::vector<char> rest;
            if (in_bufs[1].BufferType == SECBUFFER_EXTRA && in_bufs[1].cbBuffer && in_bufs[1].pvBuffer)
                rest.assign(static_cast<char*>(in_bufs[1].pvBuffer),
                            static_cast<char*>(in_bufs[1].pvBuffer) + in_bufs[1].cbBuffer);
            incoming.swap(rest);
            if (st == SEC_E_OK || st == SEC_I_COMPLETE_NEEDED) {
                extra.swap(incoming);
                if (QueryContextAttributes(&ctx, SECPKG_ATTR_STREAM_SIZES, &tls.sizes) != SEC_E_OK
                    || tls.sizes.cbMaximumMessage == 0)
                    return fail();
                return true;
            }
            if (incoming.empty())
                break;
        }
    }
    return fail();
}

} // namespace

struct ClientSlot {
    SOCKET sock = INVALID_SOCKET;
    std::thread thr;
    std::atomic<bool> done{false};
};

struct LanServiceImpl {
    mutable std::mutex mu;
    bool prepared = false;
    bool listening = false;
    std::atomic<bool> stopping{false};

    std::string name;
    /// Stable label. Written once into identity.json. Not the fingerprint.
    std::string device_id;
    std::wstring key_container;
    std::string fingerprint;
    std::string fingerprint_colon;
    std::string mdns_host;
    std::vector<std::string> addresses;
    std::vector<AdapterIp> ips;
    int tls_port = 0;
    int http_port = 0;
    std::string upstream_host;
    std::string hop;
    bool mdns_ok = false;

    PCCERT_CONTEXT cert = nullptr;
    HCERTSTORE store = nullptr;
    // Legacy RSA CSP. Schannel rejects CNG self-signed certs here (SEC_E_UNKNOWN_CREDENTIALS).
    HCRYPTPROV csp = 0;
    CredHandle cred{};
    bool have_cred = false;

    media_cli::mdns::Publisher mdns;

    struct Ticket {
        bool open = false;
        std::string secret;
        std::vector<std::string> scopes;
        std::chrono::steady_clock::time_point expires{};
        int failures = 0;
        std::chrono::steady_clock::time_point locked_until{};
    } ticket;

    std::vector<pm::lan::Peer> devices;
    fs::file_time_type devices_mtime{};
    bool devices_loaded = false;
    std::chrono::steady_clock::time_point devices_saved{};
    fs::path devices_path;
    fs::path identity_path;
    std::string qr_image;

    SOCKET listen_sock = INVALID_SOCKET;
    std::thread accept_thread;
    std::mutex slots_mu;
    std::vector<std::unique_ptr<ClientSlot>> slots;
};

namespace {

bool ensure_winsock(std::string& err)
{
    WSADATA data{};
    const int rc = WSAStartup(MAKEWORD(2, 2), &data);
    if (rc != 0) {
        err = "WSAStartup failed";
        return false;
    }
    return true;
}

void free_cert(LanServiceImpl& impl)
{
    if (impl.have_cred) {
        FreeCredentialsHandle(&impl.cred);
        impl.have_cred = false;
    }
    if (impl.cert) {
        CertFreeCertificateContext(impl.cert);
        impl.cert = nullptr;
    }
    if (impl.store) {
        CertCloseStore(impl.store, 0);
        impl.store = nullptr;
    }
    if (impl.csp) {
        CryptReleaseContext(impl.csp, 0);
        impl.csp = 0;
    }
}

bool open_or_create_key(LanServiceImpl& impl, bool& is_rsa, std::string& err)
{
    is_rsa = true;
    if (CryptAcquireContextW(&impl.csp, impl.key_container.c_str(), MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, 0))
        return true;
    const DWORD open_err = GetLastError();
    if (open_err != NTE_BAD_KEYSET) {
        err = "could not open the LAN identity key (" + std::to_string(open_err) + ")";
        return false;
    }
    if (!CryptAcquireContextW(&impl.csp, impl.key_container.c_str(), MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES,
                              CRYPT_NEWKEYSET)) {
        err = "could not create the LAN identity key (" + std::to_string(GetLastError()) + ")";
        return false;
    }
    HCRYPTKEY generated = 0;
    if (!CryptGenKey(impl.csp, AT_KEYEXCHANGE, (2048u << 16) | CRYPT_EXPORTABLE, &generated)) {
        err = "could not generate the LAN identity key (" + std::to_string(GetLastError()) + ")";
        return false;
    }
    CryptDestroyKey(generated);
    return true;
}

bool encode_extension(LPCSTR struct_type, const void* data, std::vector<unsigned char>& out)
{
    DWORD cb = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, struct_type, data, 0, nullptr, nullptr, &cb) || cb == 0)
        return false;
    out.resize(cb);
    return CryptEncodeObjectEx(X509_ASN_ENCODING, struct_type, data, 0, nullptr, out.data(), &cb) == TRUE;
}

bool make_certificate(LanServiceImpl& impl, bool is_rsa, std::string& err)
{
    DWORD name_cb = 0;
    const wchar_t* dn = L"CN=Tanit LAN";
    if (!CertStrToNameW(X509_ASN_ENCODING, dn, CERT_X500_NAME_STR, nullptr, nullptr, &name_cb, nullptr)
        || name_cb == 0) {
        err = "could not encode the LAN certificate name";
        return false;
    }
    std::vector<BYTE> name(name_cb);
    if (!CertStrToNameW(X509_ASN_ENCODING, dn, CERT_X500_NAME_STR, nullptr, name.data(), &name_cb, nullptr)) {
        err = "could not encode the LAN certificate name";
        return false;
    }
    CERT_NAME_BLOB subject{name_cb, name.data()};

    CRYPT_KEY_PROV_INFO kpi{};
    kpi.pwszContainerName = const_cast<LPWSTR>(impl.key_container.c_str());
    kpi.pwszProvName = const_cast<LPWSTR>(MS_ENH_RSA_AES_PROV_W);
    kpi.dwProvType = PROV_RSA_AES;
    kpi.dwKeySpec = AT_KEYEXCHANGE;

    CRYPT_ALGORITHM_IDENTIFIER sig{};
    sig.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);
    (void)is_rsa;

    SYSTEMTIME start{};
    GetSystemTime(&start);
    FILETIME ft{};
    SystemTimeToFileTime(&start, &ft);
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    u.QuadPart -= 24ULL * 60 * 60 * 10000000ULL;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    FileTimeToSystemTime(&ft, &start);
    SYSTEMTIME end = start;
    end.wYear = static_cast<WORD>(end.wYear + 10);

    std::wstring dns = utf8_to_wide(impl.mdns_host);
    std::vector<CERT_ALT_NAME_ENTRY> alts(1u + impl.ips.size());
    std::memset(alts.data(), 0, alts.size() * sizeof(CERT_ALT_NAME_ENTRY));
    DWORD alt_n = 0;
    if (!dns.empty()) {
        alts[alt_n].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
        alts[alt_n].pwszDNSName = dns.data();
        ++alt_n;
    }
    for (auto& ip : impl.ips) {
        alts[alt_n].dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
        alts[alt_n].IPAddress.cbData = 4;
        alts[alt_n].IPAddress.pbData = ip.bytes;
        ++alt_n;
    }
    CERT_ALT_NAME_INFO san_info{alt_n, alts.data()};
    std::vector<unsigned char> san_der;
    std::vector<unsigned char> ku_der;
    std::vector<unsigned char> eku_der;
    BYTE ku_byte = CERT_DIGITAL_SIGNATURE_KEY_USAGE;
    if (is_rsa)
        ku_byte = static_cast<BYTE>(ku_byte | CERT_KEY_ENCIPHERMENT_KEY_USAGE);
    CRYPT_BIT_BLOB ku_blob{};
    ku_blob.cbData = 1;
    ku_blob.pbData = &ku_byte;
    LPSTR server_auth = const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH);
    CERT_ENHKEY_USAGE eku{};
    eku.cUsageIdentifier = 1;
    eku.rgpszUsageIdentifier = &server_auth;

    std::vector<CERT_EXTENSION> exts;
    if (alt_n > 0 && encode_extension(szOID_SUBJECT_ALT_NAME2, &san_info, san_der)) {
        CERT_EXTENSION ext{};
        ext.pszObjId = const_cast<LPSTR>(szOID_SUBJECT_ALT_NAME2);
        ext.fCritical = FALSE;
        ext.Value.cbData = static_cast<DWORD>(san_der.size());
        ext.Value.pbData = san_der.data();
        exts.push_back(ext);
    }
    if (encode_extension(X509_KEY_USAGE, &ku_blob, ku_der)) {
        CERT_EXTENSION ext{};
        ext.pszObjId = const_cast<LPSTR>(szOID_KEY_USAGE);
        ext.fCritical = FALSE;
        ext.Value.cbData = static_cast<DWORD>(ku_der.size());
        ext.Value.pbData = ku_der.data();
        exts.push_back(ext);
    }
    if (encode_extension(X509_ENHANCED_KEY_USAGE, &eku, eku_der)) {
        CERT_EXTENSION ext{};
        ext.pszObjId = const_cast<LPSTR>(szOID_ENHANCED_KEY_USAGE);
        ext.fCritical = FALSE;
        ext.Value.cbData = static_cast<DWORD>(eku_der.size());
        ext.Value.pbData = eku_der.data();
        exts.push_back(ext);
    }
    CERT_EXTENSIONS extensions{static_cast<DWORD>(exts.size()), exts.empty() ? nullptr : exts.data()};

    PCCERT_CONTEXT created = CertCreateSelfSignCertificate(
        impl.csp, &subject, 0, &kpi, &sig, &start, &end,
        exts.empty() ? nullptr : &extensions);
    if (!created) {
        err = "could not create the LAN certificate (" + std::to_string(GetLastError()) + ")";
        return false;
    }
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE acquired = 0;
    DWORD spec = 0;
    BOOL caller_free = FALSE;
    const BOOL key_ok = CryptAcquireCertificatePrivateKey(
        created, CRYPT_ACQUIRE_SILENT_FLAG, nullptr, &acquired, &spec, &caller_free);
    if (caller_free && acquired) {
        if (spec == CERT_NCRYPT_KEY_SPEC)
            NCryptFreeObject(static_cast<NCRYPT_KEY_HANDLE>(acquired));
        else
            CryptReleaseContext(static_cast<HCRYPTPROV>(acquired), 0);
    }
    if (!key_ok) {
        CertFreeCertificateContext(created);
        err = "LAN certificate is not tied to its private key";
        return false;
    }

    BYTE hash[32];
    DWORD hash_cb = sizeof(hash);
    if (!CryptHashPublicKeyInfo(0, CALG_SHA_256, 0, X509_ASN_ENCODING, &created->pCertInfo->SubjectPublicKeyInfo,
                                hash, &hash_cb)) {
        CertFreeCertificateContext(created);
        err = "could not hash the LAN public key";
        return false;
    }
    impl.fingerprint = media::strutil::to_hex(hash, hash_cb);
    impl.fingerprint_colon = colon_fingerprint(impl.fingerprint);

    impl.store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    if (!impl.store) {
        CertFreeCertificateContext(created);
        err = "could not open a certificate store";
        return false;
    }
    PCCERT_CONTEXT stored = nullptr;
    if (!CertAddCertificateContextToStore(impl.store, created, CERT_STORE_ADD_ALWAYS, &stored)) {
        CertFreeCertificateContext(created);
        err = "could not store the LAN certificate";
        return false;
    }
    CertFreeCertificateContext(created);
    impl.cert = stored;
    return true;
}

bool acquire_tls_cred(LanServiceImpl& impl, std::string& err)
{
    SECURITY_STATUS last = SEC_E_INTERNAL_ERROR;
    auto try_acquire = [&](DWORD protocols) {
#pragma warning(push)
#pragma warning(disable : 4996)
        SCHANNEL_CRED cred{};
        cred.dwVersion = SCHANNEL_CRED_VERSION;
        cred.cCreds = 1;
        cred.paCred = &impl.cert;
        cred.grbitEnabledProtocols = protocols;
        // The cert lives only in the memory store. Without this flag Schannel
        // looks for it in MY and returns SEC_E_UNKNOWN_CREDENTIALS.
        cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO | SCH_CRED_MEMORY_STORE_CERT;
        last = AcquireCredentialsHandleW(
            nullptr, const_cast<LPWSTR>(UNISP_NAME_W), SECPKG_CRED_INBOUND, nullptr, &cred, nullptr, nullptr,
            &impl.cred, nullptr);
#pragma warning(pop)
        return last == SEC_E_OK;
    };
    if (!try_acquire(SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER)
        && !try_acquire(SP_PROT_TLS1_2_SERVER)) {
        err = "could not start TLS with the LAN certificate (" + std::to_string(static_cast<unsigned long>(last))
              + ")";
        return false;
    }
    impl.have_cred = true;
    return true;
}

void delete_qr_image(LanServiceImpl& impl)
{
    if (impl.qr_image.empty())
        return;
    std::error_code ec;
    fs::remove(fs::path(utf8_to_wide(impl.qr_image)), ec);
    impl.qr_image.clear();
}

bool reload_devices_unlocked(LanServiceImpl& impl, std::string& err)
{
    std::error_code ec;
    const bool exists = fs::is_regular_file(impl.devices_path, ec);
    fs::file_time_type mtime{};
    if (exists)
        mtime = fs::last_write_time(impl.devices_path, ec);
    if (impl.devices_loaded && (!exists || (!ec && mtime == impl.devices_mtime)))
        return true;
    pm::lan::PairStore store(impl.devices_path, static_cast<std::size_t>(k_max_devices));
    std::string identity;
    std::vector<pm::lan::Peer> peers;
    if (!store.load_identity(identity, peers, err)) {
        if (err != "pair file uses ticket scopes" || !import_ticket_file(impl.devices_path, err) ||
            !store.load_identity(identity, peers, err))
            return false;
    }
    if (!identity.empty() && identity != impl.fingerprint) {
        logger::warn("lan identity changed; revoking paired phones");
        for (auto& peer : peers) {
            peer.trust = pm::lan::Trust::Revoked;
            pm::lan::grant_clear(peer.allow_peer);
        }
        if (!store.write(impl.fingerprint, peers, err))
            return false;
        for (const auto& peer : peers)
            pm::node::sessions_cancel(peer.id, "");
        mtime = fs::last_write_time(impl.devices_path, ec);
    } else if (identity.empty() && exists) {
        if (!store.write(impl.fingerprint, peers, err))
            return false;
        mtime = fs::last_write_time(impl.devices_path, ec);
    }
    impl.devices = std::move(peers);
    impl.devices_mtime = mtime;
    impl.devices_loaded = true;
    impl.devices_saved = std::chrono::steady_clock::now();
    return true;
}

bool store_devices_unlocked(LanServiceImpl& impl, std::string& err)
{
    pm::lan::PairStore store(impl.devices_path, static_cast<std::size_t>(k_max_devices));
    if (!store.write(impl.fingerprint, impl.devices, err))
        return false;
    std::error_code ec;
    impl.devices_mtime = fs::last_write_time(impl.devices_path, ec);
    impl.devices_loaded = true;
    impl.devices_saved = std::chrono::steady_clock::now();
    return true;
}

std::vector<std::string> scope_intersection(const std::vector<std::string>& granted,
                                            const std::vector<std::string>& requested)
{
    if (requested.empty())
        return granted;
    std::vector<std::string> out;
    for (const auto& s : granted) {
        for (const auto& r : requested) {
            if (s == r) {
                out.push_back(s);
                break;
            }
        }
    }
    return out;
}

void reap_slots(LanServiceImpl& impl)
{
    std::lock_guard lock(impl.slots_mu);
    std::vector<std::unique_ptr<ClientSlot>> keep;
    for (auto& slot : impl.slots) {
        if (slot->done.load()) {
            if (slot->thr.joinable())
                slot->thr.join();
        } else {
            keep.push_back(std::move(slot));
        }
    }
    impl.slots.swap(keep);
}

void handle_client(LanServiceImpl* impl, SOCKET client, std::string peer)
{
    BOOL nodelay = TRUE;
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&nodelay), sizeof(nodelay));
    CtxtHandle ctx{};
    std::mutex schannel_mu;
    std::vector<char> extra;
    TlsServer tls;
    tls.cred = impl->cred;
    tls.have_cred = impl->have_cred;
    if (!tls_handshake(tls, ctx, client, extra))
        return;

    SOCKET upstream = INVALID_SOCKET;
    std::string connect_err;
    if (!connect_upstream(impl->upstream_host, impl->http_port, upstream, connect_err)) {
        logger::warn(std::string("lan tls: ") + connect_err);
        DeleteSecurityContext(&ctx);
        return;
    }

    RequestForwarder forwarder(impl->hop, peer);
    std::thread writer([&] {
        char buf[8192];
        while (!impl->stopping.load()) {
            const int n = recv(upstream, buf, sizeof(buf), 0);
            if (n <= 0)
                break;
            if (!tls_send(tls, ctx, schannel_mu, client, buf, static_cast<size_t>(n)))
                break;
        }
        shutdown(client, SD_BOTH);
    });

    std::vector<char> incoming = std::move(extra);
    auto pump_plain = [&](const char* p, size_t n) -> bool {
        std::string out;
        if (!forwarder.take(p, n, out))
            return false;
        return out.empty() || send_all(upstream, out.data(), out.size());
    };

    bool ok = true;
    while (ok && !impl->stopping.load()) {
        if (incoming.empty()) {
            char tmp[8192];
            const int n = recv(client, tmp, sizeof(tmp), 0);
            if (n <= 0)
                break;
            incoming.assign(tmp, tmp + n);
        }
        bool need_more = false;
        while (ok && !incoming.empty() && !need_more) {
            SecBuffer bufs[4];
            bufs[0].BufferType = SECBUFFER_DATA;
            bufs[0].pvBuffer = incoming.data();
            bufs[0].cbBuffer = static_cast<ULONG>(incoming.size());
            for (int i = 1; i < 4; ++i) {
                bufs[i].BufferType = SECBUFFER_EMPTY;
                bufs[i].pvBuffer = nullptr;
                bufs[i].cbBuffer = 0;
            }
            SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};
            SECURITY_STATUS st;
            {
                std::lock_guard lock(schannel_mu);
                st = DecryptMessage(&ctx, &desc, 0, nullptr);
            }
            if (st == SEC_E_INCOMPLETE_MESSAGE) {
                need_more = true;
                break;
            }
            if (st == SEC_I_CONTEXT_EXPIRED || st == SEC_I_RENEGOTIATE || st != SEC_E_OK) {
                ok = st == SEC_I_CONTEXT_EXPIRED;
                incoming.clear();
                break;
            }
            std::vector<char> plain;
            std::vector<char> rest;
            for (int i = 0; i < 4; ++i) {
                if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].pvBuffer && bufs[i].cbBuffer) {
                    plain.assign(static_cast<char*>(bufs[i].pvBuffer),
                                 static_cast<char*>(bufs[i].pvBuffer) + bufs[i].cbBuffer);
                } else if (bufs[i].BufferType == SECBUFFER_EXTRA && bufs[i].pvBuffer && bufs[i].cbBuffer) {
                    rest.assign(static_cast<char*>(bufs[i].pvBuffer),
                                static_cast<char*>(bufs[i].pvBuffer) + bufs[i].cbBuffer);
                }
            }
            incoming.swap(rest);
            if (!plain.empty() && !pump_plain(plain.data(), plain.size()))
                ok = false;
        }
        if (!ok)
            break;
        if (need_more) {
            char tmp[8192];
            const int n = recv(client, tmp, sizeof(tmp), 0);
            if (n <= 0)
                break;
            incoming.insert(incoming.end(), tmp, tmp + n);
            if (incoming.size() > (256u << 10))
                break;
        }
    }
    shutdown(upstream, SD_BOTH);
    shutdown(client, SD_BOTH);
    if (writer.joinable())
        writer.join();
    closesocket(upstream);
    DeleteSecurityContext(&ctx);
}

void accept_loop(LanServiceImpl* impl)
{
    while (!impl->stopping.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        if (impl->listen_sock == INVALID_SOCKET)
            break;
        FD_SET(impl->listen_sock, &fds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        const int sel = select(0, &fds, nullptr, nullptr, &tv);
        if (impl->stopping.load())
            break;
        if (sel <= 0)
            continue;
        sockaddr_in peer{};
        int peer_len = sizeof(peer);
        const SOCKET client = accept(impl->listen_sock, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (client == INVALID_SOCKET)
            continue;
        char ip[64] = "0.0.0.0";
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        reap_slots(*impl);
        std::lock_guard lock(impl->slots_mu);
        if (impl->stopping.load()) {
            closesocket(client);
            break;
        }
        int live = 0;
        for (const auto& slot : impl->slots)
            if (!slot->done.load())
                ++live;
        if (live >= k_max_clients) {
            closesocket(client);
            continue;
        }
        auto slot = std::make_unique<ClientSlot>();
        slot->sock = client;
        ClientSlot* raw = slot.get();
        raw->thr = std::thread([impl, raw, peer_ip = std::string(ip)] {
            handle_client(impl, raw->sock, peer_ip);
            std::lock_guard close_lock(impl->slots_mu);
            if (raw->sock != INVALID_SOCKET) {
                closesocket(raw->sock);
                raw->sock = INVALID_SOCKET;
            }
            raw->done = true;
        });
        impl->slots.push_back(std::move(slot));
    }
}

bool register_mdns(LanServiceImpl& impl, std::string& err)
{
    media_cli::mdns::Publication pub;
    pub.instance_name = impl.name;
    pub.service_type = "_tanit._tcp";
    pub.host = impl.mdns_host;
    pub.port = impl.tls_port;
    pub.txt = {
        {"txtvers", "1"},
        {"v", std::to_string(k_protocol_version)},
        {"fp", impl.fingerprint},
        {"name", impl.name},
        {"role", "computer"},
    };
    return impl.mdns.start(pub, err);
}

} // namespace

Service::Service() : impl_(new LanServiceImpl) {}

Service::~Service()
{
    stop();
    delete impl_;
    impl_ = nullptr;
}

bool Service::prepare(const std::string& display_name, std::string& err)
{
    err.clear();
    if (!impl_)
        return false;
    // Mesh ask → ConsentDlg when an interactive desktop is present. Language
    // follows appearance settings. Headless stays on the default Deny prompt.
    pm::lan::ensure_win32_mesh_consent_prompt();
    std::lock_guard lock(impl_->mu);
    if (impl_->prepared)
        return true;
    if (!ensure_winsock(err))
        return false;
    SetConsoleOutputCP(CP_UTF8);

    const fs::path dir = config_lan_dir(err);
    if (dir.empty())
        return false;
    impl_->devices_path = dir / "devices.json";
    impl_->identity_path = dir / "identity.json";

    const std::wstring computer = computer_name_w();
    impl_->mdns_host = wide_to_utf8(dns_label(computer)) + ".local";
    impl_->name = clean_text(display_name, 64);
    if (impl_->name.empty())
        impl_->name = clean_text(wide_to_utf8(computer), 64);
    if (impl_->name.empty())
        impl_->name = "Tanit";

    impl_->ips = lan_ipv4();
    impl_->addresses.clear();
    for (const auto& ip : impl_->ips)
        impl_->addresses.push_back(ip.text);

    impl_->key_container = key_container_for_process();
    bool is_rsa = false;
    if (!open_or_create_key(*impl_, is_rsa, err) || !make_certificate(*impl_, is_rsa, err)) {
        free_cert(*impl_);
        return false;
    }

    std::string previous;
    std::string previous_created;
    std::string device_id;
    std::string text;
    if (read_text_file(impl_->identity_path, text)) {
        const auto j = media::json::try_parse(text);
        if (j.is_object()) {
            previous = j.value("fingerprint", std::string{});
            previous_created = j.value("created", std::string{});
            device_id = j.value("id", std::string{});
        }
    }
    bool id_ok = device_id.size() == 16;
    for (unsigned char c : device_id) {
        if (!id_ok)
            break;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            id_ok = false;
    }
    if (!id_ok) {
        std::uint8_t raw[8];
        if (!random_bytes(raw, sizeof(raw))) {
            err = "could not assign a device id";
            free_cert(*impl_);
            return false;
        }
        device_id = media::strutil::to_hex(raw, sizeof(raw));
    }
    impl_->device_id = device_id;
    if (!previous.empty() && previous != impl_->fingerprint)
        logger::warn("lan public key changed; peers must pair again");
    const nlohmann::json id{
        {"v", 1},
        {"id", device_id},
        {"fingerprint", impl_->fingerprint},
        {"created", previous == impl_->fingerprint && !previous_created.empty() ? previous_created : iso_now()},
    };
    if (!write_text_file(impl_->identity_path, id.dump(2), err)) {
        free_cert(*impl_);
        return false;
    }
    if (!reload_devices_unlocked(*impl_, err)) {
        free_cert(*impl_);
        return false;
    }

    std::uint8_t hop_raw[32];
    if (!random_bytes(hop_raw, sizeof(hop_raw))) {
        err = "could not generate the LAN hop secret";
        free_cert(*impl_);
        return false;
    }
    impl_->hop = b64url(hop_raw, sizeof(hop_raw));
    impl_->prepared = true;
    return true;
}

bool Service::listen(const std::string& http_host, int http_port, int tls_port, std::string& err)
{
    err.clear();
    if (!impl_ || !impl_->prepared) {
        err = "LAN identity is not ready";
        return false;
    }
    if (tls_port <= 0 || tls_port > 65535 || tls_port == http_port) {
        err = "LAN TLS port must differ from the HTTP port";
        return false;
    }
    if (impl_->listening)
        return true;

    std::string upstream = http_host;
    if (upstream.empty() || upstream == "0.0.0.0" || upstream == "::" || upstream == "*") {
        // 127.0.0.1 can belong to another process. A wildcard listen still
        // receives a connection aimed at one of this machine's own addresses.
        upstream.clear();
        if (!impl_->ips.empty())
            upstream = impl_->ips.front().text;
        if (upstream.empty())
            upstream = "127.0.0.1";
    }
    if (ieq(upstream, "localhost"))
        upstream = "127.0.0.1";

    if (!acquire_tls_cred(*impl_, err))
        return false;

    const SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) {
        err = "could not open the LAN TLS socket";
        return false;
    }
    BOOL reuse = TRUE;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&reuse), sizeof(reuse));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(tls_port));
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        const int wsa = WSAGetLastError();
        closesocket(ls);
        err = "could not bind the LAN TLS port " + std::to_string(tls_port) + " (" + std::to_string(wsa) + ")";
        return false;
    }
    if (::listen(ls, 16) != 0) {
        closesocket(ls);
        err = "could not listen on the LAN TLS port";
        return false;
    }

    impl_->listen_sock = ls;
    impl_->tls_port = tls_port;
    impl_->http_port = http_port;
    impl_->upstream_host = upstream;
    impl_->stopping = false;
    impl_->listening = true;
    impl_->accept_thread = std::thread([this] { accept_loop(impl_); });

    std::string mdns_err;
    if (!register_mdns(*impl_, mdns_err)) {
        impl_->mdns_ok = false;
        logger::warn(std::string("lan mdns: ") + mdns_err + " — type the address on the phone");
    } else {
        impl_->mdns_ok = true;
        logger::info("lan mdns: _tanit._tcp port " + std::to_string(tls_port));
    }
    return true;
}

void Service::stop()
{
    if (!impl_)
        return;
    impl_->stopping = true;
    if (impl_->listen_sock != INVALID_SOCKET) {
        closesocket(impl_->listen_sock);
        impl_->listen_sock = INVALID_SOCKET;
    }
    if (impl_->accept_thread.joinable())
        impl_->accept_thread.join();
    std::vector<std::unique_ptr<ClientSlot>> slots;
    {
        std::lock_guard lock(impl_->slots_mu);
        for (auto& slot : impl_->slots) {
            if (slot->sock != INVALID_SOCKET)
                shutdown(slot->sock, SD_BOTH);
        }
        slots.swap(impl_->slots);
    }
    for (auto& slot : slots) {
        if (slot->thr.joinable())
            slot->thr.join();
    }
    impl_->mdns.stop();
    impl_->mdns_ok = false;
    {
        std::lock_guard lock(impl_->mu);
        delete_qr_image(*impl_);
        impl_->ticket.open = false;
        impl_->ticket.secret.clear();
    }
    free_cert(*impl_);
    impl_->listening = false;
    impl_->prepared = false;
}

PublicInfo Service::info() const
{
    PublicInfo out;
    if (!impl_)
        return out;
    std::lock_guard lock(impl_->mu);
    out.name = impl_->name;
    out.id = impl_->device_id;
    out.fingerprint = impl_->fingerprint;
    out.fingerprint_colon = impl_->fingerprint_colon;
    out.tls_port = impl_->tls_port;
    out.pairing_open = impl_->ticket.open
                       && std::chrono::steady_clock::now() < impl_->ticket.expires;
    out.mdns = impl_->mdns_ok;
    out.addresses = impl_->addresses;
    return out;
}

bool Service::proxy_peer(const std::string& addr) const
{
    if (!impl_ || addr.empty())
        return false;
    std::lock_guard lock(impl_->mu);
    if (addr == impl_->upstream_host)
        return true;
    for (const auto& ip : impl_->ips)
        if (ip.text == addr)
            return true;
    return false;
}

bool Service::hop_matches(const std::string& presented) const
{
    if (!impl_)
        return false;
    std::lock_guard lock(impl_->mu);
    return constant_time_equal(presented, impl_->hop);
}

bool Service::open_pairing(const std::vector<std::string>& scopes, int ttl_sec, PairingTicket& out,
                           std::string& err)
{
    err.clear();
    out = {};
    if (!impl_ || !impl_->prepared || impl_->tls_port <= 0) {
        err = "LAN listener is not up";
        return false;
    }
    if (scopes.empty()) {
        err = "pair scopes are empty";
        return false;
    }
    ttl_sec = std::clamp(ttl_sec, 30, 900);
    std::uint8_t raw[16];
    if (!random_bytes(raw, sizeof(raw))) {
        err = "could not generate a pairing secret";
        return false;
    }
    std::lock_guard lock(impl_->mu);
    delete_qr_image(*impl_);
    impl_->ticket = {};
    impl_->ticket.open = true;
    impl_->ticket.secret = "tp1_" + b64url(raw, sizeof(raw));
    impl_->ticket.scopes = scopes;
    impl_->ticket.expires = std::chrono::steady_clock::now() + std::chrono::seconds(ttl_sec);

    out.secret = impl_->ticket.secret;
    out.scopes = scopes;
    out.port = impl_->tls_port;
    out.fingerprint = impl_->fingerprint;
    out.fingerprint_colon = impl_->fingerprint_colon;
    out.expires_at = iso_after(ttl_sec);
    out.host = impl_->addresses.empty() ? impl_->mdns_host : impl_->addresses.front();
    out.uri = "tanit://pair?v=1&host=" + url_encode(out.host) + "&port=" + std::to_string(out.port)
              + "&fp=" + impl_->fingerprint + "&secret=" + url_encode(out.secret)
              + "&name=" + url_encode(impl_->name);
    std::vector<std::uint8_t> modules;
    int qr_size = 0;
    std::string qr_err;
    if (!encode_qr(out.uri, modules, qr_size, qr_err)) {
        out.qr_error = qr_err;
    } else {
        out.qr_ascii = qr_ascii(modules.data(), qr_size);
    }
    return true;
}

std::string Service::reveal_qr(const PairingTicket& ticket, bool open_window)
{
    if (!impl_ || ticket.uri.empty() || !ticket.qr_error.empty())
        return {};
    std::vector<std::uint8_t> modules;
    int qr_size = 0;
    std::string err;
    if (!encode_qr(ticket.uri, modules, qr_size, err))
        return {};
    wchar_t temp[MAX_PATH];
    const DWORD n = GetTempPathW(MAX_PATH, temp);
    if (n == 0 || n >= MAX_PATH)
        return {};
    const fs::path path = std::filesystem::path(temp) / L"tanit-lan-pair-qr.bmp";
    if (!write_qr_bmp(path, modules.data(), qr_size, 8, 4, err))
        return {};
    const std::string path_utf8 = wide_to_utf8(path.wstring());
    {
        std::lock_guard lock(impl_->mu);
        if (impl_->qr_image != path_utf8)
            delete_qr_image(*impl_);
        impl_->qr_image = path_utf8;
    }
    const char* skip = std::getenv("TANIT_LAN_NO_QR_WINDOW");
    const bool suppressed = skip && (std::string(skip) == "1" || ieq(skip, "true"));
    if (open_window && !suppressed) {
        const INT_PTR opened = reinterpret_cast<INT_PTR>(
            ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
        if (opened <= 32)
            logger::warn("lan pair: could not open the QR image");
    }
    return path_utf8;
}

PairError Service::complete_pairing(const std::string& secret, const std::string& device_id,
                                    const std::string& device_name,
                                    const std::vector<std::string>& requested_scopes,
                                    const std::string& peer_tls_fp, PairGrant& out, std::string& err)
{
    err.clear();
    out = {};
    if (!impl_) {
        err = "LAN pairing is off";
        return PairError::NoSession;
    }
    bool mismatch = false;
    {
        std::lock_guard lock(impl_->mu);
        if (!impl_->ticket.open) {
            err = "no pairing window is open";
            return PairError::NoSession;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= impl_->ticket.expires) {
            impl_->ticket.open = false;
            impl_->ticket.secret.clear();
            delete_qr_image(*impl_);
            err = "pairing window expired";
            return PairError::Expired;
        }
        if (impl_->ticket.failures >= 8 && now < impl_->ticket.locked_until) {
            err = "too many pairing attempts";
            return PairError::Locked;
        }
        if (!constant_time_equal(secret, impl_->ticket.secret)) {
            ++impl_->ticket.failures;
            if (impl_->ticket.failures >= 8)
                impl_->ticket.locked_until = now + std::chrono::seconds(30);
            mismatch = true;
        } else {
            if (!peer_tls_fp.empty() && !pin_ok(peer_tls_fp)) {
                err = "the peer certificate pin is not valid";
                return PairError::Rejected;
            }
            const auto granted = scope_intersection(impl_->ticket.scopes, requested_scopes);
            if (granted.empty()) {
                err = "the peer requested scopes this device did not offer";
                return PairError::Rejected;
            }
            std::string load_err;
            if (!reload_devices_unlocked(*impl_, load_err)) {
                err = load_err.empty() ? "could not load paired devices" : load_err;
                return PairError::Rejected;
            }
            std::string id = device_id;
            if (!device_id_ok(id)) {
                std::uint8_t raw[8];
                if (!random_bytes(raw, sizeof(raw))) {
                    err = "could not assign a device id";
                    return PairError::Rejected;
                }
                id = "dev-" + media::strutil::to_hex(raw, sizeof(raw));
            }
            bool replaced = false;
            for (const auto& d : impl_->devices) {
                if (d.id == id)
                    replaced = true;
            }
            if (!replaced && static_cast<int>(impl_->devices.size()) >= k_max_devices) {
                err = "too many paired devices; revoke one first";
                return PairError::Rejected;
            }
            std::uint8_t token_raw[32];
            if (!random_bytes(token_raw, sizeof(token_raw))) {
                err = "could not generate a device token";
                return PairError::Rejected;
            }
            const std::string token = "tn1_" + b64url(token_raw, sizeof(token_raw));
            std::string hash;
            if (!sha256_hex(reinterpret_cast<const std::uint8_t*>(token.data()), token.size(), hash)) {
                err = "could not store the device token";
                return PairError::Rejected;
            }
            pm::lan::Peer device;
            device.id = id;
            device.name = clean_text(device_name, 80);
            if (device.name.empty())
                device.name = "peer";
            device.token_sha256 = hash;
            device.trust = pm::lan::Trust::Paired;
            device.created = iso_now();
            device.last_seen = device.created;
            // The ticket intersection only decides that this confirm is allowed.
            // The stored grant stays off. Settings is what turns a grant on.
            // A second confirm of the same id replaces that grant and moves
            // the revision, so a peer keeping an older document applies this one.
            pm::lan::Grant previous;
            bool updated = false;
            for (const auto& d : impl_->devices) {
                if (d.id != id)
                    continue;
                device.created = d.created.empty() ? device.created : d.created;
                device.urls = d.urls;
                device.dial_token = d.dial_token;
                device.tls_fp = pin_ok(peer_tls_fp) ? peer_tls_fp : d.tls_fp;
                device.peer_fp = d.peer_fp;
                previous = d.allow_peer;
                updated = true;
                break;
            }
            // Every capability revision follows the replaced row's.
            if (updated)
                pm::lan::grant_succeed(device.allow_peer, previous);
            if (updated) {
                for (auto& d : impl_->devices) {
                    if (d.id == id) {
                        d = device;
                        break;
                    }
                }
            } else {
                if (pin_ok(peer_tls_fp))
                    device.tls_fp = peer_tls_fp;
                impl_->devices.push_back(device);
            }
            std::string save_err;
            if (!store_devices_unlocked(*impl_, save_err)) {
                err = save_err.empty() ? "could not save the paired device" : save_err;
                return PairError::Rejected;
            }
            pm::node::sessions_cancel(id, "");
            impl_->ticket.open = false;
            impl_->ticket.secret.clear();
            delete_qr_image(*impl_);
            out.token = token;
            out.device_id = id;
            out.host_id = impl_->device_id;
            out.scopes = pm::lan::grant_scopes(device.allow_peer);
            out.fingerprint = impl_->fingerprint;
            logger::info("lan pair: granted " + id + " (" + device.name + ")");
            return PairError::Ok;
        }
    }
    if (mismatch) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        err = "pairing secret was not accepted";
        return PairError::BadSecret;
    }
    err = "pairing failed";
    return PairError::Rejected;
}

bool Service::authorize(const std::string& token, DeviceAuth& out)
{
    return authorize(token, out, {});
}

bool Service::authorize(const std::string& token, DeviceAuth& out, std::string_view need_scope)
{
    out = {};
    if (!impl_ || token.size() < 8)
        return false;
    std::string hash;
    if (!sha256_hex(reinterpret_cast<const std::uint8_t*>(token.data()), token.size(), hash))
        return false;
    std::lock_guard lock(impl_->mu);
    std::string err;
    if (!reload_devices_unlocked(*impl_, err))
        return false;
    for (auto& d : impl_->devices) {
        if (d.trust != pm::lan::Trust::Paired || !constant_time_equal(hash, d.token_sha256))
            continue;
        d.last_seen = iso_now();
        const auto now = std::chrono::steady_clock::now();
        if (now - impl_->devices_saved > std::chrono::seconds(60)) {
            std::string save_err;
            (void)store_devices_unlocked(*impl_, save_err);
        }
        out.id = d.id;
        out.name = d.name;
        out.scopes = pm::lan::grant_scopes(d.allow_peer);
        // `ask` → ConsentDlg (or installed prompt). Only the needed scope is
        // prompted so an audio call does not also ask for folders.
        // authorize() with no scope still resolves vfs ask (folder routes).
        const std::string scope = need_scope.empty() ? std::string("files") : std::string(need_scope);
        const char* capability = nullptr;
        const char* operation = "start";
        if (scope == "files") {
            capability = pm::lan::k_cap_vfs;
            operation = "read";
        } else if (scope == "audio") {
            capability = pm::lan::k_cap_audio_capture;
        } else if (scope == "video") {
            capability = pm::lan::k_cap_video_capture;
        } else if (scope == "chat") {
            capability = pm::lan::k_cap_chat_turn;
            operation = "turn";
        } else if (scope == "tools") {
            capability = pm::lan::k_cap_tools_call;
            operation = "call";
        }
        if (capability && std::find(out.scopes.begin(), out.scopes.end(), scope) == out.scopes.end()) {
            pm::lan::PairStore store(impl_->devices_path, static_cast<std::size_t>(k_max_devices));
            const int revision = pm::lan::grant_capability_revision(d.allow_peer, capability);
            if (pm::lan::authorize_peer(&store, d, capability, operation, "")
                == pm::lan::Decision::Allow) {
                for (auto& row : impl_->devices) {
                    if (row.id == d.id) {
                        row = d;
                        break;
                    }
                }
                out.scopes = pm::lan::grant_scopes(d.allow_peer);
                if (std::find(out.scopes.begin(), out.scopes.end(), scope) == out.scopes.end())
                    out.scopes.push_back(scope);
            } else if (pm::lan::mesh_consent_ticket_allows(d.id, capability, operation, "",
                                                           revision)) {
                out.scopes.push_back(scope);
            }
        }
        out.write = pm::lan::grant_authorize(d.allow_peer, pm::lan::k_cap_vfs, "write", "")
                        == pm::lan::Decision::Allow
                    || pm::lan::mesh_consent_ticket_allows(d.id, pm::lan::k_cap_vfs, "write", "",
                                                          d.allow_peer.vfs_revision);
        out.revision = d.allow_peer.revision;
        if (!pm::lan::grant_resources(d.allow_peer, pm::lan::k_cap_vfs).empty()) {
            out.mount_allowed = [grant = d.allow_peer](std::string_view mount) {
                return pm::lan::grant_resource_allowed(grant, pm::lan::k_cap_vfs,
                                                       "mount:" + std::string(mount));
            };
        }
        return true;
    }
    return false;
}

std::vector<DeviceInfo> Service::devices()
{
    std::vector<DeviceInfo> out;
    if (!impl_)
        return out;
    std::lock_guard lock(impl_->mu);
    std::string err;
    if (!reload_devices_unlocked(*impl_, err))
        return out;
    for (const auto& d : impl_->devices) {
        DeviceInfo info;
        info.id = d.id;
        info.name = d.name;
        info.scopes = pm::lan::grant_scopes(d.allow_peer);
        info.vfs = pm::lan::vfs_grant_name(d.allow_peer.vfs);
        info.audio = d.allow_peer.audio.empty() ? "off" : d.allow_peer.audio;
        info.video = d.allow_peer.video.empty() ? "off" : d.allow_peer.video;
        info.chat = d.allow_peer.chat.empty() ? "off" : d.allow_peer.chat;
        info.tools = d.allow_peer.tools.empty() ? "off" : d.allow_peer.tools;
        info.revision = d.allow_peer.revision;
        info.created = d.created;
        info.last_seen = d.last_seen;
        info.revoked = d.trust != pm::lan::Trust::Paired;
        out.push_back(std::move(info));
    }
    return out;
}

bool Service::revoke(const std::string& id, std::string& err)
{
    return revoke_paired_device(id, err) && [&] {
        std::lock_guard lock(impl_->mu);
        return reload_devices_unlocked(*impl_, err);
    }();
}

bool list_paired_device_infos(std::vector<DeviceInfo>& out, std::string& err)
{
    out.clear();
    const fs::path dir = config_lan_dir(err);
    if (dir.empty())
        return false;
    const fs::path path = dir / "devices.json";
    std::string identity;
    std::vector<pm::lan::Peer> peers;
    pm::lan::PairStore store(path, static_cast<std::size_t>(k_max_devices));
    if (!store.load_identity(identity, peers, err)) {
        if (err != "pair file uses ticket scopes" || !import_ticket_file(path, err) ||
            !store.load_identity(identity, peers, err))
            return false;
    }
    err.clear();
    for (const auto& d : peers) {
        DeviceInfo info;
        info.id = d.id;
        info.name = d.name;
        info.scopes = pm::lan::grant_scopes(d.allow_peer);
        info.vfs = pm::lan::vfs_grant_name(d.allow_peer.vfs);
        info.audio = d.allow_peer.audio.empty() ? "off" : d.allow_peer.audio;
        info.video = d.allow_peer.video.empty() ? "off" : d.allow_peer.video;
        info.chat = d.allow_peer.chat.empty() ? "off" : d.allow_peer.chat;
        info.tools = d.allow_peer.tools.empty() ? "off" : d.allow_peer.tools;
        info.revision = d.allow_peer.revision;
        info.created = d.created;
        info.last_seen = d.last_seen;
        info.revoked = d.trust != pm::lan::Trust::Paired;
        out.push_back(std::move(info));
    }
    return true;
}

namespace {

std::string query_param(const std::string& query, const std::string& key)
{
    const std::string token = key + "=";
    std::size_t at = 0;
    while (at < query.size()) {
        if (query.compare(at, token.size(), token) == 0) {
            const std::size_t start = at + token.size();
            const std::size_t end = query.find('&', start);
            return query.substr(start, end == std::string::npos ? std::string::npos : end - start);
        }
        const std::size_t next = query.find('&', at);
        if (next == std::string::npos)
            break;
        at = next + 1;
    }
    return {};
}

std::string query_unquote(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9')
                    return c - '0';
                if (c >= 'a' && c <= 'f')
                    return c - 'a' + 10;
                if (c >= 'A' && c <= 'F')
                    return c - 'A' + 10;
                return -1;
            };
            const int hi = hex(in[i + 1]);
            const int lo = hex(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>(hi * 16 + lo));
                i += 2;
                continue;
            }
        }
        out.push_back(in[i] == '+' ? ' ' : in[i]);
    }
    return out;
}

bool self_lan_id(std::string& id, std::string& pin, std::string& name, std::string& err)
{
    const fs::path dir = config_lan_dir(err);
    if (dir.empty())
        return false;
    const fs::path path = dir / "identity.json";
    std::string text;
    if (read_text_file(path, text)) {
        const auto parsed = media::json::try_parse(text);
        if (parsed.is_object()) {
            id = parsed.value("id", std::string{});
            pin = parsed.value("fingerprint", std::string{});
        }
    }
    name = wide_to_utf8(computer_name_w());
    if (name.empty())
        name = "Tanit";
    bool ok = id.size() == 16;
    for (unsigned char c : id) {
        if (!ok)
            break;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            ok = false;
    }
    if (ok) {
        err.clear();
        return true;
    }
    std::uint8_t raw[8];
    if (!random_bytes(raw, sizeof raw)) {
        err = "could not assign a device id";
        return false;
    }
    id = media::strutil::to_hex(raw, sizeof raw);
    const nlohmann::json body{{"v", 1}, {"id", id}, {"fingerprint", pin}, {"created", ""}};
    if (!write_text_file(path, body.dump(2), err))
        return false;
    err.clear();
    return true;
}

} // namespace

bool discover_lan_peers(std::vector<LanSight>& out, std::string& err)
{
    out.clear();
    std::vector<media_cli::mdns::Sight> rows;
    if (!media_cli::mdns::browse("_tanit._tcp", 1200, rows, err))
        return false;
    for (const auto& row : rows) {
        LanSight sight;
        sight.name = row.name;
        sight.host = row.host;
        sight.port = row.port;
        sight.role = row.role.empty() ? "computer" : row.role;
        out.push_back(std::move(sight));
    }
    err.clear();
    return true;
}

bool accept_pairing_link(const std::string& link, std::string& err)
{
    err.clear();
    if (link.compare(0, 12, "tanit://pair") != 0) {
        err = "This pairing link is not valid";
        return false;
    }
    const std::size_t qpos = link.find('?');
    if (qpos == std::string::npos) {
        err = "This pairing link is not valid";
        return false;
    }
    const std::string query = link.substr(qpos + 1);
    if (query_param(query, "v") != "1") {
        err = "This pairing link is not supported";
        return false;
    }
    const std::string host = query_unquote(query_param(query, "host"));
    const int port = std::atoi(query_param(query, "port").c_str());
    std::string pin = query_param(query, "fp");
    pin.erase(std::remove(pin.begin(), pin.end(), ':'), pin.end());
    for (char& c : pin) {
        if (c >= 'A' && c <= 'F')
            c = static_cast<char>(c - 'A' + 'a');
    }
    const std::string secret = query_param(query, "secret");
    std::string peer_name = query_unquote(query_param(query, "name"));
    if (host.empty() || host.find(' ') != std::string::npos || port < 1 || port > 65535
        || pin.size() != 64 || secret.compare(0, 4, "tp1_") != 0) {
        err = "This pairing link is not valid";
        return false;
    }
    if (peer_name.empty())
        peer_name = host;
    std::string self_id;
    std::string self_pin;
    std::string self_name;
    if (!self_lan_id(self_id, self_pin, self_name, err))
        return false;
    const std::string base = "https://" + host + ":" + std::to_string(port);
    std::string peer_id;
    long http = 0;
    return pm::vfs::peer::pair_with(base, pin, self_id, self_name, self_pin, secret, peer_id, http, err,
                                    peer_name);
}

bool list_paired_devices(std::string& text, std::string& err)
{
    text.clear();
    const fs::path dir = config_lan_dir(err);
    if (dir.empty())
        return false;
    const fs::path path = dir / "devices.json";
    std::string identity;
    std::vector<pm::lan::Peer> peers;
    pm::lan::PairStore store(path, static_cast<std::size_t>(k_max_devices));
    if (!store.load_identity(identity, peers, err)) {
        if (err != "pair file uses ticket scopes" || !import_ticket_file(path, err) ||
            !store.load_identity(identity, peers, err))
            return false;
    }
    if (peers.empty()) {
        text = "no paired devices\n";
        return true;
    }
    for (const auto& d : peers) {
        text += d.trust == pm::lan::Trust::Paired ? "active" : "revoked";
        text += "\t";
        text += d.id;
        text += "\t";
        text += d.name;
        text += "\t";
        const auto scopes = pm::lan::grant_scopes(d.allow_peer);
        for (size_t i = 0; i < scopes.size(); ++i) {
            if (i)
                text += ",";
            text += scopes[i];
        }
        text += "\t";
        text += d.created;
        text += "\n";
    }
    return true;
}

bool revoke_paired_device(const std::string& id, std::string& err)
{
    if (!device_id_ok(id)) {
        err = "device id is empty or not usable";
        return false;
    }
    const fs::path dir = config_lan_dir(err);
    if (dir.empty())
        return false;
    const fs::path path = dir / "devices.json";
    pm::lan::PairStore store(path, static_cast<std::size_t>(k_max_devices));
    std::string identity;
    std::vector<pm::lan::Peer> peers;
    if (!store.load_identity(identity, peers, err)) {
        if (err != "pair file uses ticket scopes" || !import_ticket_file(path, err))
            return false;
    }
    if (!store.revoke(id, err)) {
        if (err.empty())
            err = "no paired device with that id";
        return false;
    }
    logger::info("lan pair: revoked " + id);
    pm::vfs::phone::forget_revoked_device(id);
    return true;
}

bool set_paired_device_grant(const std::string& id, const std::string& vfs, bool audio, bool video,
                             bool chat, bool tools, std::string& err)
{
    // Must be std::string: a const char* prefers the bool overload (pointer→bool
    // outranks user-defined conversion to std::string) and recurses forever.
    return set_paired_device_grant(id, vfs, std::string(audio ? "on" : "off"),
                                   std::string(video ? "on" : "off"),
                                   std::string(chat ? "on" : "off"),
                                   std::string(tools ? "on" : "off"), err);
}

bool set_paired_device_grant(const std::string& id, const std::string& vfs, const std::string& audio,
                             const std::string& video, const std::string& chat,
                             const std::string& tools, std::string& err)
{
    if (!device_id_ok(id)) {
        err = "device id is empty or not usable";
        return false;
    }
    pm::lan::VfsGrant grant = pm::lan::VfsGrant::Off;
    if (!pm::lan::parse_vfs_grant(vfs, grant)) {
        err = "folder access is off, read, or write";
        return false;
    }
    const fs::path dir = config_lan_dir(err);
    if (dir.empty())
        return false;
    const fs::path path = dir / "devices.json";
    pm::lan::PairStore store(path, static_cast<std::size_t>(k_max_devices));
    pm::lan::Peer peer;
    if (!store.set_caps(id, grant, audio, video, chat, tools, peer, err)) {
        if (err.empty())
            err = "no paired device with that id";
        return false;
    }
    logger::info(std::string("lan pair: grant ") + id + " vfs=" + pm::lan::vfs_grant_name(grant)
                 + " audio=" + audio);
    return true;
}

} // namespace media_cli::lan
