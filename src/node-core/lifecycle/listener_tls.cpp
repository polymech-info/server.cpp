#include "pm/node/listener_tls.hpp"

#if !defined(PM_PHONE_TLS)

namespace pm::node {

bool phone_tls_ensure(const std::filesystem::path&, std::string& pin, std::string& err)
{
    pin.clear();
    err = "phone listener has no TLS";
    return false;
}

PhoneTls* phone_tls_open(const std::filesystem::path&, int, int, std::string& pin, std::string& err)
{
    pin.clear();
    err = "phone listener has no TLS";
    return nullptr;
}

bool phone_tls_set_addresses(PhoneTls*, const std::vector<std::string>&, std::string& err)
{
    err = "phone listener has no TLS";
    return false;
}

void phone_tls_use_port(PhoneTls*, int) {}

void phone_tls_close(PhoneTls*) {}

bool phone_tls_get(const std::string&, const std::string&, const std::string&, const std::string&, long& http,
                   std::string& body, std::string& err)
{
    http = 0;
    body.clear();
    err = "phone listener has no TLS";
    return false;
}

bool phone_tls_post(const std::string&, const std::string&, const std::string&, const std::string&,
                    const std::string&, long& http, std::string& body, std::string& err)
{
    http = 0;
    body.clear();
    err = "phone listener has no TLS";
    return false;
}

} // namespace pm::node

#else

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <atomic>
#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace pm::node {
namespace {

struct Rng {
    mbedtls_entropy_context entropy{};
    mbedtls_ctr_drbg_context drbg{};
    std::mutex mu;
    bool ok = false;

    Rng()
    {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
        ok = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                   reinterpret_cast<const unsigned char*>("tanit-phone"), 11) == 0;
    }
    ~Rng()
    {
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
    }
    int random(unsigned char* out, size_t n)
    {
        std::lock_guard<std::mutex> lock(mu);
        return mbedtls_ctr_drbg_random(&drbg, out, n);
    }
    static int cb(void* ctx, unsigned char* out, size_t n)
    {
        return static_cast<Rng*>(ctx)->random(out, n);
    }
};

std::string hex_of(const unsigned char* p, size_t n)
{
    static const char* digits = "0123456789abcdef";
    std::string out(n * 2, '0');
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = digits[p[i] >> 4];
        out[i * 2 + 1] = digits[p[i] & 0x0f];
    }
    return out;
}

std::string spki_pin(mbedtls_pk_context& key)
{
    unsigned char der[1024];
    const int n = mbedtls_pk_write_pubkey_der(&key, der, sizeof der);
    if (n <= 0)
        return {};
    unsigned char hash[32];
    if (mbedtls_sha256(der + sizeof der - static_cast<size_t>(n), static_cast<size_t>(n), hash, 0) != 0)
        return {};
    return hex_of(hash, 32);
}

bool write_text(const std::filesystem::path& path, const char* text)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out)
        return false;
    out << text;
    return static_cast<bool>(out);
}

bool make_identity(const std::filesystem::path& key_path, const std::filesystem::path& crt_path,
                   Rng& rng, std::string& err)
{
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    mbedtls_x509write_cert crt;
    mbedtls_x509write_crt_init(&crt);
    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    bool ok = false;
    if (mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0
        || mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), Rng::cb, &rng) != 0) {
        err = "could not create the phone listener key";
    } else {
        mbedtls_mpi_lset(&serial, 1);
        mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
        mbedtls_x509write_crt_set_subject_key(&crt, &key);
        mbedtls_x509write_crt_set_issuer_key(&crt, &key);
        mbedtls_x509write_crt_set_subject_name(&crt, "CN=tanit-phone");
        mbedtls_x509write_crt_set_issuer_name(&crt, "CN=tanit-phone");
        mbedtls_x509write_crt_set_serial(&crt, &serial);
        mbedtls_x509write_crt_set_validity(&crt, "20260101000000", "20351231235959");
        unsigned char key_pem[4096];
        unsigned char crt_pem[4096];
        if (mbedtls_pk_write_key_pem(&key, key_pem, sizeof key_pem) != 0
            || mbedtls_x509write_crt_pem(&crt, crt_pem, sizeof crt_pem, Rng::cb, &rng) != 0) {
            err = "could not write the phone listener certificate";
        } else if (!write_text(key_path, reinterpret_cast<char*>(key_pem))
                   || !write_text(crt_path, reinterpret_cast<char*>(crt_pem))) {
            err = "could not store the phone listener certificate";
        } else {
            ok = true;
        }
    }
    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&key);
    return ok;
}

std::string local_address(const mbedtls_net_context& client)
{
    sockaddr_storage ss{};
#if defined(_WIN32)
    int len = sizeof ss;
    if (getsockname(static_cast<SOCKET>(client.fd), reinterpret_cast<sockaddr*>(&ss), &len) != 0)
        return "127.0.0.1";
#else
    socklen_t len = sizeof ss;
    if (getsockname(client.fd, reinterpret_cast<sockaddr*>(&ss), &len) != 0)
        return "127.0.0.1";
#endif
    char text[64] = "127.0.0.1";
    if (ss.ss_family == AF_INET)
        inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(&ss)->sin_addr, text, sizeof text);
    return text;
}

std::size_t content_length(const std::string& head)
{
    const std::string key = "content-length:";
    std::string lower = head;
    for (char& c : lower)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    const auto at = lower.find(key);
    if (at == std::string::npos)
        return 0;
    const auto end = lower.find("\r\n", at);
    const std::string value = lower.substr(at + key.size(), end == std::string::npos ? std::string::npos : end - (at + key.size()));
    try {
        return static_cast<std::size_t>(std::stoul(value));
    } catch (...) {
        return 0;
    }
}

void serve_one(mbedtls_ssl_context& ssl, mbedtls_net_context& backend, const std::string& arrived)
{
    std::string acc;
    unsigned char buf[4096];
    while (acc.find("\r\n\r\n") == std::string::npos && acc.size() < 16384) {
        const int n = mbedtls_ssl_read(&ssl, buf, sizeof buf);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (n <= 0)
            return;
        acc.append(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
    }
    const auto split = acc.find("\r\n\r\n");
    if (split == std::string::npos)
        return;
    const std::string raw_head = acc.substr(0, split);
    std::string body = acc.substr(split + 4);
    std::string head;
    std::size_t cursor = 0;
    bool first = true;
    while (cursor < raw_head.size()) {
        auto next = raw_head.find("\r\n", cursor);
        if (next == std::string::npos)
            next = raw_head.size();
        const std::string row = raw_head.substr(cursor, next - cursor);
        std::string lower = row;
        for (char& c : lower)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
        const bool connection = lower.rfind("connection:", 0) == 0;
        if (first || !connection)
            head += row + "\r\n";
        first = false;
        if (next == raw_head.size())
            break;
        cursor = next + 2;
    }
    const auto line = head.find("\r\n");
    if (line == std::string::npos)
        return;
    head.insert(line + 2, "X-Tanit-Arrived: " + arrived + "\r\nConnection: close\r\n");
    head += "\r\n";
    const std::size_t need = content_length(head);
    while (body.size() < need && body.size() < 9u * 1024u * 1024u) {
        const int n = mbedtls_ssl_read(&ssl, buf, sizeof buf);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (n <= 0)
            break;
        body.append(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
    }
    const std::string request = head + body.substr(0, need);
    size_t sent = 0;
    while (sent < request.size()) {
        const int n = mbedtls_net_send(&backend, reinterpret_cast<const unsigned char*>(request.data() + sent),
                                       request.size() - sent);
        if (n == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (n <= 0)
            return;
        sent += static_cast<size_t>(n);
    }
    for (;;) {
        unsigned char out[4096];
        const int n = mbedtls_net_recv(&backend, out, sizeof out);
        if (n == MBEDTLS_ERR_SSL_WANT_READ)
            continue;
        if (n <= 0)
            break;
        size_t off = 0;
        while (off < static_cast<size_t>(n)) {
            const int w = mbedtls_ssl_write(&ssl, out + off, static_cast<size_t>(n) - off);
            if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;
            if (w <= 0)
                return;
            off += static_cast<size_t>(w);
        }
    }
}

} // namespace

struct Bound {
    std::string address;
    mbedtls_net_context net{};
    std::thread accept;
    std::atomic<bool> stop{false};

    Bound() { mbedtls_net_init(&net); }
};

struct PhoneTls {
    Rng rng;
    mbedtls_pk_context key{};
    mbedtls_x509_crt crt{};
    mbedtls_ssl_config conf{};
    std::atomic<bool> stop{false};
    std::vector<std::thread> workers;
    std::mutex workers_mu;
    std::mutex mu;
    std::vector<std::unique_ptr<Bound>> bounds;
    int port = 0;
    int backend = 0;

    PhoneTls()
    {
        mbedtls_pk_init(&key);
        mbedtls_x509_crt_init(&crt);
        mbedtls_ssl_config_init(&conf);
    }
    ~PhoneTls()
    {
        mbedtls_ssl_config_free(&conf);
        mbedtls_x509_crt_free(&crt);
        mbedtls_pk_free(&key);
    }
};

void accept_loop(PhoneTls* raw, Bound* bound)
{
    while (!bound->stop.load() && !raw->stop.load()) {
        mbedtls_net_context client;
        mbedtls_net_init(&client);
        if (mbedtls_net_accept(&bound->net, &client, nullptr, 0, nullptr) != 0) {
            mbedtls_net_free(&client);
            if (bound->stop.load() || raw->stop.load())
                break;
            continue;
        }
        std::string arrived = local_address(client);
        if (arrived == "0.0.0.0")
            arrived = bound->address;
        const int backend_port = raw->backend;
        std::thread worker([raw, client, arrived, backend_port]() mutable {
            mbedtls_ssl_context ssl;
            mbedtls_ssl_init(&ssl);
            mbedtls_net_context backend_sock;
            mbedtls_net_init(&backend_sock);
            const std::string backend_port_text = std::to_string(backend_port);
            if (mbedtls_ssl_setup(&ssl, &raw->conf) == 0) {
                mbedtls_ssl_set_bio(&ssl, &client, mbedtls_net_send, mbedtls_net_recv, nullptr);
                int hs = 0;
                while ((hs = mbedtls_ssl_handshake(&ssl)) != 0) {
                    if (hs != MBEDTLS_ERR_SSL_WANT_READ && hs != MBEDTLS_ERR_SSL_WANT_WRITE)
                        break;
                }
                if (hs == 0
                    && mbedtls_net_connect(&backend_sock, "127.0.0.1", backend_port_text.c_str(),
                                           MBEDTLS_NET_PROTO_TCP) == 0)
                    serve_one(ssl, backend_sock, arrived);
                mbedtls_ssl_close_notify(&ssl);
            }
            mbedtls_net_free(&backend_sock);
            mbedtls_ssl_free(&ssl);
            mbedtls_net_free(&client);
        });
        std::lock_guard<std::mutex> lock(raw->workers_mu);
        raw->workers.push_back(std::move(worker));
    }
}

void stop_bound(Bound& bound)
{
    bound.stop.store(true);
    mbedtls_net_free(&bound.net);
    if (bound.accept.joinable())
        bound.accept.join();
}

bool phone_tls_ensure(const std::filesystem::path& pair_file, std::string& pin, std::string& err)
{
    pin.clear();
    const auto dir = pair_file.parent_path();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    const auto key_path = dir / "listener.key";
    const auto crt_path = dir / "listener.crt";
    Rng rng;
    if (!rng.ok) {
        err = "could not seed the phone listener key";
        return false;
    }
    if (!std::filesystem::exists(key_path) || !std::filesystem::exists(crt_path)) {
        if (!make_identity(key_path, crt_path, rng, err))
            return false;
    }
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    const std::string key_utf8 = key_path.string();
    const std::string crt_utf8 = crt_path.string();
    const bool parsed = mbedtls_pk_parse_keyfile(&key, key_utf8.c_str(), nullptr, Rng::cb, &rng) == 0
                        && mbedtls_x509_crt_parse_file(&crt, crt_utf8.c_str()) == 0;
    if (parsed)
        pin = spki_pin(key);
    mbedtls_x509_crt_free(&crt);
    mbedtls_pk_free(&key);
    if (!parsed || pin.size() != 64) {
        err = "could not read the phone listener certificate";
        return false;
    }
    return true;
}

PhoneTls* phone_tls_open(const std::filesystem::path& pair_file, int port, int backend, std::string& pin,
                         std::string& err)
{
    if (port <= 0 || port > 65535) {
        err = "the phone TLS port is not valid";
        return nullptr;
    }
    if (!phone_tls_ensure(pair_file, pin, err))
        return nullptr;
    auto tls = std::make_unique<PhoneTls>();
    if (!tls->rng.ok) {
        err = "could not seed the phone listener";
        return nullptr;
    }
    const auto dir = pair_file.parent_path();
    const std::string key_utf8 = (dir / "listener.key").string();
    const std::string crt_utf8 = (dir / "listener.crt").string();
    if (mbedtls_pk_parse_keyfile(&tls->key, key_utf8.c_str(), nullptr, Rng::cb, &tls->rng) != 0
        || mbedtls_x509_crt_parse_file(&tls->crt, crt_utf8.c_str()) != 0) {
        err = "could not load the phone listener certificate";
        return nullptr;
    }
    if (mbedtls_ssl_config_defaults(&tls->conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0
        || mbedtls_ssl_conf_own_cert(&tls->conf, &tls->crt, &tls->key) != 0) {
        err = "could not prepare the phone listener";
        return nullptr;
    }
    mbedtls_ssl_conf_rng(&tls->conf, Rng::cb, &tls->rng);
    mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE);
    tls->backend = backend;
    tls->port = port;
    return tls.release();
}

bool phone_tls_set_addresses(PhoneTls* tls, const std::vector<std::string>& addresses, std::string& err)
{
    if (!tls || tls->stop.load()) {
        err = "the phone listener is stopped";
        return false;
    }
    std::vector<std::string> want;
    for (const auto& address : addresses) {
        if (address.empty() || address == "0.0.0.0" || address.find(':') != std::string::npos)
            continue;
        bool seen = false;
        for (const auto& have : want)
            seen = seen || have == address;
        if (!seen)
            want.push_back(address);
    }
    std::vector<std::unique_ptr<Bound>> dropped;
    std::vector<std::string> missing;
    {
        std::lock_guard<std::mutex> lock(tls->mu);
        for (auto& bound : tls->bounds) {
            bool keep = false;
            for (const auto& address : want)
                keep = keep || address == bound->address;
            if (!keep)
                dropped.push_back(std::move(bound));
        }
        std::vector<std::unique_ptr<Bound>> kept;
        for (auto& bound : tls->bounds)
            if (bound)
                kept.push_back(std::move(bound));
        tls->bounds.swap(kept);
        for (const auto& address : want) {
            bool have = false;
            for (const auto& bound : tls->bounds)
                have = have || bound->address == address;
            if (!have)
                missing.push_back(address);
        }
    }
    for (auto& bound : dropped)
        stop_bound(*bound);
    const std::string port_text = std::to_string(tls->port);
    std::vector<std::unique_ptr<Bound>> opened;
    for (const auto& address : missing) {
        auto bound = std::make_unique<Bound>();
        bound->address = address;
        if (mbedtls_net_bind(&bound->net, address.c_str(), port_text.c_str(), MBEDTLS_NET_PROTO_TCP) != 0) {
            err = "could not bind " + address;
            for (auto& made : opened)
                stop_bound(*made);
            return false;
        }
        Bound* raw_bound = bound.get();
        raw_bound->accept = std::thread([tls, raw_bound] { accept_loop(tls, raw_bound); });
        opened.push_back(std::move(bound));
    }
    {
        std::lock_guard<std::mutex> lock(tls->mu);
        for (auto& bound : opened)
            tls->bounds.push_back(std::move(bound));
    }
    err.clear();
    return true;
}

void phone_tls_use_port(PhoneTls* tls, int port)
{
    if (tls && port > 0 && port <= 65535)
        tls->port = port;
}

void phone_tls_close(PhoneTls* tls)
{
    if (!tls)
        return;
    tls->stop.store(true);
    std::vector<std::unique_ptr<Bound>> bounds;
    {
        std::lock_guard<std::mutex> lock(tls->mu);
        bounds.swap(tls->bounds);
    }
    for (auto& bound : bounds)
        stop_bound(*bound);
    std::vector<std::thread> workers;
    {
        std::lock_guard<std::mutex> lock(tls->workers_mu);
        workers.swap(tls->workers);
    }
    for (auto& worker : workers)
        if (worker.joinable())
            worker.join();
    delete tls;
}

bool parse_https_ipv4(const std::string& base, std::string& host, std::string& port, std::string& err)
{
    const std::string prefix = "https://";
    if (base.rfind(prefix, 0) != 0) {
        err = "the peer address is not https";
        return false;
    }
    std::string rest = base.substr(prefix.size());
    if (!rest.empty() && rest.back() == '/')
        rest.pop_back();
    const auto colon = rest.rfind(':');
    if (colon == std::string::npos || colon == 0) {
        err = "the peer address is not usable";
        return false;
    }
    host = rest.substr(0, colon);
    port = rest.substr(colon + 1);
    if (host.empty() || port.empty() || host.find(':') != std::string::npos) {
        err = "the peer address is not usable";
        return false;
    }
    int dots = 0;
    for (unsigned char c : host) {
        if (c == '.')
            ++dots;
        else if (c < '0' || c > '9') {
            err = "the peer address is not usable";
            return false;
        }
    }
    if (dots != 3) {
        err = "the peer address is not usable";
        return false;
    }
    int value = 0;
    for (unsigned char c : port) {
        if (c < '0' || c > '9') {
            err = "the peer address is not usable";
            return false;
        }
        value = value * 10 + (c - '0');
        if (value > 65535) {
            err = "the peer address is not usable";
            return false;
        }
    }
    if (value <= 0) {
        err = "the peer address is not usable";
        return false;
    }
    return true;
}

std::string lower_hex(std::string text)
{
    for (char& c : text) {
        if (c >= 'A' && c <= 'F')
            c = static_cast<char>(c - 'A' + 'a');
    }
    return text;
}

bool phone_tls_http(const std::string& base, const std::string& path, const std::string& pin,
                    const std::string& bearer, const std::string& method, const std::string& payload,
                    long& http, std::string& body, std::string& err)
{
    http = 0;
    body.clear();
    err.clear();
    if (payload.size() > 16u * 1024u) {
        err = "the peer request is too large";
        return false;
    }
    if (path.empty() || path.front() != '/' || path.find(' ') != std::string::npos
        || path.find('\r') != std::string::npos || path.find('\n') != std::string::npos) {
        err = "the peer path is not usable";
        return false;
    }
    if (bearer.find('\r') != std::string::npos || bearer.find('\n') != std::string::npos) {
        err = "the peer token is not valid";
        return false;
    }
    if (lower_hex(pin).size() != 64) {
        err = "the peer certificate pin is not valid";
        return false;
    }
    std::string host;
    std::string port;
    if (!parse_https_ipv4(base, host, port, err))
        return false;

#if defined(_WIN32)
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    Rng rng;
    if (!rng.ok) {
        err = "could not seed the phone dialer";
        return false;
    }
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_net_init(&net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    auto finish = [&]() {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_net_free(&net);
    };
    if (mbedtls_net_connect(&net, host.c_str(), port.c_str(), MBEDTLS_NET_PROTO_TCP) != 0) {
        err = "the peer is not reachable";
        finish();
        return false;
    }
    if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        err = "could not prepare the phone dialer";
        finish();
        return false;
    }
    mbedtls_ssl_conf_rng(&conf, Rng::cb, &rng);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(&conf, [](void*, mbedtls_x509_crt*, int, uint32_t*) { return 0; }, nullptr);
    if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
        err = "could not prepare the phone dialer";
        finish();
        return false;
    }
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, nullptr);
    mbedtls_ssl_set_hostname(&ssl, host.c_str());
    int hs = 0;
    while ((hs = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (hs != MBEDTLS_ERR_SSL_WANT_READ && hs != MBEDTLS_ERR_SSL_WANT_WRITE)
            break;
    }
    const mbedtls_x509_crt* crt = hs == 0 ? mbedtls_ssl_get_peer_cert(&ssl) : nullptr;
    const std::string got = crt ? spki_pin(const_cast<mbedtls_pk_context&>(crt->pk)) : std::string{};
    if (hs != 0 || lower_hex(got) != lower_hex(pin)) {
        err = hs != 0 ? "could not complete TLS" : "certificate pin mismatch";
        mbedtls_ssl_close_notify(&ssl);
        finish();
        return false;
    }
    std::string request = method + " " + path + " HTTP/1.0\r\nHost: " + host + "\r\nAuthorization: Bearer "
                          + bearer + "\r\nConnection: close\r\n";
    if (!payload.empty()) {
        request += "Content-Type: application/json\r\nContent-Length: " + std::to_string(payload.size())
                   + "\r\n\r\n" + payload;
    } else {
        request += "\r\n";
    }
    size_t sent = 0;
    while (sent < request.size()) {
        const int n = mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>(request.data() + sent),
                                        request.size() - sent);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (n <= 0) {
            err = "the peer did not accept the request";
            finish();
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    std::string raw;
    unsigned char buf[4096];
    for (;;) {
        const int n = mbedtls_ssl_read(&ssl, buf, sizeof buf);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || n == 0)
            break;
        if (n < 0) {
            if (!raw.empty())
                break;
            err = "the peer closed the connection";
            finish();
            return false;
        }
        if (raw.size() + static_cast<size_t>(n) > 1024u * 1024u) {
            err = "the peer response is too large";
            finish();
            return false;
        }
        raw.append(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
    }
    mbedtls_ssl_close_notify(&ssl);
    finish();
    const auto split = raw.find("\r\n\r\n");
    if (split == std::string::npos || raw.rfind("HTTP/1.", 0) != 0) {
        err = "the peer sent no HTTP response";
        return false;
    }
    const auto line = raw.find("\r\n");
    const std::string status = raw.substr(0, line == std::string::npos ? split : line);
    const auto space = status.find(' ');
    if (space == std::string::npos) {
        err = "the peer sent no HTTP response";
        return false;
    }
    int code = 0;
    for (size_t i = space + 1; i < status.size() && status[i] >= '0' && status[i] <= '9'; ++i)
        code = code * 10 + (status[i] - '0');
    http = code;
    body = raw.substr(split + 4);
    return code >= 200 && code < 300;
}

bool phone_tls_get(const std::string& base, const std::string& path, const std::string& pin,
                   const std::string& bearer, long& http, std::string& body, std::string& err)
{
    return phone_tls_http(base, path, pin, bearer, "GET", {}, http, body, err);
}

bool phone_tls_post(const std::string& base, const std::string& path, const std::string& pin,
                    const std::string& bearer, const std::string& payload, long& http, std::string& body,
                    std::string& err)
{
    return phone_tls_http(base, path, pin, bearer, "POST", payload, http, body, err);
}

} // namespace pm::node

#endif
