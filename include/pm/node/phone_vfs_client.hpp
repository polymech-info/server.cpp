#pragma once

// Desktop client for a paired phone's `/v1/vfs`.
// Browse form is `vfs://phone-<id>/<mount>/<path>` (the same shape the file
// panel and `cp` already parse). The first segment selects the phone; the
// next segment is the phone's shared-folder mount.
//
// The phone is looked up in `lan/peers.json` (pm::node::PeerBook). The bearer is
// the token that phone issued for this computer. Addresses are the ones the
// phone announced. Each is checked against the stored certificate pin before
// any request, including `/health`, is sent. The pin match is what selects
// the address. No address is rewritten here.
//
// 401 means the phone no longer knows this computer. 403 means the phone
// turned a permission off. Neither is retried. This is not a third-device
// relay and not encryption.cpp.

#include "logging/logger.h"
#include "pm/node/peer_book.hpp"
#include "pm/node/peer_book_defaults.hpp"
#include <pm/commons/net/http_client.hpp>
#include <pm/vfs/uri.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pm::vfs::phone {

using Peer = pm::node::Peer;

/// Cap for a single phone file download (Activate / cp). Streaming to disk;
/// not held in RAM. Videos and large DCIM files need headroom.
inline constexpr std::uint64_t k_max_read = 2ull * 1024ull * 1024ull * 1024ull;
/// Matches the phone listener's `/v1/vfs/write` body cap.
inline constexpr std::size_t k_max_write = 8u * 1024u * 1024u;

/// True when every path component is a plain name (no `.` / `..` / separators).
[[nodiscard]] inline bool path_components_ok(std::string_view path) noexcept
{
    if (path.empty())
        return true;
    if (path.find('\\') != std::string_view::npos || path.find('\0') != std::string_view::npos)
        return false;
    std::size_t i = 0;
    while (i < path.size()) {
        if (path[i] == '/')
            return false;
        const auto slash = path.find('/', i);
        const auto end = slash == std::string_view::npos ? path.size() : slash;
        const auto part = path.substr(i, end - i);
        if (part.empty() || part == "." || part == "..")
            return false;
        if (end == path.size())
            break;
        i = end + 1;
    }
    return true;
}

[[nodiscard]] inline bool split(
    std::string_view device,
    std::string_view browse_path,
    std::string& server_mount,
    std::string& rel)
{
    if (!pm::node::is_device_mount(device))
        return false;
    std::string path(browse_path);
    while (!path.empty() && path.front() == '/')
        path.erase(path.begin());
    while (!path.empty() && path.back() == '/')
        path.pop_back();
    const auto slash = path.find('/');
    server_mount = slash == std::string::npos ? path : path.substr(0, slash);
    rel = slash == std::string::npos ? std::string{} : path.substr(slash + 1);
    if (server_mount.empty() || !path_components_ok(server_mount))
        return false;
    return path_components_ok(rel);
}

struct Mount {
    std::string name;
    std::string label;
    std::string host;
    std::string uri;
    /// What the phone lets this caller do on the mount, narrowed to what this
    /// client has a route for (`list`, `stat`, `read`, and when granted
    /// `write`, `mkdir`, `move`, `delete`). Missing / non-array `can` means
    /// the legacy read set; an explicit empty array means no permissions.
    std::vector<std::string> can;
};

/// The operations this client can issue against a phone. Keeps only those from
/// @p advertised. Missing / non-array `can` means the legacy read set. An
/// explicit empty array means no permissions.
[[nodiscard]] inline std::vector<std::string> client_can(const nlohmann::json& advertised)
{
    std::vector<std::string> out;
    if (!advertised.is_array())
        return {"list", "stat", "read"};
    for (const char* op : {"list", "stat", "read", "write", "mkdir", "move", "delete", "touch"}) {
        for (const auto& item : advertised) {
            if (item.is_string() && item.get<std::string>() == op) {
                out.emplace_back(op);
                break;
            }
        }
    }
    return out;
}

struct MountsResult {
    bool ok = false;
    /// The phone answered and said no. Not set for a phone that is offline.
    bool refused = false;
    std::string err;
    std::vector<Mount> mounts;
};

struct Entry {
    std::string name;
    bool is_dir = false;
    std::uint64_t size = 0;
    /// Milliseconds since Unix epoch (same as `/v1/vfs` `node.mtime`).
    std::int64_t mtime_ms = 0;
    std::string mime;
};

struct ListResult {
    bool ok = false;
    std::string err;
    std::vector<Entry> entries;
    /// The caller's operations on this mount, as in `Mount::can`.
    std::vector<std::string> can;
};

struct StatResult {
    bool ok = false;
    bool exists = false;
    bool is_dir = false;
    std::uint64_t size = 0;
    std::string err;
};

struct ReadResult {
    bool ok = false;
    std::uint64_t bytes = 0;
    std::string err;
};

struct ReadOptions {
    /// Unknown when unset. Zero means an empty file, not "unknown".
    std::optional<std::uint64_t> expected_size;
    std::function<void(std::uint64_t done, std::uint64_t total)> on_progress;
    std::function<bool()> cancel;
};

struct OpResult {
    bool ok = false;
    std::string err;
};

namespace detail {

inline void ensure_dial_book()
{
    pm::node::install_desktop_peer_book_defaults();
}

[[nodiscard]] inline bool pin_ok(const std::string& pin)
{
    if (pin.size() != 64)
        return false;
    for (unsigned char c : pin) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
    }
    return true;
}

[[nodiscard]] inline std::optional<Peer> find_peer(std::string_view authority)
{
    ensure_dial_book();
    return pm::node::find_peer(authority);
}

inline void drop_token_if_matches(std::string_view authority, std::string_view expected)
{
    ensure_dial_book();
    pm::node::drop_token_if_matches(authority, expected);
}

inline void note_grant(std::string_view authority, int revision, const std::string& vfs)
{
    ensure_dial_book();
    pm::node::note_grant(authority, revision, vfs);
}

[[nodiscard]] inline std::string join_origin_path(std::string_view base, std::string_view path)
{
    std::string out(base);
    if (path.empty())
        return out;
    while (!out.empty() && out.back() == '/')
        out.pop_back();
    std::string p(path);
    if (!p.empty() && p.front() != '/')
        p.insert(p.begin(), '/');
    out += p;
    return out;
}

[[nodiscard]] inline bool query_char_unreserved(unsigned char c) noexcept
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
           || c == '_' || c == '.' || c == '~';
}

[[nodiscard]] inline std::string percent_encode_query(std::string_view s)
{
    static constexpr char k_hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (query_char_unreserved(c))
            out.push_back(static_cast<char>(c));
        else {
            out.push_back('%');
            out.push_back(k_hex[(c >> 4) & 0x0F]);
            out.push_back(k_hex[c & 0x0F]);
        }
    }
    return out;
}

[[nodiscard]] inline std::string append_query_param(std::string path, const std::string& key,
                                                    const std::string& value)
{
    if (value.empty())
        return path;
    path += path.find('?') == std::string::npos ? '?' : '&';
    path += key;
    path += '=';
    path += percent_encode_query(value);
    return path;
}

struct NetBufferResult {
    bool got = false;
    long http = 0;
    std::string body;
    std::string err;
};

[[nodiscard]] inline NetBufferResult net_request(const Peer& peer, std::string_view base,
                                                   const std::string& path, const std::string& token,
                                                   long timeout_ms, long connect_timeout_ms,
                                                   const std::string& method = "GET",
                                                   std::string body = {}, const char* content_type = nullptr)
{
    pm::commons::net::Request req;
    req.method = method;
    req.url = join_origin_path(base, path);
    req.bearer = token;
    req.spki_sha256_hex = peer.tls_fp;
    req.timeout_ms = timeout_ms;
    req.connect_timeout_ms = connect_timeout_ms;
    if (!body.empty()) {
        req.body = std::move(body);
        if (content_type)
            req.headers.push_back({"Content-Type", content_type});
    }
    const auto resp = pm::commons::net::request(req);
    NetBufferResult out;
    out.got = resp.ok;
    out.http = resp.status;
    out.body = resp.body;
    out.err = resp.error;
    if (!resp.ok && out.err.empty() && !resp.code.empty())
        out.err = resp.code;
    return out;
}

inline constexpr auto k_lan_probe_cooldown = std::chrono::seconds(30);
inline constexpr long k_probe_timeout_sec = 2;

struct RouteState {
    std::string active_url;
    std::uint64_t generation = 0;
    std::chrono::steady_clock::time_point next_lan_probe{};
    bool resolving = false;
};

inline std::mutex& route_mutex()
{
    static std::mutex mu;
    return mu;
}

inline std::condition_variable& route_cv()
{
    static std::condition_variable cv;
    return cv;
}

inline std::map<std::string, RouteState>& routes()
{
    static std::map<std::string, RouteState> map;
    return map;
}

inline void forget_route(const std::string& device)
{
    std::lock_guard<std::mutex> lock(route_mutex());
    routes().erase(device);
    route_cv().notify_all();
}

/// Forget only when the cached URL is still @p url (stale failures must not
/// clear a newer working route).
inline void forget_route_if(const std::string& device, std::string_view url)
{
    if (url.empty())
        return;
    std::lock_guard<std::mutex> lock(route_mutex());
    const auto hit = routes().find(device);
    if (hit == routes().end() || hit->second.active_url != url)
        return;
    routes().erase(hit);
    route_cv().notify_all();
}

/// Preference hint only — not proof of reachability (RFC1918 string form).
inline bool url_looks_lan(std::string_view candidate)
{
    constexpr std::string_view kHttps = "https://";
    if (candidate.rfind(kHttps, 0) != 0)
        return false;
    const auto host = candidate.substr(kHttps.size());
    const auto cut = host.find_first_of(":/");
    const auto h = cut == std::string_view::npos ? host : host.substr(0, cut);
    if (h.find(':') != std::string_view::npos) // IPv6 — do not guess
        return false;
    if (h.rfind("192.168.", 0) == 0 || h.rfind("10.", 0) == 0)
        return true;
    if (h.rfind("172.", 0) != 0)
        return false;
    const auto rest = h.substr(4);
    const auto dot = rest.find('.');
    if (dot == std::string_view::npos || dot == 0 || dot > 3)
        return false;
    int second = 0;
    for (std::size_t i = 0; i < dot; ++i) {
        if (rest[i] < '0' || rest[i] > '9')
            return false;
        second = second * 10 + (rest[i] - '0');
        if (second > 31)
            return false;
    }
    return second >= 16 && second <= 31;
}

inline bool announced(const Peer& peer, std::string_view url)
{
    return std::find(peer.urls.begin(), peer.urls.end(), url) != peer.urls.end();
}

inline bool probe_url(const Peer& peer, const std::string& candidate, long& http, bool& refused,
                      std::string& probe_err)
{
    http = 0;
    refused = false;
    probe_err.clear();
    std::string body;
    const auto net = net_request(peer, candidate, "/health", {}, k_probe_timeout_sec * 1000L,
                                 k_probe_timeout_sec * 1000L);
    const bool got = net.got;
    http = net.http;
    body = net.body;
    probe_err = net.err;
    logger::debug(std::string("[phone-vfs] probe ") + candidate + " http=" + std::to_string(http)
                  + (probe_err.empty() ? std::string{} : " err=" + probe_err));
    if (!got)
        return false;
    if (http == 403) {
        refused = true;
        return false;
    }
    return http == 200;
}

/// Resolve a pinned origin for @p peer. Keeps a working Tailscale/CGNAT route
/// when LAN is announced but unreachable; retries LAN on a cooldown.
inline bool route_for(const Peer& peer, std::string& url, std::string& err, bool* refused_out = nullptr)
{
    if (!pin_ok(peer.tls_fp)) {
        err = "This phone has no certificate pin.";
        return false;
    }
    if (peer.urls.empty()) {
        err = "The phone has not allowed this computer on any network.";
        if (refused_out)
            *refused_out = true;
        return false;
    }

    const bool have_lan = std::any_of(peer.urls.begin(), peer.urls.end(), url_looks_lan);
    std::unique_lock lock(route_mutex());

    {
        RouteState* st = &routes()[peer.id];
        if (!st->active_url.empty() && announced(peer, st->active_url)) {
            const auto now = std::chrono::steady_clock::now();
            const bool reconsider_lan =
                have_lan && !url_looks_lan(st->active_url) && now >= st->next_lan_probe;
            if (!reconsider_lan) {
                url = st->active_url;
                return true;
            }
            // Keep active; probe LAN without dropping it.
            lock.unlock();
            std::string lan_hit;
            for (const auto& candidate : peer.urls) {
                if (!url_looks_lan(candidate))
                    continue;
                long http = 0;
                std::string probe_err;
                bool one_refused = false;
                if (probe_url(peer, candidate, http, one_refused, probe_err)) {
                    lan_hit = candidate;
                    break;
                }
            }
            lock.lock();
            st = &routes()[peer.id];
            if (!lan_hit.empty()) {
                st->active_url = std::move(lan_hit);
                ++st->generation;
                st->next_lan_probe = {};
                url = st->active_url;
                route_cv().notify_all();
                return true;
            }
            st->next_lan_probe = std::chrono::steady_clock::now() + k_lan_probe_cooldown;
            if (!st->active_url.empty() && announced(peer, st->active_url)) {
                url = st->active_url;
                return true;
            }
            // Active was revoked while we probed — fall through to discovery.
        }
    }

    for (;;) {
        RouteState* st = &routes()[peer.id];
        if (!st->active_url.empty() && announced(peer, st->active_url)) {
            url = st->active_url;
            return true;
        }
        if (!st->resolving)
            break;
        route_cv().wait(lock);
    }
    routes()[peer.id].resolving = true;
    lock.unlock();

    std::vector<std::string> ordered = peer.urls;
    std::stable_sort(ordered.begin(), ordered.end(), [](const std::string& a, const std::string& b) {
        return url_looks_lan(a) && !url_looks_lan(b);
    });
    bool refused = false;
    std::string found;
    for (const auto& candidate : ordered) {
        if (candidate.rfind("https://", 0) != 0)
            continue;
        long http = 0;
        std::string probe_err;
        bool one_refused = false;
        if (!probe_url(peer, candidate, http, one_refused, probe_err)) {
            refused = refused || one_refused;
            continue;
        }
        found = candidate;
        break;
    }

    lock.lock();
    RouteState& st = routes()[peer.id];
    st.resolving = false;
    if (!found.empty()) {
        st.active_url = std::move(found);
        ++st.generation;
        st.next_lan_probe = {};
        url = st.active_url;
        route_cv().notify_all();
        return true;
    }
    route_cv().notify_all();
    if (refused)
        err = "The phone does not allow this computer on this network.";
    else
        err = "The phone is not reachable. Open Tanit on the phone.";
    if (refused_out)
        *refused_out = refused;
    return false;
}

inline std::string json_string(const nlohmann::json& obj, const char* key)
{
    if (!obj.is_object() || !obj.contains(key) || !obj[key].is_string())
        return {};
    return obj[key].get<std::string>();
}

inline std::optional<std::int64_t> json_int64(const nlohmann::json& obj, const char* key)
{
    if (!obj.is_object() || !obj.contains(key) || !obj[key].is_number_integer())
        return std::nullopt;
    return obj[key].get<std::int64_t>();
}

inline std::optional<std::uint64_t> json_uint64(const nlohmann::json& obj, const char* key)
{
    if (!obj.is_object() || !obj.contains(key))
        return std::nullopt;
    const auto& v = obj[key];
    // nlohmann stores small positives as signed integers; reject negatives and floats.
    if (v.is_number_unsigned())
        return v.get<std::uint64_t>();
    if (v.is_number_integer()) {
        const auto n = v.get<std::int64_t>();
        if (n < 0)
            return std::nullopt;
        return static_cast<std::uint64_t>(n);
    }
    return std::nullopt;
}

inline bool entry_name_ok(std::string_view name) noexcept
{
    if (name.empty() || name == "." || name == "..")
        return false;
    if (name.find('/') != std::string_view::npos || name.find('\\') != std::string_view::npos
        || name.find('\0') != std::string_view::npos || name.find(':') != std::string_view::npos)
        return false;
    return true;
}

/// Text for a refusal, and the VFS grant the phone reported with it.
inline std::string refusal_text(const std::string& device, const std::string& body, long http)
{
    std::string code;
    std::string message;
    try {
        const nlohmann::json json = nlohmann::json::parse(body, nullptr, false);
        if (json.is_object()) {
            code = json_string(json, "code");
            message = json_string(json, "error");
            // Only `vfs_revision` advances the folder cache. Global `revision`
            // is the whole devices.json generation.
            if (const auto vfs_rev = json_int64(json, "vfs_revision")) {
                if (*vfs_rev > 0)
                    note_grant(device, static_cast<int>(*vfs_rev), json_string(json, "vfs"));
            }
        }
    } catch (const std::exception&) {
        // Malformed refusal body — keep the HTTP status message.
    }
    if (http == 401)
        return "This phone no longer accepts this computer. Add it again under Shared folders on the phone.";
    if (code == "EGRANT")
        return "Folder access for this computer is off on the phone.";
    if (code == "ENETWORK")
        return "The phone does not allow this computer on this network.";
    return message.empty() ? "phone vfs HTTP " + std::to_string(http) : message;
}

inline bool transport_failed(bool got, long http, std::string_view err) noexcept
{
    if (!got)
        return true;
    (void)http;
    (void)err;
    return false;
}

/// @p refused is set when the phone answered and said no: the pair is gone,
/// the permission is off, or this network is not granted. An unreachable
/// phone leaves it false.
inline bool get_path(std::string_view device, const std::string& path, long& http, std::string& body,
                     std::string& err, bool* refused = nullptr)
{
    if (refused)
        *refused = false;
    const auto peer = find_peer(device);
    if (!peer) {
        err = "This phone is not sharing its folders with this computer.";
        return false;
    }
    if (peer->token.empty()) {
        err = "This phone has not sent this computer a key yet. Open Tanit on the phone.";
        return false;
    }
    const std::string token = peer->token;
    std::string base;
    if (!route_for(*peer, base, err, refused))
        return false;
    const auto net =
        net_request(*peer, base, path, token, 20'000L, 8'000L);
    const bool got = net.got;
    http = net.http;
    body = net.body;
    err = net.err;
    logger::debug(std::string("[phone-vfs] GET ") + base + path + " http=" + std::to_string(http)
                  + (err.empty() ? std::string{} : " err=" + err));
    if (transport_failed(got, http, err))
        forget_route_if(peer->id, base);
    else if (http == 401)
        drop_token_if_matches(peer->id, token);
    if (got && refused)
        *refused = http == 401 || http == 403;
    return got;
}

inline bool post_json(std::string_view device, const std::string& path, const std::string& json_body,
                      long& http, std::string& body, std::string& err)
{
    const auto peer = find_peer(device);
    if (!peer) {
        err = "This phone is not sharing its folders with this computer.";
        return false;
    }
    if (peer->token.empty()) {
        err = "This phone has not sent this computer a key yet. Open Tanit on the phone.";
        return false;
    }
    const std::string token = peer->token;
    std::string base;
    if (!route_for(*peer, base, err))
        return false;
    const auto net = net_request(*peer, base, path, token, 120'000L, 30'000L, "POST", json_body,
                                 "application/json");
    const bool got = net.got;
    http = net.http;
    body = net.body;
    err = net.err;
    logger::debug(std::string("[phone-vfs] POST ") + base + path + " http=" + std::to_string(http)
                  + (err.empty() ? std::string{} : " err=" + err));
    if (transport_failed(got, http, err))
        forget_route_if(peer->id, base);
    else if (http == 401)
        drop_token_if_matches(peer->id, token);
    return got;
}

inline bool put_bytes(std::string_view device, const std::string& path, const void* data, std::size_t size,
                      long& http, std::string& body, std::string& err)
{
    const auto peer = find_peer(device);
    if (!peer) {
        err = "This phone is not sharing its folders with this computer.";
        return false;
    }
    if (peer->token.empty()) {
        err = "This phone has not sent this computer a key yet. Open Tanit on the phone.";
        return false;
    }
    const std::string token = peer->token;
    std::string base;
    if (!route_for(*peer, base, err))
        return false;
    pm::commons::net::Request req;
    req.method = "PUT";
    req.url = join_origin_path(base, path);
    req.bearer = token;
    req.spki_sha256_hex = peer->tls_fp;
    req.timeout_ms = 60'000L;
    req.connect_timeout_ms = 30'000L;
    if (size != 0 && data != nullptr)
        req.body.assign(static_cast<const char*>(data), size);
    const auto resp = pm::commons::net::request(req);
    const bool got = resp.ok;
    http = resp.status;
    body = resp.body;
    err = resp.error;
    logger::debug(std::string("[phone-vfs] PUT ") + base + path + " http=" + std::to_string(http)
                  + (err.empty() ? std::string{} : " err=" + err));
    if (transport_failed(got, http, err))
        forget_route_if(peer->id, base);
    else if (http == 401)
        drop_token_if_matches(peer->id, token);
    return got;
}

} // namespace detail

/// What the phone currently allows this computer. `vfs` is off, read, or write.
struct GrantResult {
    bool ok = false;
    int revision = 0;
    std::string vfs;
    std::string err;
};

[[nodiscard]] inline GrantResult grant(std::string_view device)
{
    GrantResult out;
    long http = 0;
    std::string body;
    if (!detail::get_path(device, "/v1/lan/grant", http, body, out.err)) {
        logger::info(std::string("[phone-vfs] grant failed ") + std::string(device) + " err="
                     + (out.err.empty() ? "unreachable" : out.err));
        return out;
    }
    if (http < 200 || http >= 300) {
        out.err = detail::refusal_text(std::string(device), body, http);
        logger::info(std::string("[phone-vfs] grant refused ") + std::string(device)
                     + " http=" + std::to_string(http) + " err=" + out.err);
        return out;
    }
    try {
        const nlohmann::json json = nlohmann::json::parse(body, nullptr, false);
        if (!json.is_object() || !json.contains("grant") || !json["grant"].is_object()) {
            out.err = "The phone sent no grant.";
            logger::info(std::string("[phone-vfs] grant failed ") + std::string(device)
                         + " err=" + out.err);
            return out;
        }
        const auto& g = json["grant"];
        // Only `vfs_revision` advances the folder cache. Global `revision` is
        // the whole devices.json generation and must not be used as a fallback.
        if (const auto vfs_rev = detail::json_int64(g, "vfs_revision")) {
            if (*vfs_rev > 0 && *vfs_rev <= static_cast<std::int64_t>(std::numeric_limits<int>::max()))
                out.revision = static_cast<int>(*vfs_rev);
        }
        out.vfs = detail::json_string(g, "vfs");
        if (out.vfs.empty())
            out.vfs = "off";
        detail::note_grant(device, out.revision, out.vfs);
        out.ok = true;
        logger::info(std::string("[phone-vfs] grant ") + std::string(device) + " vfs=" + out.vfs
                     + " rev=" + std::to_string(out.revision));
    } catch (const std::exception& ex) {
        out.err = ex.what();
        logger::info(std::string("[phone-vfs] grant failed ") + std::string(device) + " err="
                     + out.err);
    }
    return out;
}

[[nodiscard]] inline MountsResult mounts(std::string_view device)
{
    MountsResult out;
    long http = 0;
    std::string body;
    if (!detail::get_path(device, "/v1/vfs/mounts", http, body, out.err, &out.refused)) {
        logger::info(std::string("[phone-vfs] mounts failed ") + std::string(device) + " err="
                     + (out.err.empty() ? "unreachable" : out.err));
        return out;
    }
    if (http < 200 || http >= 300) {
        out.err = detail::refusal_text(std::string(device), body, http);
        logger::info(std::string("[phone-vfs] mounts refused ") + std::string(device)
                     + " http=" + std::to_string(http) + " err=" + out.err);
        return out;
    }
    try {
        const auto json = nlohmann::json::parse(body, nullptr, false);
        if (!json.is_object() || !json.contains("mounts") || !json["mounts"].is_array()) {
            out.err = "The phone sent no mount list.";
            return out;
        }
        for (const auto& row : json["mounts"]) {
            if (!row.is_object())
                continue;
            Mount mount;
            mount.name = detail::json_string(row, "name");
            mount.label = detail::json_string(row, "label");
            if (mount.label.empty())
                mount.label = mount.name;
            mount.host = detail::json_string(row, "host");
            mount.uri = detail::json_string(row, "uri");
            mount.can = client_can(row.contains("can") ? row["can"] : nlohmann::json());
            // A phone answers for its own folders only.
            if (mount.name.empty() || !path_components_ok(mount.name) || mount.host != device)
                continue;
            out.mounts.push_back(std::move(mount));
        }
        out.ok = true;
        logger::info(std::string("[phone-vfs] mounts ") + std::string(device) + " n="
                     + std::to_string(out.mounts.size()));
    } catch (const std::exception& ex) {
        out.err = ex.what();
    }
    return out;
}

[[nodiscard]] inline ListResult list(std::string_view device, std::string_view browse_path)
{
    ListResult out;
    std::string mount;
    std::string rel;
    if (!split(device, browse_path, mount, rel)) {
        out.err = "Open a shared folder on the phone.";
        return out;
    }
    std::string path = "/v1/vfs/list";
    path = detail::append_query_param(path, "mount", mount);
    path = detail::append_query_param(path, "path", rel);
    long http = 0;
    std::string body;
    if (!detail::get_path(device, path, http, body, out.err)) {
        logger::info(std::string("[phone-vfs] list failed ") + std::string(device) + "/"
                     + std::string(browse_path) + " err="
                     + (out.err.empty() ? "unreachable" : out.err));
        return out;
    }
    if (http < 200 || http >= 300) {
        out.err = detail::refusal_text(std::string(device), body, http);
        logger::info(std::string("[phone-vfs] list refused ") + std::string(device) + "/"
                     + std::string(browse_path) + " http=" + std::to_string(http)
                     + " err=" + out.err);
        return out;
    }
    try {
        const auto json = nlohmann::json::parse(body, nullptr, false);
        if (!json.is_object()) {
            out.err = "The phone sent an invalid directory listing.";
            return out;
        }
        out.can = client_can(json.contains("can") ? json["can"] : nlohmann::json());
        if (!json.contains("entries") || !json["entries"].is_array()) {
            out.err = "The phone sent no directory entries.";
            return out;
        }
        for (const auto& row : json["entries"]) {
            if (!row.is_object())
                continue;
            Entry entry;
            entry.name = detail::json_string(row, "name");
            if (!detail::entry_name_ok(entry.name))
                continue;
            entry.is_dir = detail::json_string(row, "type") == "dir";
            if (const auto size = detail::json_uint64(row, "size"))
                entry.size = *size;
            if (const auto mtime = detail::json_int64(row, "mtime"))
                entry.mtime_ms = *mtime;
            entry.mime = detail::json_string(row, "mime");
            out.entries.push_back(std::move(entry));
        }
        out.ok = true;
        logger::info(std::string("[phone-vfs] list ") + std::string(device) + "/"
                     + std::string(browse_path) + " entries=" + std::to_string(out.entries.size()));
    } catch (const std::exception& ex) {
        out.err = ex.what();
    }
    return out;
}

[[nodiscard]] inline StatResult stat(std::string_view device, std::string_view browse_path)
{
    StatResult out;
    std::string mount;
    std::string rel;
    if (!split(device, browse_path, mount, rel)) {
        out.err = "Invalid phone vfs location.";
        return out;
    }
    std::string path = "/v1/vfs/stat";
    path = detail::append_query_param(path, "mount", mount);
    path = detail::append_query_param(path, "path", rel);
    long http = 0;
    std::string body;
    if (!detail::get_path(device, path, http, body, out.err))
        return out;
    if (http == 404) {
        out.ok = true;
        return out;
    }
    if (http < 200 || http >= 300) {
        out.err = detail::refusal_text(std::string(device), body, http);
        return out;
    }
    try {
        const auto json = nlohmann::json::parse(body, nullptr, false);
        if (!json.is_object() || !json.contains("node") || !json["node"].is_object()) {
            out.err = "The phone sent no file info.";
            return out;
        }
        const auto& node = json["node"];
        const std::string type = detail::json_string(node, "type");
        if (type != "dir" && type != "file") {
            out.err = "The phone sent an unsupported node type.";
            return out;
        }
        out.ok = true;
        out.exists = true;
        out.is_dir = type == "dir";
        if (const auto size = detail::json_uint64(node, "size"))
            out.size = *size;
    } catch (const std::exception& ex) {
        out.ok = false;
        out.err = ex.what();
    }
    return out;
}

[[nodiscard]] inline ReadResult read_to_file(
    std::string_view device,
    std::string_view browse_path,
    const std::filesystem::path& dest,
    ReadOptions options = {})
{
    ReadResult out;
    std::string mount;
    std::string rel;
    if (!split(device, browse_path, mount, rel) || rel.empty()) {
        out.err = "Phone copy needs a file inside a shared folder.";
        return out;
    }
    const auto peer = detail::find_peer(device);
    if (!peer) {
        out.err = "This phone is not sharing its folders with this computer.";
        return out;
    }
    if (peer->token.empty()) {
        out.err = "This phone has not sent this computer a key yet. Open Tanit on the phone.";
        return out;
    }
    const std::string token = peer->token;
    std::string base;
    if (!detail::route_for(*peer, base, out.err))
        return out;
    std::string path = "/v1/vfs/read";
    path = detail::append_query_param(path, "mount", mount);
    path = detail::append_query_param(path, "path", rel);
    pm::commons::net::Request req;
    req.method = "GET";
    req.url = detail::join_origin_path(base, path);
    req.bearer = token;
    req.spki_sha256_hex = peer->tls_fp;
    req.timeout_ms = 0;
    req.connect_timeout_ms = 5'000L;
    req.max_bytes = k_max_read;
    req.cancel = std::move(options.cancel);
    pm::commons::net::FileOptions file_opts;
    if (options.expected_size)
        file_opts.expected_size = *options.expected_size;
    file_opts.on_progress = std::move(options.on_progress);
    logger::info(std::string("[phone-vfs] GET-FILE ") + req.url);
    const auto resp = pm::commons::net::request_to_file(req, dest, std::move(file_opts));
    const long http = resp.status;
    const bool transport_ok = resp.ok;
    const bool http_ok = transport_ok && http >= 200 && http < 300;
    if (!http_ok) {
        std::error_code remove_ec;
        std::filesystem::remove(dest, remove_ec);
        // Only transport failures clear the route. Cancel, HTTP refusals, size
        // caps and local I/O leave a working address alone.
        if (!transport_ok && http == 0 && resp.error.rfind("curl_easy_perform:", 0) == 0)
            detail::forget_route_if(peer->id, base);
        if (http == 401)
            detail::drop_token_if_matches(peer->id, token);
        if (http == 401 || http == 403) {
            // Refusal body was discarded by the file sink; use the status text.
            out.err = detail::refusal_text(std::string(device), {}, http);
        } else {
            out.err = resp.error.empty() ? "phone read failed" : resp.error;
        }
        logger::info(std::string("[phone-vfs] GET-FILE failed http=") + std::to_string(http)
                     + " err=" + out.err);
        return out;
    }
    out.ok = true;
    std::error_code size_ec;
    out.bytes = std::filesystem::file_size(dest, size_ec);
    if (size_ec)
        out.bytes = file_opts.expected_size;
    logger::info(std::string("[phone-vfs] GET-FILE ok http=") + std::to_string(http)
                 + " bytes=" + std::to_string(out.bytes));
    return out;
}

[[nodiscard]] inline OpResult mkdir(std::string_view device, std::string_view browse_path)
{
    OpResult out;
    std::string mount;
    std::string rel;
    if (!split(device, browse_path, mount, rel) || rel.empty()) {
        out.err = "Phone mkdir needs a folder inside a shared folder.";
        return out;
    }
    const nlohmann::json body{{"mount", mount}, {"path", rel}};
    long http = 0;
    std::string response;
    if (!detail::post_json(device, "/v1/vfs/mkdir", body.dump(), http, response, out.err))
        return out;
    if (http < 200 || http >= 300) {
        out.err = detail::refusal_text(std::string(device), response, http);
        return out;
    }
    out.ok = true;
    return out;
}

[[nodiscard]] inline OpResult write_bytes(std::string_view device, std::string_view browse_path,
                                          const void* data, std::size_t size)
{
    OpResult out;
    std::string mount;
    std::string rel;
    if (!split(device, browse_path, mount, rel) || rel.empty()) {
        out.err = "Phone write needs a file inside a shared folder.";
        return out;
    }
    if (size != 0 && data == nullptr) {
        out.err = "Invalid write buffer.";
        return out;
    }
    if (size > k_max_write) {
        out.err = "Phone write is larger than 8 MiB.";
        return out;
    }
    std::string path = "/v1/vfs/write";
    path = detail::append_query_param(path, "mount", mount);
    path = detail::append_query_param(path, "path", rel);
    long http = 0;
    std::string response;
    if (!detail::put_bytes(device, path, data, size, http, response, out.err))
        return out;
    if (http < 200 || http >= 300) {
        out.err = detail::refusal_text(std::string(device), response, http);
        return out;
    }
    out.ok = true;
    return out;
}

/// Create an empty file if missing, or bump mtime if it exists. Never truncates.
[[nodiscard]] inline OpResult touch(std::string_view device, std::string_view browse_path)
{
    OpResult out;
    std::string mount;
    std::string rel;
    if (!split(device, browse_path, mount, rel) || rel.empty()) {
        out.err = "Phone touch needs a file inside a shared folder.";
        return out;
    }
    const nlohmann::json body{{"mount", mount}, {"path", rel}};
    long http = 0;
    std::string response;
    if (!detail::post_json(device, "/v1/vfs/touch", body.dump(), http, response, out.err))
        return out;
    if (http < 200 || http >= 300) {
        out.err = detail::refusal_text(std::string(device), response, http);
        return out;
    }
    out.ok = true;
    return out;
}

[[nodiscard]] inline OpResult remove(std::string_view device, std::string_view browse_path, bool recursive = false)
{
    OpResult out;
    std::string mount;
    std::string rel;
    if (!split(device, browse_path, mount, rel) || rel.empty()) {
        out.err = "Refusing to delete a phone shared-folder root.";
        return out;
    }
    const nlohmann::json body{{"mount", mount}, {"path", rel}, {"recursive", recursive}};
    long http = 0;
    std::string response;
    if (!detail::post_json(device, "/v1/vfs/delete", body.dump(), http, response, out.err))
        return out;
    if (http < 200 || http >= 300) {
        out.err = detail::refusal_text(std::string(device), response, http);
        return out;
    }
    out.ok = true;
    return out;
}

/// Same-phone relocate (rename or move). Both paths are browse paths under the
/// device mount (`<shared>/<rel>`).
[[nodiscard]] inline OpResult move(std::string_view device, std::string_view from_browse,
                                   std::string_view to_browse)
{
    OpResult out;
    std::string from_mount;
    std::string from_rel;
    std::string to_mount;
    std::string to_rel;
    if (!split(device, from_browse, from_mount, from_rel) || from_rel.empty()
        || !split(device, to_browse, to_mount, to_rel) || to_rel.empty()) {
        out.err = "Phone move needs a file or folder inside a shared folder.";
        return out;
    }
    const nlohmann::json body{{"mount", from_mount},
                              {"path", from_rel},
                              {"toMount", to_mount},
                              {"toPath", to_rel}};
    long http = 0;
    std::string response;
    if (!detail::post_json(device, "/v1/vfs/move", body.dump(), http, response, out.err))
        return out;
    if (http < 200 || http >= 300) {
        out.err = detail::refusal_text(std::string(device), response, http);
        return out;
    }
    out.ok = true;
    return out;
}

// Dial-book surface (formerly src/vfs/phone_peers.hpp). Ensures desktop hooks
// before every PeerBook call so Tanit UI/CLI can keep `pm::vfs::phone::*`.

[[nodiscard]] inline bool pin_ok(const std::string& pin)
{
    return detail::pin_ok(pin);
}

[[nodiscard]] inline bool url_ok(const std::string& url)
{
    if (url.size() > 200 || url.rfind("https://", 0) != 0)
        return false;
    for (unsigned char c : url) {
        if (c <= 0x20 || c == 0x7f || c == '"' || c == '\\')
            return false;
    }
    return true;
}

[[nodiscard]] inline bool is_device_mount(std::string_view mount) noexcept
{
    return pm::node::is_device_mount(mount);
}

[[nodiscard]] inline bool seal_dial_token(const std::string& token, std::string& stored, std::string& err)
{
    detail::ensure_dial_book();
    return pm::node::seal_dial_token(token, stored, err);
}

[[nodiscard]] inline std::string open_dial_token(const std::string& stored)
{
    detail::ensure_dial_book();
    return pm::node::open_dial_token(stored);
}

[[nodiscard]] inline std::vector<Peer> peers()
{
    detail::ensure_dial_book();
    return pm::node::peers();
}

[[nodiscard]] inline std::optional<Peer> find_peer(std::string_view authority)
{
    return detail::find_peer(authority);
}

inline bool store_peer(std::string_view authority, const std::string& name,
                       const std::vector<std::string>& urls, const std::string& token,
                       const std::string& tls_fp, const std::string& owner, bool& holds_token,
                       std::string& err)
{
    detail::ensure_dial_book();
    return pm::node::store_peer(authority, name, urls, token, tls_fp, owner, holds_token, err);
}

inline void drop_token(std::string_view authority)
{
    detail::ensure_dial_book();
    pm::node::drop_token(authority);
}

inline void drop_token_if_matches(std::string_view authority, std::string_view expected)
{
    detail::drop_token_if_matches(authority, expected);
}

inline void note_grant(std::string_view authority, int revision, const std::string& vfs)
{
    detail::note_grant(authority, revision, vfs);
}

inline std::filesystem::path mounts_cache_file()
{
    detail::ensure_dial_book();
    return pm::node::mounts_cache_file();
}

inline void forget_revoked_device(std::string_view id)
{
    detail::ensure_dial_book();
    pm::node::forget_revoked_device(id);
}

inline bool forget_peer(std::string_view authority, std::string& err)
{
    detail::ensure_dial_book();
    return pm::node::forget_peer(authority, err);
}

} // namespace pm::vfs::phone
