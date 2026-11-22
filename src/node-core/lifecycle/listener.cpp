// The paired-peer listener. Portable: the Android host and the desktop test
// host both start this file. It does not read the environment.

#include "pm/node/peer_listener.hpp"
#include "pm/node/listener_tls.hpp"

#include "lan/mesh_consent.hpp"
#include "pm/server/features.hpp"
#include "pm/server/secret.hpp"
#include "pm/server/vfs.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "string/string_utils.hpp"

#include <atomic>
#include <chrono>
#include <fstream>
#include <mutex>
#include <thread>
#if defined(_WIN32)
#include <bcrypt.h>
#endif
#include <utility>

namespace pm::node {

/// The TLS front tells the loopback server which interface accepted the call.
/// A header from anywhere else is ignored.
std::string arrived_on(const httplib::Request& req)
{
    const bool loopback = req.remote_addr == "127.0.0.1" || req.remote_addr == "::1";
    if (loopback) {
        const std::string value = req.get_header_value("X-Tanit-Arrived");
        if (!value.empty() && value.size() <= 64 && value.find(' ') == std::string::npos
            && value.find(':') == std::string::npos)
            return value;
    }
    return req.local_addr;
}

namespace {

void send(httplib::Response& res, int status, const nlohmann::json& body)
{
    res.status = status;
    res.set_content(body.dump(), "application/json; charset=utf-8");
}

nlohmann::json refusal(const char* code, const std::string& message)
{
    return {{"ok", false}, {"code", code}, {"error", message}};
}

struct Shared {
    PeerListenerHost host;
    pm::lan::PairStore store;

    explicit Shared(PeerListenerHost h) : host(std::move(h)), store(host.pair_file) {}

    void note(bool warn, const std::string& line) const
    {
        if (host.log)
            host.log(warn, line);
    }

    std::string where(const httplib::Request& req) const
    {
        std::string line = "[phone-vfs] " + req.method + " " + req.path;
        const std::string mount = req.get_param_value("mount");
        if (!mount.empty())
            line += " mount=" + mount;
        line += " from=" + req.remote_addr + " on=" + arrived_on(req);
        return line;
    }

    /// Steps 2 and 3 of the header comment. Fills @p peer on success.
    bool admit(const httplib::Request& req, httplib::Response& res, pm::lan::Peer& peer) const
    {
        const pm::lan::Access access = store.authorize(pm::server::request_bearer(req));
        if (access.verdict != pm::lan::Verdict::Paired) {
            note(true, where(req) + (access.verdict == pm::lan::Verdict::Revoked
                                         ? " deny revoked peer=" + access.peer.id
                                         : std::string(" deny unknown token")));
            send(res, 401, refusal("EPAIR", "This device is not paired. Pair again."));
            return false;
        }
        peer = access.peer;
        if (!pm::lan::network_granted(peer.allow_peer, arrived_on(req))) {
            note(true, where(req) + " deny network peer=" + peer.id);
            nlohmann::json body = refusal("ENETWORK", "This network is not granted to this device.");
            body["revision"] = peer.allow_peer.revision;
            body["vfs"] = pm::lan::vfs_grant_name(peer.allow_peer.vfs);
            send(res, 403, body);
            return false;
        }
        note(false, where(req) + " ok peer=" + peer.id);
        return true;
    }
};

} // namespace

int reserve_loopback_port()
{
#if defined(_WIN32)
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET)
        return 0;
#else
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    int port = 0;
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0) {
#if defined(_WIN32)
        int len = sizeof addr;
#else
        socklen_t len = sizeof addr;
#endif
        if (getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0)
            port = ntohs(addr.sin_port);
    }
#if defined(_WIN32)
    closesocket(fd);
#else
    close(fd);
#endif
    return port;
}

struct PeerListener::Impl {
    mutable std::mutex mu;
    std::shared_ptr<httplib::Server> server;
    std::thread thread;
    std::thread watch;
    std::atomic<bool> watch_stop{false};
    PhoneTls* tls = nullptr;
    std::string pin;
    int port = 0;
    std::atomic<bool> pair_open{false};
    std::string pair_secret;
    std::chrono::steady_clock::time_point pair_expires{};
    int pair_failures = 0;
    std::chrono::steady_clock::time_point pair_locked{};
};

bool fill_random(std::uint8_t* out, std::size_t n)
{
#if defined(_WIN32)
    return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, out, static_cast<ULONG>(n),
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG));
#else
    std::ifstream in("/dev/urandom", std::ios::binary);
    if (!in)
        return false;
    in.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(n));
    return in.gcount() == static_cast<std::streamsize>(n);
#endif
}

bool same_secret(std::string_view a, std::string_view b)
{
    unsigned diff = static_cast<unsigned>(a.size() ^ b.size());
    const std::size_t n = a.size() < b.size() ? a.size() : b.size();
    for (std::size_t i = 0; i < n; ++i)
        diff |= static_cast<unsigned>(a[i]) ^ static_cast<unsigned>(b[i]);
    return diff == 0;
}

std::string query_encode(std::string_view text)
{
    std::string out;
    for (unsigned char c : text) {
        const bool plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || c == '-' || c == '_' || c == '.' || c == '~';
        if (plain) {
            out.push_back(static_cast<char>(c));
            continue;
        }
        static const char* hex = "0123456789ABCDEF";
        out.push_back('%');
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0F]);
    }
    return out;
}

void push_address(std::vector<std::string>& out, const std::string& address)
{
    if (address.empty() || address == "0.0.0.0" || address.find(':') != std::string::npos)
        return;
    for (const auto& have : out) {
        if (have == address)
            return;
    }
    out.push_back(address);
}

std::vector<std::string> granted_addresses(const PeerListenerHost& host, const pm::lan::PairStore& store)
{
    std::vector<LocalNetwork> nets;
    if (host.networks)
        nets = host.networks();
    else if (!host.bind_host.empty() && host.bind_host != "0.0.0.0") {
        LocalNetwork one;
        one.address = host.bind_host;
        one.kind = "local";
        one.name = "test";
        nets.push_back(std::move(one));
    }
    std::vector<pm::lan::Peer> rows;
    std::string err;
    if (!store.load(rows, err))
        return {};
    std::vector<std::string> out;
    for (const auto& net : nets) {
        if (net.address.empty() || net.address == "0.0.0.0")
            continue;
        bool granted = false;
        for (const auto& row : rows) {
            if (row.trust == pm::lan::Trust::Paired && pm::lan::network_granted(row.allow_peer, net.address))
                granted = true;
        }
        if (!granted)
            continue;
        bool seen = false;
        for (const auto& have : out)
            seen = seen || have == net.address;
        if (!seen)
            out.push_back(net.address);
    }
    return out;
}

/// While a pairing window is open, Wi-Fi and Ethernet accept the ticket.
/// A granted address stays. Mobile data does not.
std::vector<std::string> listen_addresses(const PeerListenerHost& host, const pm::lan::PairStore& store,
                                          bool pairing)
{
    std::vector<std::string> out = granted_addresses(host, store);
    if (!pairing || !host.networks)
        return out;
    for (const auto& net : host.networks()) {
        if (net.kind == "mobile")
            continue;
        push_address(out, net.address);
    }
    return out;
}

PeerListener::PeerListener() : impl_(std::make_unique<Impl>()) {}

PeerListener::~PeerListener()
{
    stop();
}

bool PeerListener::listening() const
{
    std::lock_guard<std::mutex> lock(impl_->mu);
    return impl_->server != nullptr;
}

int PeerListener::port() const
{
    std::lock_guard<std::mutex> lock(impl_->mu);
    return impl_->port;
}

std::string PeerListener::pin() const
{
    std::lock_guard<std::mutex> lock(impl_->mu);
    return impl_->pin;
}

bool PeerListener::pairing() const
{
    return impl_->pair_open.load();
}

bool PeerListener::open_pair_window(const std::string& name, const std::string& host, std::string& uri,
                                    std::string& err)
{
    uri.clear();
    err.clear();
    std::uint8_t raw[16];
    if (!fill_random(raw, sizeof raw)) {
        err = "could not open a pairing window";
        return false;
    }
    const std::string secret = "tp1_" + media::strutil::base64url(raw, sizeof raw);
    std::string pin;
    int port = 0;
    {
        std::lock_guard<std::mutex> lock(impl_->mu);
        if (!impl_->server || impl_->pin.size() != 64 || impl_->port <= 0) {
            err = "this phone is not listening";
            return false;
        }
        const auto now = std::chrono::steady_clock::now();
        if (impl_->pair_failures >= 8 && now < impl_->pair_locked) {
            err = "too many pairing attempts";
            return false;
        }
        impl_->pair_secret = secret;
        impl_->pair_open = true;
        impl_->pair_expires = now + std::chrono::seconds(300);
        pin = impl_->pin;
        port = impl_->port;
    }
    std::string label = name;
    std::string link = "tanit://pair?v=1&host=" + host + "&port=" + std::to_string(port)
        + "&fp=" + pin + "&secret=" + secret + "&name=" + query_encode(label);
    while (link.size() > 200 && !label.empty()) {
        label.pop_back();
        link = "tanit://pair?v=1&host=" + host + "&port=" + std::to_string(port)
            + "&fp=" + pin + "&secret=" + secret + "&name=" + query_encode(label);
    }
    if (link.size() > 200) {
        std::lock_guard<std::mutex> lock(impl_->mu);
        impl_->pair_open = false;
        impl_->pair_secret.clear();
        err = "the pairing code does not fit";
        return false;
    }
    uri = link;
    return true;
}

void PeerListener::close_pair_window()
{
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->pair_open = false;
    impl_->pair_secret.clear();
}

void PeerListener::stop()
{
    impl_->watch_stop.store(true);
    std::shared_ptr<httplib::Server> server;
    std::thread thread;
    std::thread watch;
    PhoneTls* tls = nullptr;
    {
        std::lock_guard<std::mutex> lock(impl_->mu);
        watch = std::move(impl_->watch);
        tls = impl_->tls;
        impl_->tls = nullptr;
        server = std::move(impl_->server);
        thread = std::move(impl_->thread);
        impl_->port = 0;
        impl_->pair_open = false;
        impl_->pair_secret.clear();
    }
    if (watch.joinable())
        watch.join();
    phone_tls_close(tls);
    if (server)
        server->stop();
    if (thread.joinable())
        thread.join();
}

bool PeerListener::start(PeerListenerHost host, std::string& err)
{
    stop();
    if (!media_cli::vfs_authority_valid(host.authority)) {
        err = "this device has no vfs name";
        return false;
    }
    if (host.pair_file.empty()) {
        err = "this device has no pair file";
        return false;
    }
    if (host.port_first <= 0 || host.port_last < host.port_first || host.port_last > 65535) {
        err = "the listener port range is not valid";
        return false;
    }
    const auto shared = std::make_shared<const Shared>(std::move(host));

    auto server = std::make_shared<httplib::Server>();
    server->set_payload_max_length(9u * 1024u * 1024u);
    server->new_task_queue = [] { return new httplib::ThreadPool(4); };

    // Step 1. A network nobody was granted learns nothing, not even the name.
    server->set_pre_routing_handler([shared](const httplib::Request& req, httplib::Response& res) {
        if (shared->host.enter)
            shared->host.enter();
        if (req.method == "POST" && req.path == "/v1/lan/pair")
            return httplib::Server::HandlerResponse::Unhandled;
        if (!shared->store.any_peer_on(arrived_on(req))) {
            shared->note(true, shared->where(req) + " deny network");
            send(res, 403, refusal("ENETWORK", "This network is not granted."));
            return httplib::Server::HandlerResponse::Handled;
        }
        if (req.path.rfind("/v1/", 0) == 0
            && !pm::server::route_enabled(pm::server::phone_features(), req.path)) {
            send(res, 404, refusal("ENOTFOUND", "That route is not on this device."));
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    server->Post("/v1/lan/pair", [this, shared](const httplib::Request& req, httplib::Response& res) {
        const nlohmann::json body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
        if (!body.is_object()) {
            send(res, 400, refusal("EBODY", "The announce is not valid."));
            return;
        }
        const std::string secret = body.value("secret", std::string{});
        const std::string device_id = body.value("device_id", std::string{});
        const std::string device_name = body.value("device_name", std::string{});
        bool mismatch = false;
        {
            std::lock_guard<std::mutex> lock(impl_->mu);
            const auto now = std::chrono::steady_clock::now();
            if (!impl_->pair_open) {
                send(res, 404, refusal("EPAIR", "No pairing window is open."));
                return;
            }
            if (now >= impl_->pair_expires) {
                impl_->pair_open = false;
                impl_->pair_secret.clear();
                send(res, 410, refusal("EPAIR", "The pairing window expired."));
                return;
            }
            if (impl_->pair_failures >= 8 && now < impl_->pair_locked) {
                res.set_header("Retry-After", "30");
                send(res, 429, refusal("EPAIR", "Too many pairing attempts."));
                return;
            }
            if (!same_secret(secret, impl_->pair_secret)) {
                ++impl_->pair_failures;
                if (impl_->pair_failures >= 8)
                    impl_->pair_locked = now + std::chrono::seconds(30);
                mismatch = true;
            }
        }
        if (mismatch) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            send(res, 401, refusal("EPAIR", "The pairing secret was not accepted."));
            return;
        }
        if (!pm::lan::peer_id_valid(device_id)) {
            send(res, 400, refusal("EPAIR", "The device id is not valid."));
            return;
        }
        pm::lan::Peer peer;
        std::string err;
        std::string token;
        if (!shared->store.ensure_peer(device_id, device_name, "", peer, err)
            || !shared->store.issue_token(device_id, token, err)) {
            send(res, 403, refusal("EPAIR", err.empty() ? "Pairing was refused." : err));
            return;
        }
        std::string pin;
        {
            std::lock_guard<std::mutex> lock(impl_->mu);
            impl_->pair_open = false;
            impl_->pair_secret.clear();
            pin = impl_->pin;
        }
        shared->note(false, std::string("[phone-vfs] paired ") + device_id);
        send(res, 200, {
            {"ok", true},
            {"role", "phone"},
            {"token", token},
            {"device_id", device_id},
            {"host_id", shared->host.authority},
            {"fingerprint", pin},
            {"protocol", 1},
        });
    });

    server->Get("/health", [shared](const httplib::Request&, httplib::Response& res) {
        send(res, 200, {
            {"ok", true},
            {"role", shared->host.role},
            {"vfs", true},
        });
    });

    // The caller's own allow_peer row. A peer whose vfs is off still gets 200
    // here: it is paired, and this is how it learns the permission is off.
    // `allow_peer` is the capability document. The flat fields under `grant`
    // stay for the phone UI. `revision` there is the document generation.
    server->Get("/v1/lan/grant", [shared](const httplib::Request& req, httplib::Response& res) {
        pm::lan::Peer peer;
        if (!shared->admit(req, res, peer))
            return;
        send(res, 200, {
            {"ok", true},
            {"id", peer.id},
            {"authority", shared->host.authority},
            {"trust", pm::lan::trust_name(peer.trust)},
            {"allow_peer", pm::lan::allow_peer_json(peer.allow_peer)},
            {"allow_peer_revision", peer.allow_peer.revision},
            {"grant", {
                {"revision", peer.allow_peer.revision},
                {"vfs_revision", peer.allow_peer.vfs_revision},
                {"vfs", pm::lan::vfs_grant_name(peer.allow_peer.vfs)},
                {"audio", peer.allow_peer.audio},
                {"video", peer.allow_peer.video},
                {"chat", peer.allow_peer.chat},
                {"tools", peer.allow_peer.tools},
            }},
        });
    });

    // A paired peer tells this device where that peer listens. The row is the
    // caller's pair id. The token in the body is what this device sends later,
    // and it is wrapped before it is stored.
    server->Post("/v1/lan/phone-vfs", [shared](const httplib::Request& req, httplib::Response& res) {
        pm::lan::Peer peer;
        if (!shared->admit(req, res, peer))
            return;
        {
            const pm::lan::Decision first =
                pm::lan::grant_authorize(peer.allow_peer, pm::lan::k_cap_vfs, "read", "");
            const pm::lan::Decision decided =
                first == pm::lan::Decision::Ask
                    ? pm::lan::authorize_peer(&shared->store, peer, pm::lan::k_cap_vfs, "read", "")
                    : first;
            if (decided != pm::lan::Decision::Allow) {
                shared->note(true, shared->where(req) + " deny grant peer=" + peer.id);
                const nlohmann::json body =
                    first == pm::lan::Decision::Ask
                        ? pm::lan::mesh_ask_refusal(peer, pm::lan::k_cap_vfs,
                                                    "Folder access needs permission on this device.")
                        : pm::lan::mesh_grant_refusal(peer, "Folder access is off for this device.");
                send(res, 403, body);
                return;
            }
        }
        if (req.body.size() > 16u * 1024u) {
            send(res, 413, refusal("EBODY", "The announce is too large."));
            return;
        }
        const nlohmann::json doc = nlohmann::json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
        if (!doc.is_object()) {
            send(res, 400, refusal("EBODY", "The announce is not valid."));
            return;
        }
        const std::string authority = doc.contains("authority") && doc["authority"].is_string()
            ? doc["authority"].get<std::string>()
            : std::string{};
        bool authority_ok = authority.size() >= 7 && authority.size() <= 64 && authority.rfind("phone-", 0) == 0;
        for (unsigned char c : authority) {
            const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
            if (!ok)
                authority_ok = false;
        }
        if (!authority_ok) {
            send(res, 400, refusal("EBODY", "The phone name is not valid."));
            return;
        }
        std::vector<std::string> urls;
        if (doc.contains("urls") && doc["urls"].is_array()) {
            for (const auto& url : doc["urls"]) {
                if (!url.is_string() || urls.size() >= 8) {
                    send(res, 400, refusal("EBODY", "A peer address is not usable."));
                    return;
                }
                urls.push_back(url.get<std::string>());
            }
        }
        const std::string tls_fp = doc.contains("tls_fp") && doc["tls_fp"].is_string()
            ? doc["tls_fp"].get<std::string>()
            : std::string{};
        const std::string name = doc.contains("name") && doc["name"].is_string()
            ? doc["name"].get<std::string>()
            : std::string{};
        const std::string token = doc.contains("token") && doc["token"].is_string()
            ? doc["token"].get<std::string>()
            : std::string{};
        if (urls.empty()) {
            send(res, 200, {{"ok", true}, {"authority", authority}, {"token", "missing"}});
            return;
        }
        std::string sealed;
        std::string err;
        if (!token.empty()) {
            if (!shared->host.seal_token || !shared->host.seal_token(token, sealed, err)) {
                shared->note(true, shared->where(req) + " deny token peer=" + peer.id);
                send(res, 400, refusal("ETOKEN", err.empty() ? "This device cannot store a peer token." : err));
                return;
            }
        }
        pm::lan::Peer stored;
        if (!shared->store.set_dial(peer.id, name, urls, tls_fp, sealed, stored, err)) {
            shared->note(true, shared->where(req) + " deny store peer=" + peer.id);
            send(res, 400, refusal("EBODY", err.empty() ? "The announce is not valid." : err));
            return;
        }
        shared->note(false, shared->where(req) + " stored peer=" + peer.id
                                + " token=" + (stored.dial_token.empty() ? "missing" : "held"));
        send(res, 200, {{"ok", true},
                        {"authority", authority},
                        {"token", stored.dial_token.empty() ? "missing" : "held"}});
    });

    media_cli::LlmVfsHost vfs;
    vfs.authority = shared->host.authority;
    vfs.roots = shared->host.roots;
    vfs.authorize = [shared](const httplib::Request& req, httplib::Response& res,
                             media_cli::LlmVfsAccess& access) {
        access = {};
        pm::lan::Peer peer;
        if (!shared->admit(req, res, peer))
            return false;
        const pm::server::RouteGrant need = pm::server::route_grant(req.path);
        // Semantic query on the pair row: `vfs` read. Write and the mount list
        // are narrowed below. `ask` runs the installed mesh consent prompt
        // (default Deny). UI hosts install a prompt on top.
        if (need != pm::server::RouteGrant::Files) {
            shared->note(true, shared->where(req) + " deny grant peer=" + peer.id);
            send(res, 403, pm::lan::mesh_grant_refusal(peer, "Folder access is off for this device."));
            return false;
        }
        {
            const pm::lan::Decision first =
                pm::lan::grant_authorize(peer.allow_peer, pm::lan::k_cap_vfs, "read", "");
            const pm::lan::Decision decided =
                first == pm::lan::Decision::Ask
                    ? pm::lan::authorize_peer(&shared->store, peer, pm::lan::k_cap_vfs, "read", "")
                    : first;
            if (decided != pm::lan::Decision::Allow) {
                shared->note(true, shared->where(req) + " deny grant peer=" + peer.id);
                const nlohmann::json body =
                    first == pm::lan::Decision::Ask
                        ? pm::lan::mesh_ask_refusal(peer, pm::lan::k_cap_vfs,
                                                    "Folder access needs permission on this device.")
                        : pm::lan::mesh_grant_refusal(peer, "Folder access is off for this device.");
                send(res, 403, body);
                return false;
            }
        }
        access.device_id = peer.id;
        access.files = true;
        access.write = pm::lan::authorize_peer(&shared->store, peer, pm::lan::k_cap_vfs, "write", "")
                       == pm::lan::Decision::Allow;
        // `vfs.resources` narrows the mounts. Empty lists every published mount.
        if (!pm::lan::grant_resources(peer.allow_peer, pm::lan::k_cap_vfs).empty()) {
            access.mount_allowed = [grant = peer.allow_peer](std::string_view mount) {
                return pm::lan::grant_resource_allowed(grant, pm::lan::k_cap_vfs,
                                                       "mount:" + std::string(mount));
            };
        }
        // The stream guard watches the vfs capability only. An audio or chat
        // edit does not end a folder operation. An AllowOnce ticket keeps a
        // stream alive until the capability revision moves.
        access.grant_revision = peer.allow_peer.vfs_revision;
        access.still_granted = [shared, id = peer.id, revision = peer.allow_peer.vfs_revision,
                                write = access.write]() {
            pm::lan::Peer now;
            std::string err;
            if (!shared->store.find(id, now, err) || now.trust != pm::lan::Trust::Paired)
                return false;
            if (now.allow_peer.vfs_revision != revision)
                return false;
            const char* op = write ? "write" : "read";
            if (pm::lan::mesh_consent_ticket_allows(id, pm::lan::k_cap_vfs, op, "", revision))
                return true;
            return pm::lan::grant_authorize(now.allow_peer, pm::lan::k_cap_vfs, op, "")
                   == pm::lan::Decision::Allow;
        };
        shared->note(false, shared->where(req) + " allow grant="
                                + pm::lan::vfs_grant_name(peer.allow_peer.vfs) + " peer=" + peer.id);
        return true;
    };
    media_cli::register_llm_vfs_routes(*server, std::move(vfs));

    int backend = 0;
    for (int attempt = 0; attempt < 8 && backend == 0; ++attempt) {
        const int candidate = reserve_loopback_port();
        if (candidate > 0 && server->bind_to_port("127.0.0.1", candidate))
            backend = candidate;
    }
    if (backend == 0) {
        err = "could not bind the phone listener";
        return false;
    }
    auto http = std::thread([server] { (void)server->listen_after_bind(); });
    const int announced = shared->host.port_first == shared->host.port_last ? shared->host.port_first : 0;
    std::string pin;
    PhoneTls* tls = phone_tls_open(shared->host.pair_file, announced == 0 ? shared->host.port_first : announced,
                                   backend, pin, err);
    if (!tls && announced == 0) {
        for (int port = shared->host.port_first + 1; port <= shared->host.port_last && !tls; ++port)
            tls = phone_tls_open(shared->host.pair_file, port, backend, pin, err);
    }
    if (!tls) {
        server->stop();
        if (http.joinable())
            http.join();
        if (err.empty())
            err = "could not prepare the phone listener";
        return false;
    }
    const int chosen = announced == 0 ? shared->host.port_first : announced;
    {
        std::lock_guard<std::mutex> lock(impl_->mu);
        impl_->server = server;
        impl_->thread = std::move(http);
        impl_->tls = tls;
        impl_->pin = pin;
        impl_->port = chosen;
        impl_->watch_stop.store(false);
        impl_->watch = std::thread([this, shared, tls] {
            std::string applied;
            while (!impl_->watch_stop.load()) {
                const std::vector<std::string> addresses =
                    listen_addresses(shared->host, shared->store, impl_->pair_open);
                std::string now;
                for (const auto& address : addresses)
                    now += address + " ";
                if (now != applied) {
                    std::string bind_err;
                    if (phone_tls_set_addresses(tls, addresses, bind_err)) {
                        applied = now;
                        shared->note(false, std::string("[phone-vfs] listen")
                                                + (addresses.empty() ? " none" : " " + now)
                                                + "port=" + std::to_string(impl_->port));
                    } else {
                        if (!bind_err.empty())
                            shared->note(true, "[phone-vfs] " + bind_err);
                        if (applied.empty() && impl_->port < shared->host.port_last) {
                            ++impl_->port;
                            phone_tls_use_port(tls, impl_->port);
                        }
                    }
                }
                for (int i = 0; i < 4 && !impl_->watch_stop.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        });
    }
    shared->note(false, "[phone-vfs] ready " + std::to_string(chosen)
                            + " authority=" + shared->host.authority);
    return true;
}

std::string peer_state_json(const pm::lan::PairStore& store, const std::string& authority,
                            const std::vector<LocalNetwork>& networks)
{
    nlohmann::json peers = nlohmann::json::array();
    std::vector<pm::lan::Peer> rows;
    std::string err;
    if (store.load(rows, err)) {
        for (const auto& row : rows) {
            peers.push_back({
                {"id", row.id},
                {"name", row.name},
                {"trust", pm::lan::trust_name(row.trust)},
                {"vfs", pm::lan::vfs_grant_name(row.allow_peer.vfs)},
                {"revision", row.allow_peer.revision},
                {"vfs_revision", row.allow_peer.vfs_revision},
                {"networks", row.allow_peer.networks},
                {"allow_peer", pm::lan::allow_peer_json(row.allow_peer)},
                {"has_token", !row.token_sha256.empty()},
                {"last_seen", row.last_seen},
            });
        }
    }
    nlohmann::json nets = nlohmann::json::array();
    for (const auto& net : networks) {
        nets.push_back({
            {"cidr", net.cidr},
            {"kind", net.kind},
            {"name", net.name},
            {"address", net.address},
        });
    }
    nlohmann::json out = {
        {"authority", authority},
        {"peers", std::move(peers)},
        {"networks", std::move(nets)},
    };
    if (!err.empty())
        out["error"] = err;
    return out.dump();
}

bool peer_announce_json(const pm::lan::PairStore& store, const std::string& peer_id,
                        const std::string& authority, const std::string& name, int port,
                        const std::string& tls_fp, const std::vector<LocalNetwork>& networks, bool rotate,
                        std::string& json, std::string& err)
{
    json.clear();
    bool pin_ok = tls_fp.size() == 64;
    for (unsigned char c : tls_fp) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex)
            pin_ok = false;
    }
    if (!pin_ok) {
        err = "this device has no certificate pin";
        return false;
    }
    pm::lan::Peer peer;
    if (!store.find(peer_id, peer, err))
        return false;
    if (peer.trust != pm::lan::Trust::Paired) {
        err = "this device is not paired";
        return false;
    }
    // A fresh pair has no token hash. The computer still holding the previous
    // token answers "held" and then gets 401 on the folders. Issue one now.
    if (!rotate && peer.token_sha256.empty())
        rotate = true;
    nlohmann::json urls = nlohmann::json::array();
    // Folder access off, or no granted network, announces no address. A dial
    // then has nothing to open.
    if (port > 0 && peer.allow_peer.vfs != pm::lan::VfsGrant::Off) {
        for (const auto& net : networks) {
            if (urls.size() >= 8)
                break;
            if (!pm::lan::network_granted(peer.allow_peer, net.address))
                continue;
            urls.push_back("https://" + net.address + ":" + std::to_string(port));
        }
    }
    nlohmann::json body = {
        {"authority", authority},
        {"name", name},
        {"urls", std::move(urls)},
        {"tls_fp", tls_fp},
    };
    if (rotate) {
        std::string token;
        if (!store.issue_token(peer_id, token, err))
            return false;
        body["token"] = std::move(token);
    }
    json = body.dump();
    return true;
}

} // namespace pm::node
