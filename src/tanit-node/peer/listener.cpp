// The paired-peer listener. Portable: the Android host and the desktop test
// host both start this file. It does not read the environment.

#include "pm/node/peer_listener.hpp"

#include "pm/server/secret.hpp"
#include "pm/server/vfs.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <mutex>
#include <thread>
#include <utility>

namespace pm::node {
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
        line += " from=" + req.remote_addr + " on=" + req.local_addr;
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
        if (!pm::lan::network_granted(peer.outbound, req.local_addr)) {
            note(true, where(req) + " deny network peer=" + peer.id);
            nlohmann::json body = refusal("ENETWORK", "This network is not granted to this device.");
            body["revision"] = peer.outbound.revision;
            send(res, 403, body);
            return false;
        }
        return true;
    }
};

} // namespace

struct PeerListener::Impl {
    mutable std::mutex mu;
    std::shared_ptr<httplib::Server> server;
    std::thread thread;
    int port = 0;
};

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

void PeerListener::stop()
{
    std::shared_ptr<httplib::Server> server;
    std::thread thread;
    {
        std::lock_guard<std::mutex> lock(impl_->mu);
        server = std::move(impl_->server);
        thread = std::move(impl_->thread);
        impl_->port = 0;
    }
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
        if (shared->store.any_peer_on(req.local_addr))
            return httplib::Server::HandlerResponse::Unhandled;
        shared->note(true, shared->where(req) + " deny network");
        send(res, 403, refusal("ENETWORK", "This network is not granted."));
        return httplib::Server::HandlerResponse::Handled;
    });

    server->Get("/health", [shared](const httplib::Request&, httplib::Response& res) {
        send(res, 200, {
            {"ok", true},
            {"role", shared->host.role},
            {"vfs", true},
            {"authority", shared->host.authority},
        });
    });

    // The caller's own outbound row. A peer whose vfs is off still gets 200
    // here: it is paired, and this is how it learns the permission is off.
    server->Get("/v1/lan/grant", [shared](const httplib::Request& req, httplib::Response& res) {
        pm::lan::Peer peer;
        if (!shared->admit(req, res, peer))
            return;
        send(res, 200, {
            {"ok", true},
            {"id", peer.id},
            {"authority", shared->host.authority},
            {"trust", pm::lan::trust_name(peer.trust)},
            {"grant", {
                {"revision", peer.outbound.revision},
                {"vfs", pm::lan::vfs_grant_name(peer.outbound.vfs)},
                {"audio", peer.outbound.audio},
                {"video", peer.outbound.video},
            }},
        });
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
        if (peer.outbound.vfs == pm::lan::VfsGrant::Off) {
            shared->note(true, shared->where(req) + " deny grant=off peer=" + peer.id);
            nlohmann::json body = refusal("EGRANT", "Folder access is off for this device.");
            body["revision"] = peer.outbound.revision;
            body["vfs"] = "off";
            send(res, 403, body);
            return false;
        }
        access.device_id = peer.id;
        access.files = true;
        access.write = peer.outbound.vfs == pm::lan::VfsGrant::Write;
        access.grant_revision = peer.outbound.revision;
        shared->note(false, shared->where(req) + " allow grant="
                                + pm::lan::vfs_grant_name(peer.outbound.vfs) + " peer=" + peer.id);
        return true;
    };
    media_cli::register_llm_vfs_routes(*server, std::move(vfs));

    int bound = 0;
    for (int port = shared->host.port_first; port <= shared->host.port_last; ++port) {
        if (server->bind_to_port(shared->host.bind_host, port)) {
            bound = port;
            break;
        }
    }
    if (bound == 0) {
        err = "could not bind a port for shared folders";
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(impl_->mu);
        impl_->server = server;
        impl_->port = bound;
        impl_->thread = std::thread([server] { (void)server->listen_after_bind(); });
    }
    shared->note(false, "[phone-vfs] listen " + shared->host.bind_host + ":" + std::to_string(bound)
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
                {"vfs", pm::lan::vfs_grant_name(row.outbound.vfs)},
                {"revision", row.outbound.revision},
                {"networks", row.outbound.networks},
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
                        const std::vector<LocalNetwork>& networks, bool rotate, std::string& json,
                        std::string& err)
{
    json.clear();
    pm::lan::Peer peer;
    if (!store.find(peer_id, peer, err))
        return false;
    if (peer.trust != pm::lan::Trust::Paired) {
        err = "this device is not paired";
        return false;
    }
    nlohmann::json urls = nlohmann::json::array();
    if (port > 0) {
        for (const auto& net : networks) {
            if (urls.size() >= 8)
                break;
            if (!pm::lan::network_granted(peer.outbound, net.address))
                continue;
            urls.push_back("http://" + net.address + ":" + std::to_string(port));
        }
    }
    nlohmann::json body = {
        {"authority", authority},
        {"name", name},
        {"urls", std::move(urls)},
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
