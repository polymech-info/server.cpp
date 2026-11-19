#pragma once

// The listener a device runs for its paired peers. It is the node with only
// health, the grant route, and vfs mounted. A phone runs it today. Nothing in
// it is Android: the host supplies the name, the folders, and the networks.
//
// Every request is admitted, then judged by the same route grant as the desktop:
//   1. The address the request arrived on is inside a network some paired
//      peer was granted. Otherwise 403, before any route runs.
//   2. A `/v1/` path this process did not enable is 404.
//   3. The bearer is a token in the pair file. Otherwise 401: pair again.
//   4. That peer's grant covers this network, and `route_grant` for the path.
//      Otherwise 403 with the grant revision.

#include "lan/pair_store.hpp"
#include "pm/server/vfs_root.hpp"

#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace pm::node {

/// One IPv4 interface that is up on this device.
struct LocalNetwork {
    /// `192.168.1.0/24`. This is what a grant stores.
    std::string cidr;
    /// `wifi`, `vpn`, `mobile`, `ethernet`, `local`, or `other`.
    std::string kind;
    /// Interface name, for the detail line.
    std::string name;
    /// This device's address on it.
    std::string address;
};

struct PeerListenerHost {
    std::string role = "phone";
    /// `phone-<device-id>`.
    std::string authority;
    /// `lan/devices.json` of this device.
    std::filesystem::path pair_file;
    std::function<std::vector<media_cli::VfsRoot>()> roots;
    /// Runs on the worker before a request reads settings. Android pins the profile here.
    std::function<void()> enter;
    /// One line per decision. Never a token and never file bytes.
    std::function<void(bool warn, const std::string& line)> log;
    /// Wrap a `tn1_` token before it is stored on a pair row. Empty means this
    /// host cannot keep a token a peer sends.
    std::function<bool(const std::string& token, std::string& stored, std::string& err)> seal_token;
    /// Interfaces this device can listen on. A public socket exists only for an
    /// address that is inside some paired peer's granted network. Unset, with
    /// a concrete `bind_host`, is the loopback test profile. `0.0.0.0` is never
    /// a listening socket.
    std::function<std::vector<LocalNetwork>()> networks;
    std::string bind_host = "0.0.0.0";
    int port_first = 8092;
    int port_last = 8100;
};

class PeerListener {
public:
    PeerListener();
    ~PeerListener();
    PeerListener(const PeerListener&) = delete;
    PeerListener& operator=(const PeerListener&) = delete;

    bool start(PeerListenerHost host, std::string& err);
    void stop();
    [[nodiscard]] bool listening() const;
    [[nodiscard]] int port() const;
    /// SHA-256 of this listener's certificate, 64 hex digits. Empty until start().
    [[nodiscard]] std::string pin() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// `{authority, peers:[…], networks:[…]}` for the owner's own screen. No hash and no token.
[[nodiscard]] std::string peer_state_json(const pm::lan::PairStore& store, const std::string& authority,
                                          const std::vector<LocalNetwork>& networks);

/// What this device posts to one peer: `{authority, name, urls, tls_fp}`. The
/// urls are `https://` on the networks that peer was granted. `tls_fp` is the
/// SHA-256 of this listener's certificate. `rotate` issues a new token and
/// adds it as `token`. That is the only time the plaintext exists.
bool peer_announce_json(const pm::lan::PairStore& store, const std::string& peer_id,
                        const std::string& authority, const std::string& name, int port,
                        const std::string& tls_fp, const std::vector<LocalNetwork>& networks,
                        bool rotate, std::string& json, std::string& err);

} // namespace pm::node
