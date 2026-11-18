#pragma once

// The listener a device runs for its paired peers. It is the node with only
// health, the grant route, and vfs mounted. A phone runs it today. Nothing in
// it is Android: the host supplies the name, the folders, and the networks.
//
// Every request passes three checks, in this order, on the device that owns
// the folders:
//   1. The address the request arrived on is inside a network some paired
//      peer was granted. Otherwise 403, before any route runs.
//   2. The bearer is a token in the pair file. Otherwise 401: pair again.
//   3. That peer's own grant covers this network and this verb. Otherwise
//      403 with the grant revision: the permission is off.

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

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// `{authority, peers:[…], networks:[…]}` for the owner's own screen. No hash and no token.
[[nodiscard]] std::string peer_state_json(const pm::lan::PairStore& store, const std::string& authority,
                                          const std::vector<LocalNetwork>& networks);

/// What this device posts to one peer: `{authority, name, urls}`. The urls are
/// this device's addresses on the networks that peer was granted, so an
/// ungranted network is never announced. `rotate` issues a new token and adds
/// it as `token`. That is the only time the plaintext exists.
bool peer_announce_json(const pm::lan::PairStore& store, const std::string& peer_id,
                        const std::string& authority, const std::string& name, int port,
                        const std::vector<LocalNetwork>& networks, bool rotate, std::string& json,
                        std::string& err);

} // namespace pm::node
