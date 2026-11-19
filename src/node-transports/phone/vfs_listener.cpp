// Android host for the paired-peer listener. The listener, the pair file,
// and the grant check are shared. This file supplies what only the phone
// knows: the profile, the device name, and the interfaces that are up.

#include "pm/node/phone_vfs.hpp"

#include "core/settings_portable.hpp"
#include "lan/pair_store.hpp"
#include "logging/logger.h"
#include "pm/node/node.hpp"
#include "pm/node/peer_listener.hpp"
#include "pm/server/shared_folder.hpp"
#include "pm/server/vfs.hpp"

#include "string/string_utils.hpp"

#include <android/log.h>
#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ifaddrs.h>
#include <mutex>
#include <net/if.h>
#include <netinet/in.h>
#include <random>
#include <string>
#include <vector>

namespace pm::node {
namespace {

std::mutex g_mu;
PeerListener g_listener;
std::string g_profile;
std::string g_authority;

void note(bool warn, const std::string& line)
{
    if (warn)
        logger::warn(line);
    else
        logger::info(line);
    __android_log_print(warn ? ANDROID_LOG_WARN : ANDROID_LOG_INFO, "phone-vfs", "%s", line.c_str());
}

bool profile_ok(const std::string& profile_dir)
{
    return !profile_dir.empty() && profile_dir.find("://") == std::string::npos;
}

std::filesystem::path pair_file(const std::string& profile_dir)
{
    return std::filesystem::path(profile_dir) / "lan" / "devices.json";
}

std::string network_kind(const std::string& name, const std::string& address)
{
    if (name == "lo" || media::strutil::starts_with_ascii_ci(address, "127."))
        return "local";
    if (media::strutil::starts_with_ascii_ci(name, "tun") || media::strutil::starts_with_ascii_ci(name, "tailscale") || media::strutil::starts_with_ascii_ci(name, "wg")
        || media::strutil::starts_with_ascii_ci(name, "ppp") || pm::lan::cidr_contains("100.64.0.0/10", address))
        return "vpn";
    if (media::strutil::starts_with_ascii_ci(name, "wlan") || media::strutil::starts_with_ascii_ci(name, "swlan") || media::strutil::starts_with_ascii_ci(name, "ap"))
        return "wifi";
    if (media::strutil::starts_with_ascii_ci(name, "rmnet") || media::strutil::starts_with_ascii_ci(name, "ccmni") || media::strutil::starts_with_ascii_ci(name, "pdp")
        || media::strutil::starts_with_ascii_ci(name, "radio"))
        return "mobile";
    if (media::strutil::starts_with_ascii_ci(name, "eth") || media::strutil::starts_with_ascii_ci(name, "usb") || media::strutil::starts_with_ascii_ci(name, "rndis"))
        return "ethernet";
    return "other";
}

int prefix_length(std::uint32_t mask_host_order)
{
    int bits = 0;
    while (bits < 32 && (mask_host_order & (0x80000000u >> bits)))
        ++bits;
    return bits;
}

/// Every IPv4 interface that is up. Link-local 169.254 is not a network a
/// peer can be granted.
std::vector<LocalNetwork> local_networks()
{
    std::vector<LocalNetwork> out;
    ifaddrs* list = nullptr;
    if (getifaddrs(&list) != 0)
        return out;
    for (ifaddrs* it = list; it; it = it->ifa_next) {
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET || !it->ifa_netmask)
            continue;
        if (!(it->ifa_flags & IFF_UP))
            continue;
        char buf[INET_ADDRSTRLEN] = {};
        const auto* in = reinterpret_cast<sockaddr_in*>(it->ifa_addr);
        if (!inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf)))
            continue;
        const std::string address(buf);
        if (media::strutil::starts_with_ascii_ci(address, "169.254."))
            continue;
        const auto* mask = reinterpret_cast<sockaddr_in*>(it->ifa_netmask);
        LocalNetwork net;
        net.address = address;
        net.name = it->ifa_name ? it->ifa_name : "";
        net.cidr = pm::lan::cidr_of(address, prefix_length(ntohl(mask->sin_addr.s_addr)));
        net.kind = network_kind(net.name, address);
        if (net.cidr.empty())
            continue;
        bool seen = false;
        for (const auto& row : out)
            seen = seen || row.cidr == net.cidr;
        if (!seen)
            out.push_back(std::move(net));
    }
    freeifaddrs(list);
    return out;
}

bool authority_ok(const std::string& id)
{
    if (id.size() < 7 || id.size() > 64 || id.compare(0, 6, "phone-") != 0)
        return false;
    return media_cli::vfs_authority_valid(id);
}

std::string load_or_create_authority(const std::string& profile, std::string& err)
{
    const std::filesystem::path path = std::filesystem::path(profile) / "phone-node-id";
    {
        std::ifstream in(path);
        std::string id;
        if (in && std::getline(in, id)) {
            while (!id.empty() && (id.back() == '\r' || id.back() == ' '))
                id.pop_back();
            if (authority_ok(id))
                return id;
        }
    }
    std::random_device rd;
    std::uniform_int_distribution<int> hex(0, 15);
    static constexpr char digits[] = "0123456789abcdef";
    std::string id = "phone-";
    for (int i = 0; i < 16; ++i)
        id.push_back(digits[hex(rd)]);
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        err = "could not store this phone's vfs name";
        return {};
    }
    out << id << "\n";
    return id;
}

nlohmann::json peer_json(const pm::lan::Peer& peer)
{
    return {
        {"id", peer.id},
        {"name", peer.name},
        {"trust", pm::lan::trust_name(peer.trust)},
        {"vfs", pm::lan::vfs_grant_name(peer.outbound.vfs)},
        {"revision", peer.outbound.revision},
        {"networks", peer.outbound.networks},
        {"has_token", !peer.token_sha256.empty()},
    };
}

} // namespace

void phone_vfs_stop()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_listener.stop();
}

PhoneVfsInfo phone_vfs_sync(const std::string& profile_dir)
{
    std::lock_guard<std::mutex> lock(g_mu);
    PhoneVfsInfo info;
    if (!android_listener_features().vfs) {
        info.error = "vfs is off on this phone";
        return info;
    }
    if (!profile_ok(profile_dir))
        return info;
    media::portable_settings::set_profile_dir_override(profile_dir);
    if (pm::server::shared_folder_roots().empty()) {
        g_listener.stop();
        return info;
    }
    if (g_listener.listening() && g_profile == profile_dir) {
        info.listening = true;
        info.port = g_listener.port();
        info.authority = g_authority;
        return info;
    }
    g_listener.stop();

    std::string err;
    const std::string authority = load_or_create_authority(profile_dir, err);
    if (authority.empty()) {
        info.error = err.empty() ? "could not name this phone" : err;
        return info;
    }
    PeerListenerHost host;
    host.role = "phone";
    host.authority = authority;
    host.pair_file = pair_file(profile_dir);
    host.roots = [] { return pm::server::shared_folder_roots(); };
    host.enter = [profile_dir] { media::portable_settings::set_profile_dir_override(profile_dir); };
    host.log = note;
    if (!g_listener.start(std::move(host), err)) {
        info.authority = authority;
        info.error = err.empty() ? "could not start the shared-folder listener" : err;
        return info;
    }
    g_profile = profile_dir;
    g_authority = authority;
    info.listening = true;
    info.port = g_listener.port();
    info.authority = authority;
    return info;
}

PhoneVfsInfo phone_vfs_status(std::string& uris_json)
{
    uris_json = "[]";
    std::lock_guard<std::mutex> lock(g_mu);
    PhoneVfsInfo info;
    info.listening = g_listener.listening();
    info.port = g_listener.port();
    info.authority = g_authority;
    if (!info.listening)
        return info;
    media::portable_settings::set_profile_dir_override(g_profile);
    nlohmann::json uris = nlohmann::json::array();
    for (const auto& root : pm::server::shared_folder_roots())
        uris.push_back("vfs://" + g_authority + "/" + root.name);
    uris_json = uris.dump();
    return info;
}

std::string phone_lan_state(const std::string& profile_dir)
{
    if (!profile_ok(profile_dir))
        return "{\"peers\":[],\"networks\":[]}";
    std::string err;
    const std::string authority = load_or_create_authority(profile_dir, err);
    return peer_state_json(pm::lan::PairStore(pair_file(profile_dir)), authority, local_networks());
}

bool phone_lan_ensure_peer(const std::string& profile_dir, const std::string& key,
                           const std::string& name, const std::string& tls_fp, std::string& json,
                           std::string& err)
{
    if (!profile_ok(profile_dir) || key.empty()) {
        err = "no paired computer";
        return false;
    }
    pm::lan::Peer peer;
    if (!pm::lan::PairStore(pair_file(profile_dir))
             .ensure_peer(pm::lan::derive_peer_id(key), name, tls_fp, peer, err))
        return false;
    json = peer_json(peer).dump();
    return true;
}

bool phone_lan_set_grant(const std::string& profile_dir, const std::string& id, const std::string& vfs,
                         const std::string& networks_json, std::string& json, std::string& err)
{
    if (!profile_ok(profile_dir)) {
        err = "no profile";
        return false;
    }
    pm::lan::VfsGrant grant = pm::lan::VfsGrant::Off;
    if (!pm::lan::parse_vfs_grant(vfs, grant)) {
        err = "vfs is off, read, or write";
        return false;
    }
    std::vector<std::string> networks;
    const nlohmann::json parsed =
        nlohmann::json::parse(networks_json.empty() ? "[]" : networks_json, nullptr, false);
    if (!parsed.is_array()) {
        err = "networks must be a list";
        return false;
    }
    for (const auto& row : parsed) {
        if (row.is_string())
            networks.push_back(row.get<std::string>());
    }
    pm::lan::Peer peer;
    if (!pm::lan::PairStore(pair_file(profile_dir)).set_grant(id, grant, networks, peer, err))
        return false;
    note(false, "[phone-vfs] grant peer=" + peer.id + " vfs=" + pm::lan::vfs_grant_name(peer.outbound.vfs)
                    + " networks=" + std::to_string(peer.outbound.networks.size())
                    + " revision=" + std::to_string(peer.outbound.revision));
    json = peer_json(peer).dump();
    return true;
}

bool phone_lan_revoke(const std::string& profile_dir, const std::string& id, std::string& err)
{
    if (!profile_ok(profile_dir)) {
        err = "no profile";
        return false;
    }
    if (!pm::lan::PairStore(pair_file(profile_dir)).revoke(id, err))
        return false;
    note(false, "[phone-vfs] revoke peer=" + id);
    return true;
}

bool phone_lan_repair(const std::string& profile_dir, const std::string& id, std::string& err)
{
    if (!profile_ok(profile_dir)) {
        err = "no profile";
        return false;
    }
    pm::lan::Peer peer;
    return pm::lan::PairStore(pair_file(profile_dir)).repair(id, peer, err);
}

bool phone_lan_announce(const std::string& profile_dir, const std::string& id, const std::string& name,
                        bool rotate, std::string& json, std::string& err)
{
    if (!profile_ok(profile_dir)) {
        err = "no profile";
        return false;
    }
    std::string authority;
    int port = 0;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        authority = g_authority;
        port = g_listener.port();
    }
    if (authority.empty())
        authority = load_or_create_authority(profile_dir, err);
    if (authority.empty())
        return false;
    return peer_announce_json(pm::lan::PairStore(pair_file(profile_dir)), id, authority, name, port,
                              local_networks(), rotate, json, err);
}

} // namespace pm::node
