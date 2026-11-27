#pragma once

// Dial book for paired node peers: `lan/peers.json` under the configured dir.
// One row per peer, keyed by vfs authority (`phone-<id>`). Row shape matches
// the on-disk lan/peers.json contract. Token wrap/unwrap and config paths are
// supplied via hooks; without them token operations fail closed.

#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pm::node {

inline constexpr std::size_t k_max_peers = 64;
inline constexpr std::size_t k_max_urls = 8;

struct Peer {
    std::string id;
    std::string name;
    /// Addresses the peer announced, in its order. At most eight. `https://` only.
    std::vector<std::string> urls;
    /// SHA-256 of the peer listener certificate, 64 hex digits.
    std::string tls_fp;
    /// Plaintext in memory only. Empty when no token is stored or unwrap fails.
    std::string token;
    /// Who announced this peer: the desktop pair-device id of the caller, or
    /// `serve-key` when the caller used the serve key itself.
    std::string pair;
    int grant_revision = 0;
    std::string grant_vfs;
    std::string last_seen;
};

struct PeerBookHooks {
    std::function<std::filesystem::path()> config_dir;
    /// Platform-wrapped storage (e.g. `w1:` + hex). Required for seal/store.
    std::function<bool(const std::string& plaintext, std::string& stored, std::string& err)>
        seal_token;
    /// Inverse of @p seal_token. Required to read stored dial tokens.
    std::function<std::string(const std::string& stored)> open_token;
    std::function<std::string(std::string_view text, std::size_t max)> clip_name;
    std::function<std::string()> utc_now;
};

class PeerBook {
public:
    void set_hooks(PeerBookHooks hooks);

    [[nodiscard]] static bool is_device_mount(std::string_view mount) noexcept;

    [[nodiscard]] bool seal_dial_token(const std::string& token, std::string& stored,
                                       std::string& err) const;
    [[nodiscard]] std::string open_dial_token(const std::string& stored) const;

    [[nodiscard]] std::vector<Peer> peers() const;
    [[nodiscard]] std::optional<Peer> find_peer(std::string_view authority) const;

    bool store_peer(std::string_view authority, const std::string& name,
                    const std::vector<std::string>& urls, const std::string& token,
                    const std::string& tls_fp, const std::string& owner, bool& holds_token,
                    std::string& err);

    void drop_token(std::string_view authority);
    void drop_token_if_matches(std::string_view authority, std::string_view expected);
    void note_grant(std::string_view authority, int revision, const std::string& vfs);

    [[nodiscard]] std::filesystem::path mounts_cache_file() const;
    void forget_revoked_device(std::string_view id);
    bool forget_peer(std::string_view authority, std::string& err);

private:
    [[nodiscard]] std::filesystem::path peers_file() const;
    [[nodiscard]] std::filesystem::path devices_file() const;
    [[nodiscard]] std::string clip_label(std::string_view name) const;
    [[nodiscard]] std::string now_iso() const;

    mutable std::mutex mu_;
    PeerBookHooks hooks_;
};

/// Process-wide dial book. Configure hooks before use (see peer_book_defaults.hpp).
[[nodiscard]] PeerBook& peer_book();
void set_peer_book_hooks(PeerBookHooks hooks);

[[nodiscard]] inline bool is_device_mount(std::string_view mount) noexcept
{
    return PeerBook::is_device_mount(mount);
}

[[nodiscard]] inline bool seal_dial_token(const std::string& token, std::string& stored,
                                          std::string& err)
{
    return peer_book().seal_dial_token(token, stored, err);
}

[[nodiscard]] inline std::string open_dial_token(const std::string& stored)
{
    return peer_book().open_dial_token(stored);
}

[[nodiscard]] inline std::vector<Peer> peers()
{
    return peer_book().peers();
}

[[nodiscard]] inline std::optional<Peer> find_peer(std::string_view authority)
{
    return peer_book().find_peer(authority);
}

inline bool store_peer(std::string_view authority, const std::string& name,
                       const std::vector<std::string>& urls, const std::string& token,
                       const std::string& tls_fp, const std::string& owner, bool& holds_token,
                       std::string& err)
{
    return peer_book().store_peer(authority, name, urls, token, tls_fp, owner, holds_token, err);
}

inline void drop_token(std::string_view authority)
{
    peer_book().drop_token(authority);
}

inline void drop_token_if_matches(std::string_view authority, std::string_view expected)
{
    peer_book().drop_token_if_matches(authority, expected);
}

inline void note_grant(std::string_view authority, int revision, const std::string& vfs)
{
    peer_book().note_grant(authority, revision, vfs);
}

[[nodiscard]] inline std::filesystem::path mounts_cache_file()
{
    return peer_book().mounts_cache_file();
}

inline void forget_revoked_device(std::string_view id)
{
    peer_book().forget_revoked_device(id);
}

inline bool forget_peer(std::string_view authority, std::string& err)
{
    return peer_book().forget_peer(authority, err);
}

} // namespace pm::node