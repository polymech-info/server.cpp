#pragma once

// Android host for the paired-peer listener (pm/node/peer_listener.hpp).
// This file is what JNI calls. It supplies the profile, the phone's name,
// and the interfaces. Pair rows and the grant check are shared C++.
//
// The socket lives in the app process. It is up while a folder bookmark is
// shared. A sleeping process is an offline peer. This is not a second daemon.

#include <string>

namespace pm::node {

struct PhoneVfsInfo {
    bool listening = false;
    int port = 0;
    std::string authority;
    /// SHA-256 of this listener's certificate. Empty until it is listening.
    std::string pin;
    std::string error;
};

/// Start the listener even when no folder is shared. Pairing uses this.
PhoneVfsInfo phone_vfs_listen(const std::string& profile_dir);

/// Start when a shared folder exists, stop when none do. Idempotent.
/// Starting grants nothing: a peer still needs a token, a network, and vfs on.
PhoneVfsInfo phone_vfs_sync(const std::string& profile_dir);

void phone_vfs_stop();

/// `uris` is a JSON array of `vfs://phone-<id>/<mount>` strings. Empty when
/// the listener is down.
PhoneVfsInfo phone_vfs_status(std::string& uris_json);

/// `{authority, peers, networks}` for the settings screen.
std::string phone_lan_state(const std::string& profile_dir);

/// Adds the row for a computer this phone is already paired with. @p key is
/// that computer's TLS fingerprint, or its address when it has none. The new
/// row grants nothing. @p json is the row.
bool phone_lan_ensure_peer(const std::string& profile_dir, const std::string& key,
                           const std::string& name, const std::string& tls_fp, std::string& json,
                           std::string& err);

/// The owner's edit. @p vfs is `off`, `read`, or `write`. @p networks_json is
/// a JSON array of `a.b.c.d/n`. @p json is the row after the edit.
bool phone_lan_set_grant(const std::string& profile_dir, const std::string& id, const std::string& vfs,
                         const std::string& networks_json, std::string& json, std::string& err);

bool phone_lan_revoke(const std::string& profile_dir, const std::string& id, std::string& err);

/// A revoked computer becomes paired again, with nothing granted.
bool phone_lan_repair(const std::string& profile_dir, const std::string& id, std::string& err);

/// The body this phone posts to that computer. `rotate` adds a new token.
bool phone_lan_announce(const std::string& profile_dir, const std::string& id, const std::string& name,
                        bool rotate, std::string& json, std::string& err);

/// Opens a pairing window and returns the QR modules. No secret leaves this JSON.
std::string phone_lan_open_ticket(const std::string& profile_dir, const std::string& name);

void phone_lan_close_ticket();

/// Stores the other phone on this phone's pair file. @p token is the `tn1_`
/// plaintext and is wrapped before it is written. The row grants nothing.
bool phone_lan_remember_peer(const std::string& profile_dir, const std::string& id,
                             const std::string& name, const std::string& tls_fp,
                             const std::string& url, const std::string& token, std::string& err);

} // namespace pm::node
