#pragma once

// Pair rows for one device, and the grant check a listener runs per request.
//
// One row is one peer. `allow_peer` is what this device allows that peer to
// use on this device. This file is the authority for that. The token proves
// who the peer is. It does not carry the grant. `dial_token`, `urls`, and
// `tls_fp` are the other direction: how this device calls that peer.
//
// Version 3 stores `allow_peer` as a capability map:
//
//   "allow_peer": {
//     "vfs":           { "revision": 4, "level": "read",
//                        "conditions": { "networks": ["192.168.1.0/24"] } },
//     "audio.capture": { "revision": 2, "level": "use" },
//     "video.capture": { ... }, "chat.turn": { ... }, "tools.call": { ... },
//     "some.future":   { ... }   // kept unchanged, never authorized here
//   }
//
// Each capability has its own revision. The row also keeps one generation
// (`allow_peer_revision`) that orders whole documents. Enforcement and
// session cancellation watch the capability revision they consume.
//
// Only the device that owns the file edits it. No route calls the edit
// functions. A new row grants nothing: every capability is off and no
// network is named.
//
// The file is read on every authorize, so an edit applies to the next
// request. A write is a temp file and a rename.

#include <nlohmann/json.hpp>

#include <cstddef>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace pm::lan {

/// Capability ids this build interprets. Ids are protocol.
inline constexpr const char* k_cap_vfs = "vfs";
inline constexpr const char* k_cap_audio_capture = "audio.capture";
inline constexpr const char* k_cap_video_capture = "video.capture";
inline constexpr const char* k_cap_chat_turn = "chat.turn";
inline constexpr const char* k_cap_tools_call = "tools.call";

/// Registered ids with no route behind them yet. They are stored and returned
/// unchanged (in `Grant::unknown_capabilities`), and `grant_authorize` answers
/// `Decision::Unsupported` for them whatever level the file says. They turn on
/// when the route that consumes them is registered and the Grant models them.
inline constexpr const char* k_cap_audio_playback = "audio.playback";
inline constexpr const char* k_cap_video_control = "video.control";
inline constexpr const char* k_cap_chat_realtime = "chat.realtime";
inline constexpr const char* k_cap_speech_stt = "speech.stt";
inline constexpr const char* k_cap_speech_tts = "speech.tts";
inline constexpr const char* k_cap_host_open = "host.open";

enum class Trust { Verifying, Paired, Revoked };
enum class VfsGrant { Off, Read, Write };

[[nodiscard]] const char* trust_name(Trust trust) noexcept;
[[nodiscard]] const char* vfs_grant_name(VfsGrant grant) noexcept;
[[nodiscard]] bool parse_vfs_grant(std::string_view text, VfsGrant& out) noexcept;

/// What this device allows one peer. Serialized as `allow_peer`.
struct Grant {
    /// Generation of the whole document. Counts local edits. The order of two
    /// grants is this number, not a clock. Live guards use the per-capability
    /// revisions below.
    int revision = 1;
    /// `vfs` capability. Its revision moves when vfs or networks change.
    VfsGrant vfs = VfsGrant::Off;
    /// `vfs` file says `level=ask`. `vfs` stays Off: ask is never use. A local
    /// consent decision (not built yet) is what would turn one operation on.
    bool vfs_ask = false;
    /// `on`, `off`, or `ask`. `audio.capture`, `video.capture`, `chat.turn`,
    /// `tools.call`. `ask` is stored and returned, and never authorizes by
    /// itself (`grant_authorize` answers `Decision::Ask`). Nothing reads `ask`
    /// as `on`. A files scope is `vfs`, not one of these.
    std::string audio = "off";
    std::string video = "off";
    std::string chat = "off";
    std::string tools = "off";
    /// IPv4 networks (`192.168.1.0/24`) this peer may reach this device on.
    /// Empty means none. A network that appears later is not added.
    /// Stored under `vfs.conditions.networks`.
    std::vector<std::string> networks;

    /// One revision per known capability. Each moves only when that
    /// capability changes.
    int vfs_revision = 1;
    int audio_revision = 1;
    int video_revision = 1;
    int chat_revision = 1;
    int tools_revision = 1;

    /// Members of a known capability this build does not model (`resources`,
    /// extra `conditions`), keyed by capability id. Written back unchanged.
    std::map<std::string, nlohmann::json> capability_extra;
    /// Capabilities this build does not implement. Read and written unchanged.
    /// This build never authorizes them.
    std::map<std::string, nlohmann::json> unknown_capabilities;
};

/// True for the ids this build models and can authorize (`vfs`, `audio.capture`, ...).
[[nodiscard]] bool capability_known(std::string_view id) noexcept;
/// True for ids in the registry that have no route yet (`audio.playback`, ...).
/// They are round-tripped like unknown ids and never authorized.
[[nodiscard]] bool capability_reserved(std::string_view id) noexcept;

/// Answer of `grant_authorize`.
enum class Decision {
    /// Use is granted.
    Allow,
    /// Off, missing, wrong operation for the level, or a resource the capability does not list.
    Deny,
    /// `level=ask`. The caller needs a local consent decision. Nothing here
    /// shows one yet, so a route treats this as a refusal.
    Ask,
    /// Reserved or unknown capability. This build cannot authorize it.
    Unsupported,
};

/// The semantic policy query: one capability, one operation, and the concrete
/// resource the handler parsed (`mount:photos`; empty when the route has not
/// parsed one yet). Operations under `vfs`: `list`, `stat`, `read`, `resolve`
/// need read; `write`, `mkdir`, `move`, `delete` need write. Under the other
/// known capabilities every operation needs `on`.
///
/// A non-empty `resources` list on the capability narrows it: a non-empty
/// @p resource must match an entry (exact, `prefix*`, or `*`). A missing or empty
/// list means every resource the capability publishes.
[[nodiscard]] Decision grant_authorize(const Grant& grant, std::string_view capability,
                                       std::string_view operation, std::string_view resource);
/// `resources` of a known capability, empty when the file names none.
[[nodiscard]] std::vector<std::string> grant_resources(const Grant& grant, std::string_view capability);
/// True when the capability lists no resources, or @p resource matches one.
[[nodiscard]] bool grant_resource_allowed(const Grant& grant, std::string_view capability,
                                          std::string_view resource);
/// Revision of one capability. @p name is a capability id or a session scope
/// (`files`, `audio`, `video`, `chat`, `tools`). 0 when the name is not known.
[[nodiscard]] int grant_capability_revision(const Grant& grant, std::string_view name) noexcept;
/// The `allow_peer` object for @p grant.
[[nodiscard]] nlohmann::json allow_peer_json(const Grant& grant);
/// Reads an `allow_peer` object. Unknown capabilities are kept. The document
/// generation (`revision`) is not part of the object and is left at 1.
bool allow_peer_from_json(const nlohmann::json& node, Grant& grant, std::string& err);
/// Turns every known capability off, drops networks and unknown capabilities,
/// and moves every capability revision and the generation.
void grant_clear(Grant& grant);
/// Makes @p next follow @p prev: every revision is @p prev's plus one.
void grant_succeed(Grant& next, const Grant& prev);

struct Peer {
    std::string id;
    std::string name;
    /// Ed25519 pairing fingerprint. Empty until a host links that identity.
    std::string peer_fp;
    /// SPKI SHA-256 of the peer's TLS listener, when this device dials it.
    std::string tls_fp;
    /// `https://` addresses of that listener. At most eight. Empty until known.
    std::vector<std::string> urls;
    /// Wrapped token this device sends when it dials the peer. Opaque. Empty
    /// until the peer has issued one. Not the hash in `token_sha256`.
    std::string dial_token;
    /// SHA-256 of the `tn1_` token the peer presents. Empty until one is issued.
    std::string token_sha256;
    Trust trust = Trust::Paired;
    /// What this device allows this peer to use here. Enforced on inbound requests.
    Grant allow_peer;
    std::string created;
    std::string last_seen;
};

enum class Verdict {
    /// No row holds this token. HTTP 401.
    Unknown,
    /// The row is revoked. HTTP 401.
    Revoked,
    /// The peer is known. The grant decides the rest.
    Paired,
};

struct Access {
    Verdict verdict = Verdict::Unknown;
    Peer peer;
};

/// `a.b.c.d/n`, n from 0 to 32.
[[nodiscard]] bool cidr_valid(std::string_view cidr) noexcept;
[[nodiscard]] bool cidr_contains(std::string_view cidr, std::string_view ipv4) noexcept;
/// The network part of @p ipv4 under @p prefix_len, as `a.b.c.d/n`. Empty on bad input.
[[nodiscard]] std::string cidr_of(std::string_view ipv4, int prefix_len);
/// True when @p local_ipv4, the address the request arrived on, is inside a granted network.
[[nodiscard]] bool network_granted(const Grant& grant, std::string_view local_ipv4) noexcept;

/// Stable row id for a peer known by a fingerprint or an address: 16 hex of its SHA-256.
[[nodiscard]] std::string derive_peer_id(std::string_view key);
[[nodiscard]] bool peer_id_valid(std::string_view id) noexcept;
/// `files`, `audio`, `video`, `chat`, or `tools`.
[[nodiscard]] bool grant_scope_known(std::string_view scope) noexcept;
/// `files` becomes vfs write. The others become `on`.
bool grant_set_scope(Grant& grant, std::string_view scope);
/// Flat scope names kept for API compatibility and `RouteGrant`. This is a
/// projection of `grant_authorize`: a scope is listed when its capability
/// answers Allow. `ask` and reserved capabilities never appear. Route code
/// that can name an operation and a resource should call `grant_authorize`.
[[nodiscard]] std::vector<std::string> grant_scopes(const Grant& grant);

class PairStore {
public:
    explicit PairStore(std::filesystem::path file, std::size_t max_peers = 16);

    [[nodiscard]] const std::filesystem::path& file() const noexcept { return file_; }

    /// A missing file is an empty list. Version 3 is the only schema this reads
    /// and writes. Version 1 and 2 files are refused with an error that says to
    /// pair again. A desktop ticket file (`v` plus `scopes`) is refused here;
    /// the desktop imports it once.
    bool load(std::vector<Peer>& out, std::string& err) const;
    bool load_identity(std::string& identity, std::vector<Peer>& out, std::string& err) const;
    /// Replaces the file. `rows` must already be valid. The desktop limit is the caller's.
    bool write(std::string_view identity, const std::vector<Peer>& rows, std::string& err) const;
    bool find(std::string_view id, Peer& out, std::string& err) const;

    /// Adds the row when it is missing: paired, vfs off, no network, revision 1.
    /// An existing row keeps its trust and its grant.
    bool ensure_peer(std::string_view id, std::string_view name, std::string_view tls_fp,
                     Peer& out, std::string& err) const;

    /// How this device dials that peer. A missing row is created with nothing
    /// granted. An empty @p dial_token keeps the stored one. @p urls replaces
    /// the stored list. A revoked row is refused.
    bool set_dial(std::string_view id, std::string_view name, const std::vector<std::string>& urls,
                  std::string_view tls_fp, std::string_view dial_token, Peer& out, std::string& err) const;

    /// Replaces the token hash and returns the plaintext once. The grant stays.
    bool issue_token(std::string_view id, std::string& token, std::string& err) const;

    /// Local edit of `vfs` and its networks. Only the vfs revision (and the
    /// generation) move, and only when something changed.
    bool set_grant(std::string_view id, VfsGrant vfs, const std::vector<std::string>& networks,
                   Peer& out, std::string& err) const;

    /// Replaces vfs and the audio, video, chat, and tools switches. Networks stay.
    /// Each capability revision moves only when that capability changed. A
    /// capability that turns off cancels that peer's live calls for it.
    bool set_caps(std::string_view id, VfsGrant vfs, bool audio, bool video, bool chat, bool tools,
                  Peer& out, std::string& err) const;

    /// The token stops working. The row stays so the UI can name the peer.
    bool revoke(std::string_view id, std::string& err) const;

    /// Deletes the row and cancels that peer's sessions. A missing id succeeds.
    bool forget(std::string_view id, std::string& err) const;

    /// A revoked row becomes paired again with nothing granted and no token.
    bool repair(std::string_view id, Peer& out, std::string& err) const;

    [[nodiscard]] Access authorize(std::string_view token) const;

    /// True when a paired peer was granted the network @p local_ipv4 is on.
    [[nodiscard]] bool any_peer_on(std::string_view local_ipv4) const;

private:
    std::filesystem::path file_;
    std::size_t max_peers_;
};

} // namespace pm::lan
