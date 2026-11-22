#pragma once

// Mesh peer consent for `allow_peer` level=ask.
//
// This is not the LLM tool-call consent pipe (`/v1/chat/consent`,
// ConsentSurface). The principal is a RemotePair hitting this device's
// listener. The owner decides locally. A remote peer never edits policy.
//
// Flow:
//   grant_authorize(...) → Ask
//   authorize_peer(...)  → calls the installed prompt (default: Deny)
//     Deny        → Decision::Deny (HTTP 403 EASK)
//     AllowOnce   → in-memory ticket for this peer+capability(+resource);
//                   PairStore unchanged
//     PersistRead / PersistWrite / PersistOn → PairStore edit, then Allow
//
// UI sits on top: install a prompt that maps MeshConsentRequest to
// ConsentDlg (or Compose) and returns MeshConsentResult. Tests install a
// fake. The default prompt refuses, matching today's ask=refusal behaviour.

#include "lan/pair_store.hpp"

#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace pm::lan {

enum class MeshConsentAnswer {
    Deny,
    /// This request only. Does not change the pair file.
    AllowOnce,
    /// VFS: set level to read (keeps networks).
    PersistRead,
    /// VFS: set level to write (keeps networks).
    PersistWrite,
    /// Switch capabilities: set level to use/on.
    PersistOn,
};

struct MeshConsentRequest {
    std::string peer_id;
    std::string peer_name;
    std::string capability;
    std::string operation;
    std::string resource;
    int capability_revision = 0;
};

struct MeshConsentResult {
    MeshConsentAnswer answer = MeshConsentAnswer::Deny;
};

using MeshConsentPrompt = std::function<MeshConsentResult(const MeshConsentRequest&)>;

/// Process-wide prompt. Empty / unset means Deny. Thread-safe.
void set_mesh_consent_prompt(MeshConsentPrompt prompt);
[[nodiscard]] MeshConsentPrompt mesh_consent_prompt();

/// Clears in-memory AllowOnce tickets (tests, identity reset).
void clear_mesh_consent_tickets();

[[nodiscard]] MeshConsentRequest make_mesh_consent_request(const Peer& peer,
                                                           std::string_view capability,
                                                           std::string_view operation,
                                                           std::string_view resource);

/// True when an AllowOnce ticket still covers this call (same peer, capability,
/// capability revision; resource must match when the ticket named one).
[[nodiscard]] bool mesh_consent_ticket_allows(std::string_view peer_id,
                                              std::string_view capability,
                                              std::string_view operation,
                                              std::string_view resource,
                                              int capability_revision);

/// Applies a Persist* answer to @p store. AllowOnce / Deny are no-ops here.
/// On success @p peer is refreshed from the store. PairStore edits are `const`
/// methods (file replace under the hood).
bool apply_mesh_consent_persist(const PairStore& store, Peer& peer, const MeshConsentRequest& ask,
                                MeshConsentAnswer answer, std::string& err);

/// Policy + optional consent for one inbound call.
/// Allow / Deny / Unsupported pass through. Ask consults tickets, then the
/// prompt. @p store may be null: Persist* then becomes Deny.
[[nodiscard]] Decision authorize_peer(const PairStore* store, Peer& peer, std::string_view capability,
                                      std::string_view operation, std::string_view resource);

/// HTTP body helpers. EASK = capability is ask and consent did not allow.
[[nodiscard]] nlohmann::json mesh_ask_refusal(const Peer& peer, std::string_view capability,
                                              std::string_view message);
[[nodiscard]] nlohmann::json mesh_grant_refusal(const Peer& peer, std::string_view message);

} // namespace pm::lan
