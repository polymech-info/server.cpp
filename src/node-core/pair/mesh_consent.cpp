#include "lan/mesh_consent.hpp"

#include <algorithm>
#include <utility>

namespace pm::lan {
namespace {

struct Ticket {
    std::string peer_id;
    std::string capability;
    std::string operation;
    std::string resource;
    int capability_revision = 0;
};

std::mutex g_mu;
MeshConsentPrompt g_prompt;
std::vector<Ticket> g_tickets;

bool ticket_match(const Ticket& t, std::string_view peer_id, std::string_view capability,
                  std::string_view operation, std::string_view resource, int revision) noexcept
{
    if (t.peer_id != peer_id || t.capability != capability || t.capability_revision != revision)
        return false;
    if (!t.operation.empty() && t.operation != operation)
        return false;
    if (!t.resource.empty() && t.resource != resource)
        return false;
    return true;
}

void add_ticket_unlocked(const MeshConsentRequest& ask)
{
    Ticket next;
    next.peer_id = ask.peer_id;
    next.capability = ask.capability;
    next.operation = ask.operation;
    next.resource = ask.resource;
    next.capability_revision = ask.capability_revision;
    g_tickets.erase(std::remove_if(g_tickets.begin(), g_tickets.end(),
                                   [&](const Ticket& t) {
                                       return t.peer_id == next.peer_id && t.capability == next.capability;
                                   }),
                    g_tickets.end());
    g_tickets.push_back(std::move(next));
}

} // namespace

void set_mesh_consent_prompt(MeshConsentPrompt prompt)
{
    std::lock_guard lock(g_mu);
    g_prompt = std::move(prompt);
}

MeshConsentPrompt mesh_consent_prompt()
{
    std::lock_guard lock(g_mu);
    return g_prompt;
}

void clear_mesh_consent_tickets()
{
    std::lock_guard lock(g_mu);
    g_tickets.clear();
}

MeshConsentRequest make_mesh_consent_request(const Peer& peer, std::string_view capability,
                                             std::string_view operation, std::string_view resource)
{
    MeshConsentRequest ask;
    ask.peer_id = peer.id;
    ask.peer_name = peer.name.empty() ? peer.id : peer.name;
    ask.capability = std::string(capability);
    ask.operation = std::string(operation);
    ask.resource = std::string(resource);
    ask.capability_revision = grant_capability_revision(peer.allow_peer, capability);
    return ask;
}

bool mesh_consent_ticket_allows(std::string_view peer_id, std::string_view capability,
                                std::string_view operation, std::string_view resource,
                                int capability_revision)
{
    std::lock_guard lock(g_mu);
    for (const auto& t : g_tickets) {
        if (ticket_match(t, peer_id, capability, operation, resource, capability_revision))
            return true;
    }
    return false;
}

bool apply_mesh_consent_persist(const PairStore& store, Peer& peer, const MeshConsentRequest& ask,
                                MeshConsentAnswer answer, std::string& err)
{
    err.clear();
    if (answer == MeshConsentAnswer::Deny || answer == MeshConsentAnswer::AllowOnce)
        return true;

    if (ask.capability == k_cap_vfs) {
        VfsGrant vfs = VfsGrant::Off;
        if (answer == MeshConsentAnswer::PersistRead)
            vfs = VfsGrant::Read;
        else if (answer == MeshConsentAnswer::PersistWrite)
            vfs = VfsGrant::Write;
        else {
            err = "vfs consent must be read or write";
            return false;
        }
        return store.set_grant(peer.id, vfs, peer.allow_peer.networks, peer, err);
    }

    if (answer != MeshConsentAnswer::PersistOn) {
        err = "that consent answer does not fit this capability";
        return false;
    }
    // Keep other caps as stored (including `ask`). Only the answered one becomes on.
    std::string audio = peer.allow_peer.audio.empty() ? "off" : peer.allow_peer.audio;
    std::string video = peer.allow_peer.video.empty() ? "off" : peer.allow_peer.video;
    std::string chat = peer.allow_peer.chat.empty() ? "off" : peer.allow_peer.chat;
    std::string tools = peer.allow_peer.tools.empty() ? "off" : peer.allow_peer.tools;
    if (ask.capability == k_cap_audio_capture)
        audio = "on";
    else if (ask.capability == k_cap_video_capture)
        video = "on";
    else if (ask.capability == k_cap_chat_turn)
        chat = "on";
    else if (ask.capability == k_cap_tools_call)
        tools = "on";
    else {
        err = "unknown capability for persist";
        return false;
    }
    return store.set_caps(peer.id, peer.allow_peer.vfs, audio, video, chat, tools, peer, err);
}

Decision authorize_peer(const PairStore* store, Peer& peer, std::string_view capability,
                        std::string_view operation, std::string_view resource)
{
    const Decision first = grant_authorize(peer.allow_peer, capability, operation, resource);
    if (first != Decision::Ask)
        return first;

    const int revision = grant_capability_revision(peer.allow_peer, capability);
    if (mesh_consent_ticket_allows(peer.id, capability, operation, resource, revision))
        return Decision::Allow;

    const MeshConsentRequest ask = make_mesh_consent_request(peer, capability, operation, resource);
    MeshConsentResult picked;
    {
        MeshConsentPrompt prompt;
        {
            std::lock_guard lock(g_mu);
            prompt = g_prompt;
        }
        if (prompt)
            picked = prompt(ask);
    }

    if (picked.answer == MeshConsentAnswer::Deny)
        return Decision::Deny;

    if (picked.answer == MeshConsentAnswer::AllowOnce) {
        std::lock_guard lock(g_mu);
        add_ticket_unlocked(ask);
        return Decision::Allow;
    }

    if (!store) {
        return Decision::Deny;
    }
    std::string err;
    if (!apply_mesh_consent_persist(*store, peer, ask, picked.answer, err))
        return Decision::Deny;
    // Persist cleared ask; re-check so resource lists still apply.
    return grant_authorize(peer.allow_peer, capability, operation, resource) == Decision::Allow
               ? Decision::Allow
               : Decision::Deny;
}

nlohmann::json mesh_ask_refusal(const Peer& peer, std::string_view capability,
                                std::string_view message)
{
    return nlohmann::json{
        {"ok", false},
        {"code", "EASK"},
        {"error", std::string(message)},
        {"capability", std::string(capability)},
        {"revision", peer.allow_peer.revision},
        {"vfs_revision", peer.allow_peer.vfs_revision},
        {"vfs", vfs_grant_name(peer.allow_peer.vfs)},
    };
}

nlohmann::json mesh_grant_refusal(const Peer& peer, std::string_view message)
{
    return nlohmann::json{
        {"ok", false},
        {"code", "EGRANT"},
        {"error", std::string(message)},
        {"revision", peer.allow_peer.revision},
        {"vfs_revision", peer.allow_peer.vfs_revision},
        {"vfs", vfs_grant_name(peer.allow_peer.vfs)},
    };
}

} // namespace pm::lan
