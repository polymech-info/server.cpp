#include "lan/pair_store.hpp"

#include "pm/node/sessions.hpp"

#include "commands/batch_queue.hpp"
#include "string/string_utils.hpp"

#include <nlohmann/json.hpp>
#include <picosha2.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <system_error>
#if defined(_WIN32)
#    include <io.h>
#else
#    include <unistd.h>
#endif

#if defined(_WIN32)
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <windows.h>
#    include <bcrypt.h>
#    if defined(_MSC_VER)
#        pragma comment(lib, "bcrypt.lib")
#    endif
#endif

namespace pm::lan {
namespace {

/// The widest network a grant may name: `10.0.0.0/8`, `127.0.0.0/8`.
constexpr int k_min_grant_prefix = 8;

/// Edits in this process are serialized. A second process only reads.
std::mutex& store_mutex()
{
    static std::mutex mu;
    return mu;
}

bool random_bytes(std::uint8_t* out, std::size_t n)
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

std::string sha256_hex(std::string_view text)
{
    return picosha2::hash256_hex_string(std::string(text));
}

bool same_bytes(std::string_view a, std::string_view b) noexcept
{
    unsigned diff = static_cast<unsigned>(a.size() ^ b.size());
    const std::size_t n = a.size() < b.size() ? a.size() : b.size();
    for (std::size_t i = 0; i < n; ++i)
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return diff == 0;
}

bool parse_ipv4(std::string_view text, std::uint32_t& out) noexcept
{
    std::uint32_t value = 0;
    int parts = 0;
    std::size_t i = 0;
    while (i < text.size()) {
        if (text[i] < '0' || text[i] > '9')
            return false;
        std::uint32_t part = 0;
        int digits = 0;
        while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
            part = part * 10 + static_cast<std::uint32_t>(text[i] - '0');
            if (++digits > 3 || part > 255)
                return false;
            ++i;
        }
        value = (value << 8) | part;
        ++parts;
        if (i == text.size())
            break;
        if (text[i] != '.' || parts == 4)
            return false;
        ++i;
        if (i == text.size())
            return false;
    }
    if (parts != 4)
        return false;
    out = value;
    return true;
}

bool parse_cidr(std::string_view cidr, std::uint32_t& net, std::uint32_t& mask) noexcept
{
    const auto slash = cidr.find('/');
    if (slash == std::string_view::npos || slash + 1 >= cidr.size() || cidr.size() - slash > 3)
        return false;
    int len = 0;
    for (std::size_t i = slash + 1; i < cidr.size(); ++i) {
        if (cidr[i] < '0' || cidr[i] > '9')
            return false;
        len = len * 10 + (cidr[i] - '0');
    }
    if (len > 32)
        return false;
    std::uint32_t address = 0;
    if (!parse_ipv4(cidr.substr(0, slash), address))
        return false;
    mask = len == 0 ? 0u : 0xFFFFFFFFu << (32 - len);
    net = address & mask;
    return true;
}

std::string format_ipv4(std::uint32_t value)
{
    char buf[20];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (value >> 24) & 255u, (value >> 16) & 255u,
                  (value >> 8) & 255u, value & 255u);
    return buf;
}

Trust parse_trust(const std::string& text) noexcept
{
    if (text == "paired")
        return Trust::Paired;
    if (text == "verifying")
        return Trust::Verifying;
    // An unknown word must not read as paired.
    return Trust::Revoked;
}

const char* switch_level(const std::string& value) noexcept
{
    if (value == "on")
        return "use";
    // `ask` is stored as written. It never reads as `on`.
    return value == "ask" ? "ask" : "off";
}

bool resource_matches(std::string_view pattern, std::string_view resource) noexcept
{
    if (pattern == "*")
        return true;
    if (!pattern.empty() && pattern.back() == '*') {
        const std::string_view prefix = pattern.substr(0, pattern.size() - 1);
        return resource.size() >= prefix.size() && resource.substr(0, prefix.size()) == prefix;
    }
    return pattern == resource;
}

/// A capability object: its unmodelled members, then `revision` and `level`.
nlohmann::json capability_json(const Grant& grant, const char* id, int revision, const char* level)
{
    nlohmann::json out = nlohmann::json::object();
    const auto extra = grant.capability_extra.find(id);
    if (extra != grant.capability_extra.end() && extra->second.is_object())
        out = extra->second;
    out["revision"] = (std::max)(1, revision);
    out["level"] = level;
    return out;
}

/// Reads `revision` and `level` of a known capability. The remaining members
/// go to @p extra unchanged.
bool read_capability(const nlohmann::json& node, int& revision, std::string& level,
                     nlohmann::json& extra, std::string& err)
{
    revision = 1;
    level.clear();
    extra = nlohmann::json::object();
    if (!node.is_object()) {
        err = "the pair file is not valid";
        return false;
    }
    for (auto it = node.begin(); it != node.end(); ++it) {
        if (it.key() == "revision") {
            if (!it.value().is_number_integer()) {
                err = "the pair file is not valid";
                return false;
            }
            revision = (std::max)(1, it.value().get<int>());
        } else if (it.key() == "level") {
            if (!it.value().is_string()) {
                err = "the pair file is not valid";
                return false;
            }
            level = it.value().get<std::string>();
        } else {
            extra[it.key()] = it.value();
        }
    }
    return true;
}

bool read_switch_level(const std::string& level, std::string& out, std::string& err)
{
    out = "off";
    if (level.empty() || level == "off")
        return true;
    if (level == "use") {
        out = "on";
        return true;
    }
    if (level == "ask") {
        out = "ask";
        return true;
    }
    err = "the pair file is not valid";
    return false;
}

void keep_extra(Grant& grant, const char* id, nlohmann::json extra)
{
    if (extra.is_object() && !extra.empty())
        grant.capability_extra[id] = std::move(extra);
}

std::string text_of(const nlohmann::json& row, const char* key)
{
    return row.contains(key) && row[key].is_string() ? row[key].get<std::string>() : std::string{};
}

bool pin_hex(std::string_view text)
{
    if (text.size() != 64)
        return false;
    for (unsigned char c : text) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
    }
    return true;
}

bool https_url(std::string_view url)
{
    if (url.size() > 200 || url.rfind("https://", 0) != 0)
        return false;
    for (unsigned char c : url) {
        if (c <= 0x20 || c == 0x7f || c == '"' || c == '\\')
            return false;
    }
    return true;
}

/// Empty, or a wrapped token. `w1:` is the desktop secret store. `aks:v1:` is
/// the phone keystore. A `tn1_` token is plaintext and is never stored.
bool wrapped_dial_token(std::string_view token)
{
    if (token.empty())
        return true;
    if (token.size() > 4096 || token.rfind("tn1_", 0) == 0)
        return false;
    return token.rfind("w1:", 0) == 0 || token.rfind("aks:v1:", 0) == 0;
}

bool read_urls(const nlohmann::json& row, std::vector<std::string>& urls, std::string& err)
{
    urls.clear();
    if (!row.contains("urls"))
        return true;
    if (!row["urls"].is_array()) {
        err = "the pair file is not valid";
        return false;
    }
    for (const auto& item : row["urls"]) {
        if (!item.is_string() || !https_url(item.get<std::string>())) {
            err = "the pair file is not valid";
            return false;
        }
        urls.push_back(item.get<std::string>());
    }
    if (urls.size() > 8) {
        err = "the pair file is not valid";
        return false;
    }
    return true;
}

bool read_doc(const std::filesystem::path& file, std::string& identity, std::vector<Peer>& out,
              std::string& err)
{
    out.clear();
    identity.clear();
    std::error_code ec;
    if (!std::filesystem::exists(file, ec))
        return true;
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        err = "could not open the pair file";
        return false;
    }
    const nlohmann::json doc = nlohmann::json::parse(in, nullptr, false);
    if (!doc.is_object() || !doc.contains("devices") || !doc["devices"].is_array()) {
        err = "the pair file is not valid";
        return false;
    }
    // The desktop ticket file used `v`. This store uses `version`.
    if (doc.contains("v") && !doc.contains("version")) {
        err = "pair file uses ticket scopes";
        return false;
    }
    int version = 0;
    if (doc.contains("version") && doc["version"].is_number_integer())
        version = doc["version"].get<int>();
    if (version == 1 || version == 2) {
        err = "the pair file is version " + std::to_string(version)
              + "; only version 3 is supported. Delete it and pair the devices again";
        return false;
    }
    if (version != 3) {
        err = "the pair file is not valid";
        return false;
    }
    if (doc.contains("identity") && doc["identity"].is_string())
        identity = doc["identity"].get<std::string>();
    for (const auto& row : doc["devices"]) {
        if (!row.is_object() || (row.contains("scopes") && !row.contains("allow_peer"))) {
            err = row.is_object() && row.contains("scopes") ? "pair file uses ticket scopes"
                                                            : "the pair file is not valid";
            return false;
        }
        if (row.contains("outbound")) {
            err = "the pair file uses outbound; only allow_peer is supported. Delete it and pair the devices again";
            return false;
        }
        Peer peer;
        peer.id = text_of(row, "id");
        if (!peer_id_valid(peer.id)) {
            err = "the pair file has a device id that is not valid";
            return false;
        }
        peer.name = text_of(row, "name");
        peer.peer_fp = text_of(row, "peer_fp");
        peer.tls_fp = text_of(row, "tls_fp");
        if (!read_urls(row, peer.urls, err))
            return false;
        peer.dial_token = text_of(row, "dial_token");
        if (!wrapped_dial_token(peer.dial_token)) {
            err = "the pair file is not valid";
            return false;
        }
        peer.token_sha256 = text_of(row, "token_sha256");
        if (!peer.token_sha256.empty() && peer.token_sha256.size() != 64) {
            err = "the pair file is not valid";
            return false;
        }
        peer.trust = parse_trust(text_of(row, "trust"));
        if (!allow_peer_from_json(row.contains("allow_peer") ? row["allow_peer"] : nlohmann::json::object(),
                                  peer.allow_peer, err))
            return false;
        if (row.contains("allow_peer_revision")) {
            if (!row["allow_peer_revision"].is_number_integer()) {
                err = "the pair file is not valid";
                return false;
            }
            peer.allow_peer.revision = (std::max)(1, row["allow_peer_revision"].get<int>());
        }
        peer.created = text_of(row, "created");
        peer.last_seen = text_of(row, "last_seen");
        out.push_back(std::move(peer));
    }
    return true;
}

bool write_doc(const std::filesystem::path& file, std::string_view identity,
               const std::vector<Peer>& rows, std::string& err)
{
    nlohmann::json devices = nlohmann::json::array();
    for (const auto& peer : rows) {
        devices.push_back({
            {"id", peer.id},
            {"name", peer.name},
            {"peer_fp", peer.peer_fp},
            {"tls_fp", peer.tls_fp},
            {"urls", peer.urls},
            {"dial_token", peer.dial_token},
            {"token_sha256", peer.token_sha256},
            {"trust", trust_name(peer.trust)},
            {"allow_peer", allow_peer_json(peer.allow_peer)},
            {"allow_peer_revision", peer.allow_peer.revision},
            {"created", peer.created},
            {"last_seen", peer.last_seen},
        });
    }
    std::error_code ec;
    if (!file.parent_path().empty())
        std::filesystem::create_directories(file.parent_path(), ec);
    std::filesystem::path tmp = file;
    tmp += ".tmp";
    std::filesystem::path bak = file;
    bak += ".bak";
    const std::string body =
        nlohmann::json{{"version", 3}, {"identity", std::string(identity)}, {"devices", std::move(devices)}}
            .dump(2);
#if defined(_WIN32)
    FILE* fp = _wfopen(tmp.c_str(), L"wb");
#else
    FILE* fp = std::fopen(tmp.string().c_str(), "wb");
#endif
    if (!fp) {
        err = "could not write the pair file";
        return false;
    }
    const bool wrote = std::fwrite(body.data(), 1, body.size(), fp) == body.size();
    if (wrote)
        std::fflush(fp);
#if defined(_WIN32)
    if (wrote)
        _commit(_fileno(fp));
#else
    if (wrote)
        fsync(fileno(fp));
#endif
    std::fclose(fp);
    if (!wrote) {
        std::filesystem::remove(tmp, ec);
        err = "could not write the pair file";
        return false;
    }
    if (std::filesystem::exists(file, ec)) {
#if defined(_WIN32)
        if (!CopyFileW(file.c_str(), bak.c_str(), FALSE)) {
            std::filesystem::remove(tmp, ec);
            err = "could not back up the pair file";
            return false;
        }
#else
        std::filesystem::copy_file(file, bak, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            std::filesystem::remove(tmp, ec);
            err = "could not back up the pair file";
            return false;
        }
#endif
    }
#if defined(_WIN32)
    // Replace a file a listener may still have open.
    bool replaced = false;
    for (int attempt = 0; attempt < 20; ++attempt) {
        if (MoveFileExW(tmp.c_str(), file.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            replaced = true;
            break;
        }
        ::Sleep(10);
    }
    if (!replaced) {
        std::filesystem::remove(tmp, ec);
        err = "could not replace the pair file";
        return false;
    }
#else
    std::filesystem::rename(tmp, file, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        err = "could not replace the pair file";
        return false;
    }
#endif
    return true;
}

Peer* row_of(std::vector<Peer>& rows, std::string_view id)
{
    for (auto& row : rows)
        if (row.id == id)
            return &row;
    return nullptr;
}

} // namespace

const char* trust_name(Trust trust) noexcept
{
    switch (trust) {
    case Trust::Verifying: return "verifying";
    case Trust::Paired:    return "paired";
    case Trust::Revoked:   return "revoked";
    }
    return "revoked";
}

const char* vfs_grant_name(VfsGrant grant) noexcept
{
    switch (grant) {
    case VfsGrant::Off:   return "off";
    case VfsGrant::Read:  return "read";
    case VfsGrant::Write: return "write";
    }
    return "off";
}

bool parse_vfs_grant(std::string_view text, VfsGrant& out) noexcept
{
    if (text == "off") {
        out = VfsGrant::Off;
        return true;
    }
    if (text == "read") {
        out = VfsGrant::Read;
        return true;
    }
    if (text == "write") {
        out = VfsGrant::Write;
        return true;
    }
    return false;
}

bool cidr_valid(std::string_view cidr) noexcept
{
    std::uint32_t net = 0;
    std::uint32_t mask = 0;
    return parse_cidr(cidr, net, mask);
}

bool cidr_contains(std::string_view cidr, std::string_view ipv4) noexcept
{
    std::uint32_t net = 0;
    std::uint32_t mask = 0;
    std::uint32_t address = 0;
    if (!parse_cidr(cidr, net, mask) || !parse_ipv4(ipv4, address))
        return false;
    return (address & mask) == net;
}

std::string cidr_of(std::string_view ipv4, int prefix_len)
{
    std::uint32_t address = 0;
    if (prefix_len < 0 || prefix_len > 32 || !parse_ipv4(ipv4, address))
        return {};
    const std::uint32_t mask = prefix_len == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix_len);
    return format_ipv4(address & mask) + "/" + std::to_string(prefix_len);
}

bool network_granted(const Grant& grant, std::string_view local_ipv4) noexcept
{
    for (const auto& cidr : grant.networks)
        if (cidr_contains(cidr, local_ipv4))
            return true;
    return false;
}

std::string derive_peer_id(std::string_view key)
{
    return sha256_hex(key).substr(0, 16);
}

bool peer_id_valid(std::string_view id) noexcept
{
    if (id.empty() || id.size() > 64)
        return false;
    for (unsigned char c : id) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                        c == '.' || c == '_' || c == '-' || c == ':';
        if (!ok)
            return false;
    }
    return true;
}

bool grant_scope_known(std::string_view scope) noexcept
{
    return scope == "files" || scope == "audio" || scope == "video" || scope == "chat" ||
           scope == "tools";
}

bool grant_set_scope(Grant& grant, std::string_view scope)
{
    if (scope == "files") {
        grant.vfs = VfsGrant::Write;
        return true;
    }
    if (scope == "audio") {
        grant.audio = "on";
        return true;
    }
    if (scope == "video") {
        grant.video = "on";
        return true;
    }
    if (scope == "chat") {
        grant.chat = "on";
        return true;
    }
    if (scope == "tools") {
        grant.tools = "on";
        return true;
    }
    return false;
}

std::vector<std::string> grant_scopes(const Grant& grant)
{
    // A projection of the semantic query. A scope is listed when its
    // capability allows use. `ask` and reserved capabilities never appear.
    struct Scope {
        const char* name;
        const char* capability;
        const char* operation;
    };
    const Scope table[] = {
        {"files", k_cap_vfs, "read"},
        {"audio", k_cap_audio_capture, "start"},
        {"video", k_cap_video_capture, "start"},
        {"chat", k_cap_chat_turn, "turn"},
        {"tools", k_cap_tools_call, "call"},
    };
    std::vector<std::string> scopes;
    for (const Scope& scope : table) {
        if (grant_authorize(grant, scope.capability, scope.operation, "") == Decision::Allow)
            scopes.emplace_back(scope.name);
    }
    return scopes;
}

bool capability_known(std::string_view id) noexcept
{
    return id == k_cap_vfs || id == k_cap_audio_capture || id == k_cap_video_capture ||
           id == k_cap_chat_turn || id == k_cap_tools_call;
}

bool capability_reserved(std::string_view id) noexcept
{
    return id == k_cap_audio_playback || id == k_cap_video_control || id == k_cap_chat_realtime ||
           id == k_cap_speech_stt || id == k_cap_speech_tts || id == k_cap_host_open;
}

std::vector<std::string> grant_resources(const Grant& grant, std::string_view capability)
{
    std::vector<std::string> out;
    const auto found = grant.capability_extra.find(std::string(capability));
    if (found == grant.capability_extra.end() || !found->second.is_object())
        return out;
    const auto it = found->second.find("resources");
    if (it == found->second.end() || !it->is_array())
        return out;
    for (const auto& item : *it) {
        if (item.is_string())
            out.push_back(item.get<std::string>());
    }
    return out;
}

bool grant_resource_allowed(const Grant& grant, std::string_view capability, std::string_view resource)
{
    const auto resources = grant_resources(grant, capability);
    if (resources.empty() || resource.empty())
        return true;
    // A vfs entry may name the mount bare (`photos`) or as `mount:photos`.
    constexpr std::string_view mount_prefix = "mount:";
    const bool vfs_mount = capability == k_cap_vfs && resource.substr(0, mount_prefix.size()) == mount_prefix;
    for (const auto& entry : resources) {
        if (resource_matches(entry, resource))
            return true;
        if (vfs_mount && resource_matches(entry, resource.substr(mount_prefix.size())))
            return true;
    }
    return false;
}

Decision grant_authorize(const Grant& grant, std::string_view capability, std::string_view operation,
                         std::string_view resource)
{
    if (!capability_known(capability))
        return Decision::Unsupported;
    Decision decision = Decision::Deny;
    if (capability == k_cap_vfs) {
        const bool read_op = operation == "list" || operation == "stat" || operation == "read" ||
                             operation == "resolve";
        const bool write_op = operation == "write" || operation == "mkdir" || operation == "move" ||
                              operation == "delete";
        if (grant.vfs == VfsGrant::Off) {
            if (grant.vfs_ask && (read_op || write_op))
                decision = Decision::Ask;
        } else if (read_op) {
            decision = Decision::Allow;
        } else if (write_op && grant.vfs == VfsGrant::Write) {
            decision = Decision::Allow;
        }
    } else {
        const std::string* level = nullptr;
        if (capability == k_cap_audio_capture)
            level = &grant.audio;
        else if (capability == k_cap_video_capture)
            level = &grant.video;
        else if (capability == k_cap_chat_turn)
            level = &grant.chat;
        else
            level = &grant.tools;
        if (*level == "on")
            decision = Decision::Allow;
        else if (*level == "ask")
            decision = Decision::Ask;
    }
    if (decision != Decision::Deny && !grant_resource_allowed(grant, capability, resource))
        return Decision::Deny;
    return decision;
}

int grant_capability_revision(const Grant& grant, std::string_view name) noexcept
{
    if (name == k_cap_vfs || name == "files")
        return grant.vfs_revision;
    if (name == k_cap_audio_capture || name == "audio")
        return grant.audio_revision;
    if (name == k_cap_video_capture || name == "video")
        return grant.video_revision;
    if (name == k_cap_chat_turn || name == "chat")
        return grant.chat_revision;
    if (name == k_cap_tools_call || name == "tools")
        return grant.tools_revision;
    return 0;
}

nlohmann::json allow_peer_json(const Grant& grant)
{
    nlohmann::json doc = nlohmann::json::object();
    const char* vfs_level = grant.vfs == VfsGrant::Off && grant.vfs_ask ? "ask" : vfs_grant_name(grant.vfs);
    nlohmann::json vfs = capability_json(grant, k_cap_vfs, grant.vfs_revision, vfs_level);
    if (!grant.networks.empty())
        vfs["conditions"]["networks"] = grant.networks;
    doc[k_cap_vfs] = std::move(vfs);
    doc[k_cap_audio_capture] =
        capability_json(grant, k_cap_audio_capture, grant.audio_revision, switch_level(grant.audio));
    doc[k_cap_video_capture] =
        capability_json(grant, k_cap_video_capture, grant.video_revision, switch_level(grant.video));
    doc[k_cap_chat_turn] =
        capability_json(grant, k_cap_chat_turn, grant.chat_revision, switch_level(grant.chat));
    doc[k_cap_tools_call] =
        capability_json(grant, k_cap_tools_call, grant.tools_revision, switch_level(grant.tools));
    for (const auto& entry : grant.unknown_capabilities) {
        // A known id is always written from the fields above.
        if (!capability_known(entry.first))
            doc[entry.first] = entry.second;
    }
    return doc;
}

bool allow_peer_from_json(const nlohmann::json& node, Grant& grant, std::string& err)
{
    grant = {};
    if (!node.is_object()) {
        err = "the pair file is not valid";
        return false;
    }
    for (auto it = node.begin(); it != node.end(); ++it) {
        const std::string& id = it.key();
        if (!capability_known(id)) {
            grant.unknown_capabilities[id] = it.value();
            continue;
        }
        int revision = 1;
        std::string level;
        nlohmann::json extra;
        if (!read_capability(it.value(), revision, level, extra, err))
            return false;
        if (id == k_cap_vfs) {
            grant.vfs_revision = revision;
            if (level == "ask") {
                // Stored, never use. `vfs` stays off.
                grant.vfs = VfsGrant::Off;
                grant.vfs_ask = true;
            } else if (!level.empty() && !parse_vfs_grant(level, grant.vfs)) {
                err = "the pair file is not valid";
                return false;
            }
            if (extra.contains("conditions")) {
                if (!extra["conditions"].is_object()) {
                    err = "the pair file is not valid";
                    return false;
                }
                nlohmann::json conditions = extra["conditions"];
                if (conditions.contains("networks")) {
                    if (!conditions["networks"].is_array()) {
                        err = "the pair file is not valid";
                        return false;
                    }
                    for (const auto& row : conditions["networks"]) {
                        if (!row.is_string() || !cidr_valid(row.get<std::string>())) {
                            err = "the pair file is not valid";
                            return false;
                        }
                        grant.networks.push_back(row.get<std::string>());
                    }
                    conditions.erase("networks");
                }
                if (conditions.empty())
                    extra.erase("conditions");
                else
                    extra["conditions"] = std::move(conditions);
            }
            keep_extra(grant, k_cap_vfs, std::move(extra));
            continue;
        }
        std::string* slot = nullptr;
        int* rev = nullptr;
        if (id == k_cap_audio_capture) {
            slot = &grant.audio;
            rev = &grant.audio_revision;
        } else if (id == k_cap_video_capture) {
            slot = &grant.video;
            rev = &grant.video_revision;
        } else if (id == k_cap_chat_turn) {
            slot = &grant.chat;
            rev = &grant.chat_revision;
        } else {
            slot = &grant.tools;
            rev = &grant.tools_revision;
        }
        if (!read_switch_level(level, *slot, err))
            return false;
        *rev = revision;
        keep_extra(grant, id.c_str(), std::move(extra));
    }
    return true;
}

void grant_clear(Grant& grant)
{
    grant.vfs = VfsGrant::Off;
    grant.vfs_ask = false;
    grant.audio = "off";
    grant.video = "off";
    grant.chat = "off";
    grant.tools = "off";
    grant.networks.clear();
    grant.capability_extra.clear();
    grant.unknown_capabilities.clear();
    ++grant.vfs_revision;
    ++grant.audio_revision;
    ++grant.video_revision;
    ++grant.chat_revision;
    ++grant.tools_revision;
    ++grant.revision;
}

void grant_succeed(Grant& next, const Grant& prev)
{
    next.revision = (std::max)(2, prev.revision + 1);
    next.vfs_revision = prev.vfs_revision + 1;
    next.audio_revision = prev.audio_revision + 1;
    next.video_revision = prev.video_revision + 1;
    next.chat_revision = prev.chat_revision + 1;
    next.tools_revision = prev.tools_revision + 1;
}

PairStore::PairStore(std::filesystem::path file, std::size_t max_peers)
    : file_(std::move(file)), max_peers_(max_peers == 0 ? 1 : max_peers)
{
}

bool PairStore::load(std::vector<Peer>& out, std::string& err) const
{
    std::string identity;
    return read_doc(file_, identity, out, err);
}

bool PairStore::load_identity(std::string& identity, std::vector<Peer>& out, std::string& err) const
{
    return read_doc(file_, identity, out, err);
}

bool PairStore::write(std::string_view identity, const std::vector<Peer>& rows, std::string& err) const
{
    if (rows.size() > max_peers_) {
        err = "too many paired devices";
        return false;
    }
    for (const auto& row : rows) {
        if (!peer_id_valid(row.id)) {
            err = "the pair file has a device id that is not valid";
            return false;
        }
    }
    std::lock_guard<std::mutex> lock(store_mutex());
    return write_doc(file_, identity, rows, err);
}

bool PairStore::find(std::string_view id, Peer& out, std::string& err) const
{
    std::vector<Peer> rows;
    std::string identity;
    if (!read_doc(file_, identity, rows, err))
        return false;
    const Peer* row = row_of(rows, id);
    if (!row) {
        err = "this device is not paired";
        return false;
    }
    out = *row;
    return true;
}

bool PairStore::ensure_peer(std::string_view id, std::string_view name, std::string_view tls_fp,
                            Peer& out, std::string& err) const
{
    if (!peer_id_valid(id)) {
        err = "the device id is not valid";
        return false;
    }
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    std::string identity;
    if (!read_doc(file_, identity, rows, err))
        return false;
    const std::string now = media::utc_now_iso8601();
    if (Peer* row = row_of(rows, id)) {
        const std::string label = media::strutil::clip_text(name, 80);
        const std::string fp = media::strutil::clip_text(tls_fp, 128);
        if (!label.empty())
            row->name = label;
        if (!fp.empty())
            row->tls_fp = fp;
        row->last_seen = now;
        out = *row;
        return write_doc(file_, identity, rows, err);
    }
    if (rows.size() >= max_peers_) {
        // A revoked row gives up its place. A paired one never does.
        const auto revoked = std::find_if(rows.begin(), rows.end(), [](const Peer& row) {
            return row.trust == Trust::Revoked;
        });
        if (revoked == rows.end()) {
            err = "this device is already paired with " + std::to_string(max_peers_) + " others";
            return false;
        }
        rows.erase(revoked);
    }
    Peer peer;
    peer.id = std::string(id);
    peer.name = media::strutil::clip_text(name, 80);
    peer.tls_fp = media::strutil::clip_text(tls_fp, 128);
    peer.trust = Trust::Paired;
    peer.created = now;
    peer.last_seen = now;
    rows.push_back(peer);
    if (!write_doc(file_, identity, rows, err))
        return false;
    out = std::move(peer);
    return true;
}

bool PairStore::set_dial(std::string_view id, std::string_view name, const std::vector<std::string>& urls,
                         std::string_view tls_fp, std::string_view dial_token, Peer& out,
                         std::string& err) const
{
    if (!peer_id_valid(id)) {
        err = "the device id is not valid";
        return false;
    }
    if (!pin_hex(tls_fp)) {
        err = "the peer certificate pin is not valid";
        return false;
    }
    if (urls.empty() || urls.size() > 8) {
        err = "a peer address is not usable";
        return false;
    }
    for (const auto& url : urls) {
        if (!https_url(url)) {
            err = "a peer address is not usable";
            return false;
        }
    }
    if (!wrapped_dial_token(dial_token)) {
        err = "the peer token is not valid";
        return false;
    }
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    std::string identity;
    if (!read_doc(file_, identity, rows, err))
        return false;
    const std::string now = media::utc_now_iso8601();
    if (Peer* row = row_of(rows, id)) {
        if (row->trust == Trust::Revoked) {
            err = "this device is revoked";
            return false;
        }
        const std::string label = media::strutil::clip_text(name, 80);
        if (!label.empty())
            row->name = label;
        row->tls_fp = std::string(tls_fp);
        row->urls.assign(urls.begin(), urls.end());
        if (!dial_token.empty())
            row->dial_token = std::string(dial_token);
        row->last_seen = now;
        out = *row;
        return write_doc(file_, identity, rows, err);
    }
    if (rows.size() >= max_peers_) {
        err = "this device is already paired with " + std::to_string(max_peers_) + " others";
        return false;
    }
    Peer peer;
    peer.id = std::string(id);
    peer.name = media::strutil::clip_text(name, 80);
    peer.tls_fp = std::string(tls_fp);
    peer.urls.assign(urls.begin(), urls.end());
    peer.dial_token = std::string(dial_token);
    peer.trust = Trust::Paired;
    peer.created = now;
    peer.last_seen = now;
    rows.push_back(peer);
    if (!write_doc(file_, identity, rows, err))
        return false;
    out = std::move(peer);
    return true;
}

bool PairStore::issue_token(std::string_view id, std::string& token, std::string& err) const
{
    token.clear();
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    std::string identity;
    if (!read_doc(file_, identity, rows, err))
        return false;
    Peer* row = row_of(rows, id);
    if (!row || row->trust != Trust::Paired) {
        err = "this device is not paired";
        return false;
    }
    std::array<std::uint8_t, 32> raw{};
    if (!random_bytes(raw.data(), raw.size())) {
        err = "no random source for a pair token";
        return false;
    }
    std::string fresh = "tn1_" + media::strutil::base64url(raw.data(), raw.size());
    row->token_sha256 = sha256_hex(fresh);
    row->last_seen = media::utc_now_iso8601();
    if (!write_doc(file_, identity, rows, err))
        return false;
    pm::node::sessions_cancel(id, "");
    token = std::move(fresh);
    return true;
}

bool PairStore::set_grant(std::string_view id, VfsGrant vfs, const std::vector<std::string>& networks,
                          Peer& out, std::string& err) const
{
    std::vector<std::string> clean;
    for (const auto& cidr : networks) {
        if (!cidr_valid(cidr)) {
            err = "\"" + media::strutil::clip_text(cidr, 40) + "\" is not a network like 192.168.1.0/24";
            return false;
        }
        // A grant names a network. `0.0.0.0/0` would name all of them.
        if (std::stoi(cidr.substr(cidr.find('/') + 1)) < k_min_grant_prefix) {
            err = "\"" + media::strutil::clip_text(cidr, 40) + "\" is wider than one network";
            return false;
        }
        if (std::find(clean.begin(), clean.end(), cidr) == clean.end())
            clean.push_back(cidr);
    }
    if (clean.size() > 16) {
        err = "at most 16 networks per device";
        return false;
    }
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    std::string identity;
    if (!read_doc(file_, identity, rows, err))
        return false;
    Peer* row = row_of(rows, id);
    if (!row || row->trust != Trust::Paired) {
        err = "this device is not paired";
        return false;
    }
    if (row->allow_peer.vfs != vfs || row->allow_peer.networks != clean) {
        row->allow_peer.vfs = vfs;
        if (vfs != VfsGrant::Off)
            row->allow_peer.vfs_ask = false;
        row->allow_peer.networks = std::move(clean);
        // Only the vfs capability changed. Audio, video, chat, and tools keep their revision.
        ++row->allow_peer.vfs_revision;
        ++row->allow_peer.revision;
        if (!write_doc(file_, identity, rows, err))
            return false;
        pm::node::sessions_cancel(id, "files");
    }
    out = *row;
    return true;
}

bool PairStore::set_caps(std::string_view id, VfsGrant vfs, bool audio, bool video, bool chat,
                         bool tools, Peer& out, std::string& err) const
{
    auto flag = [](bool on) { return on ? std::string("on") : std::string("off"); };
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    std::string identity;
    if (!read_doc(file_, identity, rows, err))
        return false;
    Peer* row = row_of(rows, id);
    if (!row || row->trust != Trust::Paired) {
        err = "this device is not paired";
        return false;
    }
    const std::string audio_flag = flag(audio);
    const std::string video_flag = flag(video);
    const std::string chat_flag = flag(chat);
    const std::string tools_flag = flag(tools);
    const bool same = row->allow_peer.vfs == vfs && row->allow_peer.audio == audio_flag
                      && row->allow_peer.video == video_flag && row->allow_peer.chat == chat_flag
                      && row->allow_peer.tools == tools_flag;
    if (same) {
        out = *row;
        return true;
    }
    // A capability revision moves only when that capability's switch changed.
    Grant& grant = row->allow_peer;
    std::vector<std::string> dropped;
    if (grant.vfs != vfs) {
        dropped.emplace_back("files");
        ++grant.vfs_revision;
    }
    if (grant.audio != audio_flag) {
        ++grant.audio_revision;
        if (!audio)
            dropped.emplace_back("audio");
    }
    if (grant.video != video_flag) {
        ++grant.video_revision;
        if (!video)
            dropped.emplace_back("video");
    }
    if (grant.chat != chat_flag) {
        ++grant.chat_revision;
        if (!chat)
            dropped.emplace_back("chat");
    }
    if (grant.tools != tools_flag) {
        ++grant.tools_revision;
        if (!tools)
            dropped.emplace_back("tools");
    }
    grant.vfs = vfs;
    if (vfs != VfsGrant::Off)
        grant.vfs_ask = false;
    grant.audio = audio_flag;
    grant.video = video_flag;
    grant.chat = chat_flag;
    grant.tools = tools_flag;
    ++grant.revision;
    if (!write_doc(file_, identity, rows, err))
        return false;
    for (const auto& capability : dropped)
        pm::node::sessions_cancel(id, capability);
    out = *row;
    return true;
}

bool PairStore::revoke(std::string_view id, std::string& err) const
{
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    std::string identity;
    if (!read_doc(file_, identity, rows, err))
        return false;
    Peer* row = row_of(rows, id);
    if (!row) {
        err = "this device is not paired";
        return false;
    }
    if (row->trust == Trust::Revoked)
        return true;
    row->trust = Trust::Revoked;
    grant_clear(row->allow_peer);
    if (!write_doc(file_, identity, rows, err))
        return false;
    pm::node::sessions_cancel(id, "");
    return true;
}

bool PairStore::forget(std::string_view id, std::string& err) const
{
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    std::string identity;
    if (!read_doc(file_, identity, rows, err))
        return false;
    const std::string key(id);
    std::vector<Peer> kept;
    kept.reserve(rows.size());
    bool found = false;
    for (const Peer& row : rows) {
        if (row.id == key) {
            found = true;
            continue;
        }
        kept.push_back(row);
    }
    if (found && !write_doc(file_, identity, kept, err))
        return false;
    if (found)
        pm::node::sessions_cancel(key, "");
    return true;
}

bool PairStore::repair(std::string_view id, Peer& out, std::string& err) const
{
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    std::string identity;
    if (!read_doc(file_, identity, rows, err))
        return false;
    Peer* row = row_of(rows, id);
    if (!row) {
        err = "this device is not paired";
        return false;
    }
    if (row->trust != Trust::Paired) {
        row->trust = Trust::Paired;
        row->token_sha256.clear();
        row->dial_token.clear();
        row->urls.clear();
        row->tls_fp.clear();
        grant_clear(row->allow_peer);
        row->last_seen = media::utc_now_iso8601();
        if (!write_doc(file_, identity, rows, err))
            return false;
        pm::node::sessions_cancel(id, "");
    }
    out = *row;
    return true;
}

Access PairStore::authorize(std::string_view token) const
{
    Access access;
    if (token.size() < 8 || token.size() > 256 || token.substr(0, 4) != "tn1_")
        return access;
    std::vector<Peer> rows;
    std::string identity;
    std::string err;
    if (!read_doc(file_, identity, rows, err))
        return access;
    const std::string hash = sha256_hex(token);
    for (const auto& row : rows) {
        if (row.token_sha256.empty() || !same_bytes(row.token_sha256, hash))
            continue;
        access.peer = row;
        access.verdict = row.trust == Trust::Paired ? Verdict::Paired : Verdict::Revoked;
        return access;
    }
    return access;
}

bool PairStore::any_peer_on(std::string_view local_ipv4) const
{
    std::vector<Peer> rows;
    std::string identity;
    std::string err;
    if (!read_doc(file_, identity, rows, err))
        return false;
    for (const auto& row : rows) {
        if (row.trust == Trust::Paired && network_granted(row.allow_peer, local_ipv4))
            return true;
    }
    return false;
}

} // namespace pm::lan
