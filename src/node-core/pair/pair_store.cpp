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

nlohmann::json grant_json(const Grant& grant)
{
    return {
        {"revision", grant.revision},
        {"vfs", vfs_grant_name(grant.vfs)},
        {"audio", grant.audio},
        {"video", grant.video},
        {"chat", grant.chat},
        {"tools", grant.tools},
        {"networks", grant.networks},
    };
}

bool read_switch(const nlohmann::json& node, const char* key, std::string& out, std::string& err)
{
    out = "off";
    if (!node.contains(key))
        return true;
    if (!node[key].is_string()) {
        err = "the pair file is not valid";
        return false;
    }
    const std::string value = node[key].get<std::string>();
    if (value != "on" && value != "off") {
        err = "the pair file is not valid";
        return false;
    }
    out = value;
    return true;
}

bool grant_from(const nlohmann::json& node, Grant& grant, std::string& err)
{
    grant = {};
    if (!node.is_object()) {
        err = "the pair file is not valid";
        return false;
    }
    if (node.contains("revision") && node["revision"].is_number_integer())
        grant.revision = (std::max)(1, node["revision"].get<int>());
    if (node.contains("vfs")) {
        if (!node["vfs"].is_string() ||
            !parse_vfs_grant(node["vfs"].get<std::string>(), grant.vfs)) {
            err = "the pair file is not valid";
            return false;
        }
    }
    if (!read_switch(node, "audio", grant.audio, err) ||
        !read_switch(node, "video", grant.video, err) ||
        !read_switch(node, "chat", grant.chat, err) ||
        !read_switch(node, "tools", grant.tools, err))
        return false;
    if (node.contains("networks") && node["networks"].is_array()) {
        for (const auto& row : node["networks"]) {
            if (!row.is_string() || !cidr_valid(row.get<std::string>())) {
                err = "the pair file is not valid";
                return false;
            }
            grant.networks.push_back(row.get<std::string>());
        }
    }
    return true;
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
    if (version != 1 && version != 2) {
        err = "the pair file is not valid";
        return false;
    }
    if (doc.contains("identity") && doc["identity"].is_string())
        identity = doc["identity"].get<std::string>();
    for (const auto& row : doc["devices"]) {
        if (!row.is_object() || (row.contains("scopes") && !row.contains("outbound"))) {
            err = row.contains("scopes") ? "pair file uses ticket scopes" : "the pair file is not valid";
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
        if (!grant_from(row.contains("outbound") ? row["outbound"] : nlohmann::json::object(),
                        peer.outbound, err))
            return false;
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
            {"outbound", grant_json(peer.outbound)},
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
        nlohmann::json{{"version", 2}, {"identity", std::string(identity)}, {"devices", std::move(devices)}}
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

void clear_caps(Grant& grant)
{
    grant.vfs = VfsGrant::Off;
    grant.audio = "off";
    grant.video = "off";
    grant.chat = "off";
    grant.tools = "off";
    grant.networks.clear();
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
    std::vector<std::string> scopes;
    if (grant.vfs != VfsGrant::Off)
        scopes.emplace_back("files");
    if (grant.audio == "on")
        scopes.emplace_back("audio");
    if (grant.video == "on")
        scopes.emplace_back("video");
    if (grant.chat == "on")
        scopes.emplace_back("chat");
    if (grant.tools == "on")
        scopes.emplace_back("tools");
    return scopes;
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
    if (row->outbound.vfs != vfs || row->outbound.networks != clean) {
        row->outbound.vfs = vfs;
        row->outbound.networks = std::move(clean);
        ++row->outbound.revision;
        if (!write_doc(file_, identity, rows, err))
            return false;
        pm::node::sessions_cancel(id, "files");
    }
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
    clear_caps(row->outbound);
    ++row->outbound.revision;
    if (!write_doc(file_, identity, rows, err))
        return false;
    pm::node::sessions_cancel(id, "");
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
        clear_caps(row->outbound);
        ++row->outbound.revision;
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
        if (row.trust == Trust::Paired && network_granted(row.outbound, local_ipv4))
            return true;
    }
    return false;
}

} // namespace pm::lan
