#include "pm/node/peer_book.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>

namespace pm::node {
namespace {

std::string default_clip(std::string_view text, std::size_t max)
{
    if (text.size() <= max)
        return std::string(text);
    return std::string(text.substr(0, max));
}

std::string default_utc_now_iso8601()
{
    using clock = std::chrono::system_clock;
    const auto t = clock::to_time_t(clock::now());
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

bool pin_ok(const std::string& pin)
{
    if (pin.size() != 64)
        return false;
    for (unsigned char c : pin) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
    }
    return true;
}

bool url_ok(const std::string& url)
{
    if (url.size() > 200 || url.rfind("https://", 0) != 0)
        return false;
    for (unsigned char c : url) {
        if (c <= 0x20 || c == 0x7f || c == '"' || c == '\\')
            return false;
    }
    return true;
}

nlohmann::json* row_of(nlohmann::json& rows, std::string_view id)
{
    for (auto& row : rows) {
        if (row.is_object() && row.value("id", std::string{}) == id)
            return &row;
    }
    return nullptr;
}

PeerBook g_default_book;

} // namespace

PeerBook& peer_book()
{
    return g_default_book;
}

void set_peer_book_hooks(PeerBookHooks hooks)
{
  peer_book().set_hooks(std::move(hooks));
}

void PeerBook::set_hooks(PeerBookHooks hooks)
{
    std::lock_guard lock(mu_);
    hooks_ = std::move(hooks);
}

bool PeerBook::is_device_mount(std::string_view mount) noexcept
{
    if (mount.size() < 7 || mount.size() > 64 || !mount.starts_with("phone-"))
        return false;
    for (unsigned char c : mount) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

std::filesystem::path PeerBook::peers_file() const
{
    if (!hooks_.config_dir)
        return {};
    return hooks_.config_dir() / "lan" / "peers.json";
}

std::filesystem::path PeerBook::devices_file() const
{
    if (!hooks_.config_dir)
        return {};
    return hooks_.config_dir() / "lan" / "devices.json";
}

std::filesystem::path PeerBook::mounts_cache_file() const
{
    if (!hooks_.config_dir)
        return {};
    return hooks_.config_dir() / "lan" / "phone-mounts-cache.json";
}

std::string PeerBook::clip_label(std::string_view name) const
{
    if (hooks_.clip_name)
        return hooks_.clip_name(name, 80);
    return default_clip(name, 80);
}

std::string PeerBook::now_iso() const
{
    if (hooks_.utc_now)
        return hooks_.utc_now();
    return default_utc_now_iso8601();
}

bool PeerBook::seal_dial_token(const std::string& token, std::string& stored, std::string& err) const
{
    if (token.size() > 256 || token.rfind("tn1_", 0) != 0) {
        err = "the peer token is not valid";
        return false;
    }
    if (!hooks_.seal_token) {
        err = "token storage is not configured";
        return false;
    }
    return hooks_.seal_token(token, stored, err);
}

std::string PeerBook::open_dial_token(const std::string& stored) const
{
    if (!hooks_.open_token)
        return {};
    return hooks_.open_token(stored);
}

namespace {

nlohmann::json read_doc(const std::filesystem::path& file)
{
    std::ifstream in(file, std::ios::binary);
    if (!in)
        return nlohmann::json::object();
    nlohmann::json doc = nlohmann::json::parse(in, nullptr, false);
    return doc.is_object() ? doc : nlohmann::json::object();
}

bool write_doc(const std::filesystem::path& file, const nlohmann::json& doc, std::string& err)
{
    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    std::filesystem::path tmp = file;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "could not store the phone";
            return false;
        }
        out << doc.dump(2);
        if (!out) {
            err = "could not store the phone";
            return false;
        }
    }
    std::filesystem::rename(tmp, file, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        err = "could not store the phone";
        return false;
    }
    return true;
}

} // namespace

std::vector<Peer> PeerBook::peers() const
{
    std::vector<Peer> out;
    auto already = [&](std::string_view id) {
        for (const auto& peer : out) {
            if (peer.id == id)
                return true;
        }
        return false;
    };

    const auto unwrap = [this](const std::string& stored) { return open_dial_token(stored); };

    auto take_urls = [](const nlohmann::json& row, Peer& peer) {
        if (!row.contains("urls") || !row["urls"].is_array())
            return;
        for (const auto& url : row["urls"]) {
            if (url.is_string() && url_ok(url.get<std::string>()) && peer.urls.size() < k_max_urls)
                peer.urls.push_back(url.get<std::string>());
        }
    };

    {
        const auto path = devices_file();
        if (!path.empty()) {
            std::ifstream in(path);
            nlohmann::json doc = nlohmann::json::parse(in, nullptr, false);
            if (doc.is_object()) {
                const char* list_key = doc.contains("devices") ? "devices" : "peers";
                if (doc.contains(list_key) && doc[list_key].is_array()) {
                    for (const auto& row : doc[list_key]) {
                        if (!row.is_object())
                            continue;
                        if (row.value("trust", std::string{}) == "revoked")
                            continue;
                        Peer peer;
                        peer.id = row.value("id", std::string{});
                        if (!is_device_mount(peer.id) || already(peer.id))
                            continue;
                        take_urls(row, peer);
                        peer.tls_fp = row.value("tls_fp", std::string{});
                        peer.token = unwrap(row.value("dial_token", row.value("token", std::string{})));
                        if (peer.urls.empty() || peer.tls_fp.empty() || peer.token.empty())
                            continue;
                        peer.name = row.value("name", std::string{});
                        peer.last_seen = row.value("last_seen", std::string{});
                        out.push_back(std::move(peer));
                    }
                }
            }
        }
    }

    const std::filesystem::path file = peers_file();
    if (file.empty())
        return out;
    const nlohmann::json doc = read_doc(file);
    if (!doc.contains("peers") || !doc["peers"].is_array())
        return out;
    for (const auto& row : doc["peers"]) {
        if (!row.is_object())
            continue;
        Peer peer;
        peer.id = row.value("id", std::string{});
        if (!is_device_mount(peer.id) || already(peer.id))
            continue;
        peer.name = row.value("name", std::string{});
        take_urls(row, peer);
        peer.tls_fp = row.value("tls_fp", std::string{});
        peer.token = unwrap(row.value("token", std::string{}));
        peer.pair = row.value("pair", std::string{});
        if (row.contains("inbound") && row["inbound"].is_object()) {
            peer.grant_revision = row["inbound"].value("revision", 0);
            peer.grant_vfs = row["inbound"].value("vfs", std::string{});
        }
        peer.last_seen = row.value("last_seen", std::string{});
        out.push_back(std::move(peer));
    }
    return out;
}

std::optional<Peer> PeerBook::find_peer(std::string_view authority) const
{
    for (auto peer : peers()) {
        if (peer.id == authority)
            return peer;
    }
    return std::nullopt;
}

bool PeerBook::store_peer(std::string_view authority, const std::string& name,
                          const std::vector<std::string>& urls, const std::string& token,
                          const std::string& tls_fp, const std::string& owner, bool& holds_token,
                          std::string& err)
{
    holds_token = false;
    if (!is_device_mount(authority)) {
        err = "the phone name is not valid";
        return false;
    }
    if (!pin_ok(tls_fp)) {
        err = "the phone certificate pin is not valid";
        return false;
    }
    nlohmann::json clean = nlohmann::json::array();
    for (const auto& url : urls) {
        if (!url_ok(url)) {
            err = "a phone address is not usable";
            return false;
        }
        if (clean.size() < k_max_urls)
            clean.push_back(url);
    }
    std::string stored_token;
    if (!token.empty()) {
        if (token.size() > 256 || token.rfind("tn1_", 0) != 0) {
            err = "the phone token is not valid";
            return false;
        }
        if (!hooks_.seal_token) {
            err = "token storage is not configured";
            return false;
        }
        if (!hooks_.seal_token(token, stored_token, err))
            return false;
    }
    const std::filesystem::path file = peers_file();
    if (file.empty()) {
        err = "the peer book is not configured";
        return false;
    }
    std::lock_guard lock(mu_);
    nlohmann::json doc = read_doc(file);
    if (!doc.contains("peers") || !doc["peers"].is_array())
        doc["peers"] = nlohmann::json::array();
    doc["version"] = 1;
    nlohmann::json& rows = doc["peers"];
    nlohmann::json* row = row_of(rows, authority);
    if (!row) {
        if (rows.size() >= k_max_peers) {
            err = "this computer already knows " + std::to_string(k_max_peers) + " phones";
            return false;
        }
        nlohmann::json fresh = nlohmann::json::object();
        fresh["id"] = std::string(authority);
        rows.push_back(std::move(fresh));
        row = &rows.back();
    }
    const std::string label = clip_label(name);
    if (!label.empty())
        (*row)["name"] = label;
    if (row->value("pair", std::string{}) != owner) {
        row->erase("token");
        row->erase("inbound");
        (*row)["pair"] = owner;
    }
    (*row)["urls"] = std::move(clean);
    (*row)["tls_fp"] = tls_fp;
    if (!stored_token.empty()) {
        (*row)["token"] = stored_token;
        row->erase("inbound");
    }
    (*row)["last_seen"] = now_iso();
    holds_token = !open_dial_token(row->value("token", std::string{})).empty();
    return write_doc(file, doc, err);
}

void PeerBook::drop_token(std::string_view authority)
{
    const std::filesystem::path file = peers_file();
    if (file.empty())
        return;
    std::lock_guard lock(mu_);
    nlohmann::json doc = read_doc(file);
    if (!doc.contains("peers") || !doc["peers"].is_array())
        return;
    nlohmann::json* row = row_of(doc["peers"], authority);
    if (!row || !row->contains("token"))
        return;
    row->erase("token");
    row->erase("inbound");
    std::string err;
    (void)write_doc(file, doc, err);
}

void PeerBook::drop_token_if_matches(std::string_view authority, std::string_view expected)
{
    if (expected.empty())
        return;
    const std::filesystem::path file = peers_file();
    if (file.empty())
        return;
    std::lock_guard lock(mu_);
    nlohmann::json doc = read_doc(file);
    if (!doc.contains("peers") || !doc["peers"].is_array())
        return;
    nlohmann::json* row = row_of(doc["peers"], authority);
    if (!row || !row->contains("token"))
        return;
    const std::string current = open_dial_token(row->value("token", std::string{}));
    if (current != expected)
        return;
    row->erase("token");
    row->erase("inbound");
    std::string err;
    (void)write_doc(file, doc, err);
}

void PeerBook::note_grant(std::string_view authority, int revision, const std::string& vfs)
{
    if (revision <= 0)
        return;
    const std::filesystem::path file = peers_file();
    if (file.empty())
        return;
    std::lock_guard lock(mu_);
    nlohmann::json doc = read_doc(file);
    if (!doc.contains("peers") || !doc["peers"].is_array())
        return;
    nlohmann::json* row = row_of(doc["peers"], authority);
    if (!row)
        return;
    const bool have = row->contains("inbound") && (*row)["inbound"].is_object();
    const int known = have ? (*row)["inbound"].value("revision", 0) : 0;
    const std::string known_vfs = have ? (*row)["inbound"].value("vfs", std::string{}) : std::string{};
    if (have && revision == known && vfs == known_vfs)
        return;
    (*row)["inbound"] = {{"revision", revision}, {"vfs", vfs}};
    std::string err;
    (void)write_doc(file, doc, err);
}

void PeerBook::forget_revoked_device(std::string_view id)
{
    if (id.empty())
        return;
    std::vector<std::string> gone;
  {
        const std::filesystem::path file = peers_file();
        if (!file.empty()) {
            std::lock_guard lock(mu_);
            nlohmann::json doc = read_doc(file);
            if (doc.contains("peers") && doc["peers"].is_array()) {
                nlohmann::json kept = nlohmann::json::array();
                for (auto& row : doc["peers"]) {
                    if (!row.is_object())
                        continue;
                    const std::string row_id = row.value("id", std::string{});
                    if (row_id == id || row.value("pair", std::string{}) == id) {
                        if (!row_id.empty())
                            gone.push_back(row_id);
                        continue;
                    }
                    kept.push_back(std::move(row));
                }
                if (kept.size() != doc["peers"].size()) {
                    doc["peers"] = std::move(kept);
                    std::string err;
                    (void)write_doc(file, doc, err);
                }
            }
        }
    }
    gone.push_back(std::string(id));
    const std::filesystem::path cache = mounts_cache_file();
    if (cache.empty())
        return;
    std::ifstream in(cache, std::ios::binary);
    if (!in)
        return;
    nlohmann::json doc = nlohmann::json::parse(in, nullptr, false);
    in.close();
    if (!doc.is_object() || !doc.contains("peers") || !doc["peers"].is_object())
        return;
    bool changed = false;
    for (const auto& key : gone) {
        if (doc["peers"].contains(key)) {
            doc["peers"].erase(key);
            changed = true;
        }
    }
    if (!changed)
        return;
    std::error_code ec;
    std::filesystem::path tmp = cache;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out)
            return;
        out << doc.dump();
        if (!out)
            return;
    }
    std::filesystem::rename(tmp, cache, ec);
    if (ec)
        std::filesystem::remove(tmp, ec);
}

bool PeerBook::forget_peer(std::string_view authority, std::string& err)
{
    const std::filesystem::path file = peers_file();
    if (file.empty()) {
        err = "the peer book is not configured";
        return false;
    }
    std::lock_guard lock(mu_);
    nlohmann::json doc = read_doc(file);
    if (!doc.contains("peers") || !doc["peers"].is_array())
        return true;
    nlohmann::json kept = nlohmann::json::array();
    for (auto& row : doc["peers"]) {
        if (!row.is_object() || row.value("id", std::string{}) != authority)
            kept.push_back(std::move(row));
    }
    doc["peers"] = std::move(kept);
    return write_doc(file, doc, err);
}

} // namespace pm::node