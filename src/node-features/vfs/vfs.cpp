#include "pm/server/vfs.hpp"

#include "fs/path_sanitizer.hpp"
#include "logging/logger.h"
#include "pm/vfs/store.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>
#include "string/string_utils.hpp"

namespace media_cli {
namespace {

constexpr std::size_t k_max_body = 8u * 1024u * 1024u;
/// Hard page cap when the caller omits `limit` — keeps huge folders from
/// monopolizing an HTTP worker. Clients page with `after=<next>`.
constexpr std::size_t k_list_default_limit = 5000;
constexpr std::size_t k_store_cache_max = 16;
constexpr int k_transfer_max = 2;
constexpr int k_transfer_waiters = 2;
constexpr int k_transfer_wait_ms = 8000;

using SharedRoot = VfsRoot;

void send_json(httplib::Response& res, int status, const nlohmann::json& body)
{
    res.status = status;
    res.set_content(body.dump(), "application/json; charset=utf-8");
}

nlohmann::json fail_body(const std::string& code, const std::string& message)
{
    return {{"ok", false}, {"code", code}, {"error", message}};
}

const SharedRoot* find_root(const std::vector<SharedRoot>& roots, const std::string& name)
{
    for (const auto& root : roots)
        if (root.name == name)
            return &root;
    return nullptr;
}

std::string roots_fingerprint(const std::vector<SharedRoot>& roots)
{
    std::string fp;
    fp.reserve(roots.size() * 64);
    for (const auto& root : roots) {
        fp.append(root.name);
        fp.push_back('\0');
        fp.append(root.path);
        fp.push_back('\0');
    }
    return fp;
}

pm::vfs::Store open_store(const std::vector<SharedRoot>& roots, pm::vfs::Error& err)
{
    std::vector<pm::vfs::Mount> mounts;
    mounts.reserve(roots.size());
    for (const auto& root : roots) {
        pm::vfs::Mount m;
        m.name = root.name;
        m.type = "fs";
        m.root = media::path::path_from_utf8(root.path);
        mounts.push_back(std::move(m));
    }
    return pm::vfs::Store::open_mounts(std::move(mounts), err);
}

/// Reuses immutable Store instances while the published mount set is unchanged.
struct StoreRegistry {
    std::mutex mu;
    std::unordered_map<std::string, std::shared_ptr<const pm::vfs::Store>> entries;

    std::shared_ptr<const pm::vfs::Store> get(const std::vector<SharedRoot>& roots, pm::vfs::Error& err)
    {
        const auto fp = roots_fingerprint(roots);
        {
            std::lock_guard<std::mutex> lock(mu);
            const auto it = entries.find(fp);
            if (it != entries.end())
                return it->second;
        }
        auto built = std::make_shared<pm::vfs::Store>(open_store(roots, err));
        if (err)
            return nullptr;
        std::lock_guard<std::mutex> lock(mu);
        auto [it, inserted] = entries.emplace(fp, built);
        if (!inserted)
            return it->second;
        while (entries.size() > k_store_cache_max) {
            // Drop an arbitrary older entry; fingerprints are small and rebuild is cheap.
            if (entries.begin()->first == fp) {
                auto victim = std::next(entries.begin());
                if (victim == entries.end())
                    break;
                entries.erase(victim);
            } else {
                entries.erase(entries.begin());
            }
        }
        return built;
    }
};

/// Caps concurrent stream/download/upload work so listing and control routes
/// keep free HTTP workers.
class TransferGate {
public:
    explicit TransferGate(int max_n, int max_waiting)
        : max_n_(max_n < 1 ? 1 : max_n)
        , max_waiting_(max_waiting < 0 ? 0 : max_waiting)
    {
    }

    class Slot {
    public:
        Slot(TransferGate& gate, int wait_ms) : g_(&gate)
        {
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(wait_ms > 0 ? wait_ms : 1);
            std::unique_lock<std::mutex> lock(g_->mu_);
            if (g_->inflight_ >= g_->max_n_) {
                if (g_->max_waiting_ > 0 && g_->waiting_ >= g_->max_waiting_) {
                    g_ = nullptr;
                    return;
                }
                ++g_->waiting_;
                const bool got = g_->cv_.wait_until(lock, deadline, [&] {
                    return g_->inflight_ < g_->max_n_;
                });
                --g_->waiting_;
                if (!got) {
                    g_ = nullptr;
                    return;
                }
            }
            ++g_->inflight_;
        }
        ~Slot()
        {
            if (!g_)
                return;
            {
                std::lock_guard<std::mutex> lock(g_->mu_);
                --g_->inflight_;
            }
            g_->cv_.notify_one();
        }
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        bool ok() const { return g_ != nullptr; }
        explicit operator bool() const { return ok(); }

    private:
        TransferGate* g_ = nullptr;
    };

private:
    std::mutex mu_;
    std::condition_variable cv_;
    int max_n_ = 1;
    int max_waiting_ = 0;
    int inflight_ = 0;
    int waiting_ = 0;
};

pm::vfs::OperationContext op_ctx(const LlmVfsAccess& access)
{
    pm::vfs::OperationContext ctx;
    ctx.still_granted = access.still_granted;
    return ctx;
}

nlohmann::json node_json(const pm::vfs::Node& node)
{
    return {
        {"name", node.name},
        {"path", node.path},
        {"size", node.size},
        {"mtime", node.mtime},
        {"mime", node.mime},
        {"parent", node.parent},
        {"type", node.type},
    };
}

void send_store_error(httplib::Response& res, const pm::vfs::Error& err)
{
    const int status = err.status ? err.status : pm::vfs::vfs_errno_status(err.code);
    send_json(res, status, fail_body(
        pm::vfs::canonical_vfs_errno(err.code),
        err.message.empty() ? pm::vfs::default_vfs_message(err.code) : err.message));
}

struct Located {
    std::string mount;
    std::string path;
};

bool query_location(const httplib::Request& req, Located& loc, std::string& err)
{
    loc.mount = req.get_param_value("mount");
    loc.path = req.get_param_value("path");
    if (loc.mount.empty()) {
        err = "mount is required";
        return false;
    }
    return true;
}

bool json_string_field(const nlohmann::json& body, const char* key, std::string& out, std::string& err,
                       bool required)
{
    out.clear();
    if (!body.is_object()) {
        err = "Expected JSON object";
        return false;
    }
    const auto it = body.find(key);
    if (it == body.end()) {
        if (required) {
            err = std::string(key) + " is required";
            return false;
        }
        return true;
    }
    if (!it->is_string()) {
        err = std::string(key) + " must be a string";
        return false;
    }
    out = it->get<std::string>();
    if (required && out.empty()) {
        err = std::string(key) + " is required";
        return false;
    }
    return true;
}

bool body_location(const nlohmann::json& body, Located& loc, std::string& err)
{
    return json_string_field(body, "mount", loc.mount, err, true)
        && json_string_field(body, "path", loc.path, err, false);
}

bool body_bool_field(const nlohmann::json& body, const char* key, bool& out, std::string& err)
{
    out = false;
    if (!body.is_object()) {
        err = "Expected JSON object";
        return false;
    }
    const auto it = body.find(key);
    if (it == body.end())
        return true;
    if (!it->is_boolean()) {
        err = std::string(key) + " must be a boolean";
        return false;
    }
    out = it->get<bool>();
    return true;
}

/// UNC / device-namespace paths are rejected before any filesystem call.
bool is_network_or_device_path(std::string_view raw)
{
    if (raw.size() >= 2
        && ((raw[0] == '\\' && raw[1] == '\\') || (raw[0] == '/' && raw[1] == '/')))
        return true;
    if (raw.size() >= 4 && raw[0] == '\\' && raw[1] == '?' && raw[2] == '?' && raw[3] == '\\')
        return true;
    return false;
}

bool absolute_request(std::string_view raw)
{
    if (is_network_or_device_path(raw))
        return false;
    if (raw.size() >= 3 &&
        ((raw[0] >= 'A' && raw[0] <= 'Z') || (raw[0] >= 'a' && raw[0] <= 'z')) &&
        raw[1] == ':' && (raw[2] == '\\' || raw[2] == '/'))
        return true;
#ifndef _WIN32
    if (!raw.empty() && raw[0] == '/')
        return true;
#endif
    return false;
}

std::string fold_key(const std::filesystem::path& path)
{
    std::string key = media::path::path_to_generic_utf8(path.lexically_normal());
#ifdef _WIN32
    key = media::strutil::lower_ascii(std::move(key));
#endif
    // Keep a drive-root trailing slash (`c:/`); strip longer trailing slashes.
    while (key.size() > 3 && key.back() == '/')
        key.pop_back();
    return key;
}

bool key_inside(const std::string& file_key, const std::string& root_key)
{
    if (root_key.empty() || file_key.empty())
        return false;
    if (file_key == root_key)
        return true;
    if (file_key.size() <= root_key.size())
        return false;
    if (file_key.compare(0, root_key.size(), root_key) != 0)
        return false;
    if (root_key.back() == '/')
        return true;
    return file_key[root_key.size()] == '/';
}

std::filesystem::path canonical_abs(const std::filesystem::path& input, std::error_code& ec)
{
    ec.clear();
    std::filesystem::path abs = std::filesystem::absolute(input, ec);
    if (ec)
        return {};
    const std::filesystem::path canon = std::filesystem::weakly_canonical(abs, ec);
    if (ec)
        return {};
    return canon.lexically_normal();
}

bool relative_components_ok(std::string_view rel) noexcept
{
    if (rel.empty())
        return false;
    std::size_t i = 0;
    while (i < rel.size()) {
        if (rel[i] == '/')
            return false;
        const auto slash = rel.find('/', i);
        const auto end = slash == std::string_view::npos ? rel.size() : slash;
        const auto part = rel.substr(i, end - i);
        if (part.empty() || part == "." || part == "..")
            return false;
        if (end == rel.size())
            break;
        i = end + 1;
    }
    return true;
}

std::string encode_segment(std::string_view seg)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(seg.size());
    for (unsigned char c : seg) {
        const bool plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (plain) {
            out.push_back(static_cast<char>(c));
            continue;
        }
        out.push_back('%');
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0f]);
    }
    return out;
}

std::string vfs_uri(const std::string& authority, const std::string& mount, const std::string& rel)
{
    std::string uri = "vfs://" + authority + "/" + mount;
    if (rel.empty())
        return uri;
    uri.push_back('/');
    std::size_t start = 0;
    while (start <= rel.size()) {
        const auto slash = rel.find('/', start);
        const auto count = slash == std::string::npos ? std::string::npos : slash - start;
        uri += encode_segment(rel.substr(start, count));
        if (slash == std::string::npos)
            break;
        uri.push_back('/');
        start = slash + 1;
    }
    return uri;
}

struct SharedHit {
    std::string mount;
    std::string rel;
    std::string uri;
};

struct CanonRoot {
    const SharedRoot* root = nullptr;
    std::filesystem::path folder;
    std::string key;
};

std::vector<CanonRoot> prepare_roots(const std::vector<SharedRoot>& roots)
{
    std::vector<CanonRoot> out;
    out.reserve(roots.size());
    for (const auto& root : roots) {
        if (root.path.empty() || is_network_or_device_path(root.path))
            continue;
        std::error_code ec;
        const std::filesystem::path folder = canonical_abs(media::path::path_from_utf8(root.path), ec);
        if (ec || folder.empty())
            continue;
        const std::string key = fold_key(folder);
        if (key.empty())
            continue;
        out.push_back(CanonRoot{&root, folder, key});
    }
    return out;
}

std::optional<SharedHit> locate_in(
    const std::filesystem::path& file, const std::vector<CanonRoot>& prepared, const std::string& authority)
{
    if (file.empty() || prepared.empty())
        return std::nullopt;
    const std::string file_key = fold_key(file);
    const CanonRoot* best = nullptr;
    for (const auto& root : prepared) {
        if (!key_inside(file_key, root.key))
            continue;
        if (!best || root.key.size() > best->key.size())
            best = &root;
    }
    if (!best || !best->root)
        return std::nullopt;
    std::string rel = media::path::path_to_generic_utf8(file.lexically_relative(best->folder));
    if (rel == ".")
        rel.clear();
    if (!rel.empty() && !relative_components_ok(rel))
        return std::nullopt;
    SharedHit hit;
    hit.mount = best->root->name;
    hit.rel = std::move(rel);
    hit.uri = vfs_uri(authority, best->root->name, hit.rel);
    return hit;
}

std::optional<SharedHit> locate(
    const std::string& raw, const std::vector<SharedRoot>& roots, const std::string& authority)
{
    if (raw.empty() || raw.size() > 4096 || is_network_or_device_path(raw) || !absolute_request(raw))
        return std::nullopt;
    try {
        std::error_code ec;
        const std::filesystem::path file = canonical_abs(media::path::path_from_utf8(raw), ec);
        if (ec || file.empty())
            return std::nullopt;
        return locate_in(file, prepare_roots(roots), authority);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// A relative path is shared only when the file exists in exactly one bookmark.
// This stats the candidate; it does not read the file.
std::optional<SharedHit> locate_relative(
    const std::string& raw, const std::vector<SharedRoot>& roots, const std::string& authority)
{
    if (raw.empty() || raw.size() > 4096 || is_network_or_device_path(raw) || absolute_request(raw))
        return std::nullopt;
    std::string rel = raw;
    for (char& c : rel) {
        if (c == '\\')
            c = '/';
    }
    while (!rel.empty() && (rel.front() == '/' || rel.front() == ' '))
        rel.erase(rel.begin());
    if (rel.rfind("./", 0) == 0)
        rel.erase(0, 2);
    if (rel.empty() || rel.find(':') != std::string::npos || !relative_components_ok(rel))
        return std::nullopt;

    std::optional<SharedHit> found;
    try {
        const auto prepared = prepare_roots(roots);
        for (const auto& root : prepared) {
            std::error_code ec;
            const std::filesystem::path candidate = root.folder / media::path::path_from_utf8(rel);
            if (!std::filesystem::is_regular_file(candidate, ec) || ec)
                continue;
            const auto canon = canonical_abs(candidate, ec);
            if (ec || canon.empty())
                continue;
            const auto hit = locate_in(canon, prepared, authority);
            if (!hit)
                continue;
            if (found)
                return std::nullopt;
            found = hit;
        }
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return found;
}

nlohmann::json resolve_item(
    const std::string& path, const std::vector<SharedRoot>& roots, const std::string& authority)
{
    nlohmann::json row = {{"path", path}, {"shared", false}};
    auto hit = locate(path, roots, authority);
    if (!hit)
        hit = locate_relative(path, roots, authority);
    if (hit) {
        row["shared"] = true;
        row["uri"] = hit->uri;
        row["mount"] = hit->mount;
        row["rel"] = hit->rel;
    }
    return row;
}

void send_shared_bytes(
    httplib::Response& res,
    StoreRegistry& registry,
    TransferGate& transfers,
    const std::vector<SharedRoot>& roots,
    const std::string& authority,
    const std::string& mount,
    const std::string& rel,
    const LlmVfsAccess& access)
{
    if (!find_root(roots, mount)) {
        send_json(res, 404, fail_body("ENOENT", "unknown mount"));
        return;
    }
    auto slot = std::make_shared<TransferGate::Slot>(transfers, k_transfer_wait_ms);
    if (!*slot) {
        send_json(res, 503, fail_body("EBUSY", "too many transfers in progress"));
        return;
    }
    pm::vfs::Error open_err;
    const auto store = registry.get(roots, open_err);
    if (open_err || !store) {
        send_store_error(res, open_err);
        return;
    }
    // Jail + open as one Store step. Stream from the retained handle.
    const auto opened = store->open_read(pm::vfs::Caller{}, mount, rel, op_ctx(access));
    if (opened.error || !opened.file) {
        send_store_error(res, opened.error);
        return;
    }
    if (opened.file->size > static_cast<std::uint64_t>((std::numeric_limits<size_t>::max)())) {
        send_json(res, 413, fail_body("EFBIG", "file is too large to stream on this host"));
        return;
    }
    const std::string mime = opened.file->node.mime.empty() ? std::string{"application/octet-stream"}
                                                            : opened.file->node.mime;
    res.set_header("X-Vfs-Mount", mount);
    res.set_header("X-Vfs-Uri", vfs_uri(authority, mount, rel));
    res.set_header("Accept-Ranges", "bytes");
    auto session = opened.file;
    auto still = access.still_granted;
    auto buffer = std::make_shared<std::vector<char>>(256 * 1024);
    res.set_content_provider(
        static_cast<size_t>(session->size),
        mime,
        [session, still, buffer, slot](size_t offset, size_t length, httplib::DataSink& sink) {
            if (still && !still())
                return false;
            if (!session || !session->file)
                return false;
            if (offset > session->size)
                return false;
            if (!session->file.seek(offset))
                return false;
            size_t left = length;
            while (left > 0) {
                if (still && !still())
                    return false;
                const size_t chunk = (std::min)(left, buffer->size());
                pm::vfs::Error read_err;
                const size_t got = session->file.read(buffer->data(), chunk, read_err);
                if (read_err || got == 0)
                    return false;
                if (!sink.write(buffer->data(), got))
                    return false;
                left -= got;
            }
            return left == 0;
        });
}

/// Mounts this caller may see. Unrestricted access requires `full` or `all_mounts`.
std::vector<SharedRoot> visible_roots(std::vector<SharedRoot> roots, const LlmVfsAccess& access)
{
    if (access.full || access.all_mounts) {
        if (!access.mount_allowed)
            return roots;
        roots.erase(std::remove_if(roots.begin(), roots.end(),
                                   [&access](const SharedRoot& root) {
                                       return !access.mount_allowed(root.name);
                                   }),
                    roots.end());
        return roots;
    }
    if (!access.mount_allowed)
        return {};
    roots.erase(std::remove_if(roots.begin(), roots.end(),
                               [&access](const SharedRoot& root) {
                                   return !access.mount_allowed(root.name);
                               }),
                roots.end());
    return roots;
}

/// What the caller may do on a mount. `write` also means mkdir, move, delete, touch.
nlohmann::json can_json(const LlmVfsAccess& access)
{
    if (access.full || access.write)
        return nlohmann::json::array(
            {"list", "stat", "read", "write", "mkdir", "move", "delete", "touch"});
    return nlohmann::json::array({"list", "stat", "read"});
}

bool write_allowed(const LlmVfsAccess& access, httplib::Response& res)
{
    if (access.full || access.write)
        return true;
    nlohmann::json body = fail_body("EGRANT", "write is not granted");
    if (access.grant_revision > 0) {
        body["vfs_revision"] = access.grant_revision;
        body["vfs"] = "read";
    }
    send_json(res, 403, body);
    return false;
}

} // namespace

bool vfs_authority_valid(std::string_view authority) noexcept
{
    if (authority.empty() || authority.size() > 64)
        return false;
    for (unsigned char c : authority) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

std::optional<SharedFileRef> shared_file_for_path(
    std::string_view absolute, const std::vector<VfsRoot>& roots, std::string_view authority)
{
    if (!vfs_authority_valid(authority))
        return std::nullopt;
    const auto hit = locate(std::string(absolute), roots, std::string(authority));
    if (!hit)
        return std::nullopt;
    return SharedFileRef{hit->mount, hit->rel, hit->uri};
}

void register_llm_vfs_routes(httplib::Server& svr, LlmVfsHost host)
{
    if (!vfs_authority_valid(host.authority) || !host.authorize) {
        logger::warn("vfs routes are off: the node gave no usable authority");
        return;
    }
    const std::string authority = host.authority;
    const LlmVfsAuthorize authorize = host.authorize;
    const auto shared_roots = [provider = host.roots]() -> std::vector<SharedRoot> {
        return provider ? provider() : std::vector<SharedRoot>{};
    };
    const auto registry = std::make_shared<StoreRegistry>();
    const auto transfers = std::make_shared<TransferGate>(k_transfer_max, k_transfer_waiters);
    auto guard = [authorize](const httplib::Request& req, httplib::Response& res, LlmVfsAccess& access) {
        access = {};
        if (!authorize(req, res, access))
            return false;
        if (!access.full && !access.files) {
            res.status = 403;
            send_json(res, 403, fail_body("EACCES", "files scope is required"));
            return false;
        }
        return true;
    };

    svr.Get("/v1/vfs/mounts", [guard, shared_roots, authority](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access))
            return;
        nlohmann::json mounts = nlohmann::json::array();
        for (const auto& root : visible_roots(shared_roots(), access)) {
            mounts.push_back({
                {"name", root.name},
                {"label", root.label.empty() ? root.name : root.label},
                {"uri", vfs_uri(authority, root.name, {})},
                {"host", authority},
                {"kind", "folder"},
                {"can", can_json(access)},
            });
        }
        send_json(res, 200, {{"ok", true}, {"mounts", std::move(mounts)}});
    });

    svr.Get("/v1/vfs/list", [guard, shared_roots, authority, registry](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access))
            return;
        Located loc;
        std::string err;
        if (!query_location(req, loc, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        const auto roots = visible_roots(shared_roots(), access);
        if (!find_root(roots, loc.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        std::size_t limit = k_list_default_limit;
        if (req.has_param("limit")) {
            try {
                const auto raw = std::stoll(req.get_param_value("limit"));
                if (raw < 0) {
                    send_json(res, 400, fail_body("EINVAL", "limit must be non-negative"));
                    return;
                }
                limit = raw == 0 ? k_list_default_limit
                                 : (std::min)(static_cast<std::size_t>(raw), k_list_default_limit);
            } catch (...) {
                send_json(res, 400, fail_body("EINVAL", "limit is not a number"));
                return;
            }
        }
        const std::string after = req.get_param_value("after");
        pm::vfs::Error open_err;
        const auto store = registry->get(roots, open_err);
        if (open_err || !store) {
            send_store_error(res, open_err);
            return;
        }
        const auto listed = store->list(pm::vfs::Caller{}, loc.mount, loc.path, {}, limit, after);
        if (listed.error) {
            send_store_error(res, listed.error);
            return;
        }
        nlohmann::json entries = nlohmann::json::array();
        for (const auto& node : listed.entries)
            entries.push_back(node_json(node));
        nlohmann::json body = {
            {"ok", true},
            {"mount", loc.mount},
            {"uri", vfs_uri(authority, loc.mount, loc.path)},
            {"can", can_json(access)},
            {"entries", std::move(entries)},
        };
        if (!listed.next.empty())
            body["next"] = listed.next;
        send_json(res, 200, body);
    });

    svr.Get("/v1/vfs/stat", [guard, shared_roots, registry](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access))
            return;
        Located loc;
        std::string err;
        if (!query_location(req, loc, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        const auto roots = visible_roots(shared_roots(), access);
        if (!find_root(roots, loc.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        pm::vfs::Error open_err;
        const auto store = registry->get(roots, open_err);
        if (open_err || !store) {
            send_store_error(res, open_err);
            return;
        }
        const auto st = store->stat(pm::vfs::Caller{}, loc.mount, loc.path);
        if (st.error) {
            send_store_error(res, st.error);
            return;
        }
        send_json(res, 200, {{"ok", true}, {"mount", loc.mount}, {"node", node_json(st.node)}});
    });

    auto resolve_paths = [shared_roots, authority](
                             const LlmVfsAccess& access, const nlohmann::json& paths,
                             nlohmann::json& items, std::string& err) {
        if (!paths.is_array()) {
            err = "paths must be an array";
            return false;
        }
        if (paths.size() > 64) {
            err = "at most 64 paths";
            return false;
        }
        const auto roots = visible_roots(shared_roots(), access);
        for (const auto& row : paths) {
            if (!row.is_string()) {
                items.push_back({{"path", nullptr}, {"shared", false}, {"error", "path must be a string"}});
                continue;
            }
            items.push_back(resolve_item(row.get<std::string>(), roots, authority));
        }
        return true;
    };

    svr.Get("/v1/vfs/resolve", [guard, resolve_paths](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access))
            return;
        const std::string path = req.get_param_value("path");
        if (path.empty()) {
            send_json(res, 400, fail_body("EINVAL", "path is required"));
            return;
        }
        nlohmann::json items = nlohmann::json::array();
        nlohmann::json batch = nlohmann::json::array();
        batch.push_back(path);
        std::string err;
        if (!resolve_paths(access, batch, items, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        send_json(res, 200, {{"ok", true}, {"item", items.empty() ? nlohmann::json::object() : items[0]}});
    });

    svr.Post("/v1/vfs/resolve", [guard, resolve_paths](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access))
            return;
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
        } catch (const std::exception& ex) {
            send_json(res, 400, fail_body("EINVAL", ex.what()));
            return;
        }
        nlohmann::json items = nlohmann::json::array();
        std::string err;
        const nlohmann::json paths = body.contains("paths") ? body["paths"] : nlohmann::json::array();
        if (!resolve_paths(access, paths, items, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        send_json(res, 200, {{"ok", true}, {"items", std::move(items)}});
    });

    svr.Get("/v1/vfs/read", [guard, shared_roots, authority, registry, transfers](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access))
            return;
        const std::string file = req.get_param_value("file");
        if (!file.empty()) {
            if (!absolute_request(file)) {
                send_json(res, 400, fail_body("EINVAL", "file must be an absolute path"));
                return;
            }
            const auto roots = visible_roots(shared_roots(), access);
            const auto hit = locate(file, roots, authority);
            if (!hit || hit->rel.empty()) {
                send_json(res, 404, fail_body("ENOENT", "not a shared file"));
                return;
            }
            send_shared_bytes(res, *registry, *transfers, roots, authority, hit->mount, hit->rel, access);
            return;
        }
        Located loc;
        std::string err;
        if (!query_location(req, loc, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        send_shared_bytes(res, *registry, *transfers, visible_roots(shared_roots(), access), authority,
                          loc.mount, loc.path, access);
    });

    svr.Put("/v1/vfs/write", [guard, shared_roots, registry, transfers](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access) || !write_allowed(access, res))
            return;
        if (req.body.size() > k_max_body) {
            send_json(res, 413, fail_body("EFBIG", "write is larger than 8MB"));
            return;
        }
        Located loc;
        std::string err;
        if (!query_location(req, loc, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        if (loc.path.empty()) {
            send_json(res, 400, fail_body("EINVAL", "path is required"));
            return;
        }
        const auto roots = visible_roots(shared_roots(), access);
        if (!find_root(roots, loc.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        TransferGate::Slot slot(*transfers, k_transfer_wait_ms);
        if (!slot) {
            send_json(res, 503, fail_body("EBUSY", "too many transfers in progress"));
            return;
        }
        pm::vfs::Error open_err;
        const auto store = registry->get(roots, open_err);
        if (open_err || !store) {
            send_store_error(res, open_err);
            return;
        }
        const auto written =
            store->write(pm::vfs::Caller{}, loc.mount, loc.path, req.body, op_ctx(access));
        if (written.error) {
            send_store_error(res, written.error);
            return;
        }
        send_json(res, 200, {{"ok", true}, {"mount", loc.mount}, {"node", node_json(written.node)}});
    });

    svr.Post("/v1/vfs/touch", [guard, shared_roots, registry](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access) || !write_allowed(access, res))
            return;
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
        } catch (const std::exception& ex) {
            send_json(res, 400, fail_body("EINVAL", ex.what()));
            return;
        }
        Located loc;
        std::string err;
        if (!body_location(body, loc, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        if (loc.path.empty()) {
            send_json(res, 400, fail_body("EINVAL", "path is required"));
            return;
        }
        const auto roots = visible_roots(shared_roots(), access);
        if (!find_root(roots, loc.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        pm::vfs::Error open_err;
        const auto store = registry->get(roots, open_err);
        if (open_err || !store) {
            send_store_error(res, open_err);
            return;
        }
        const auto touched = store->touch(pm::vfs::Caller{}, loc.mount, loc.path, op_ctx(access));
        if (touched.error) {
            send_store_error(res, touched.error);
            return;
        }
        send_json(res, 200, {{"ok", true}, {"mount", loc.mount}, {"node", node_json(touched.node)}});
    });

    svr.Post("/v1/vfs/mkdir", [guard, shared_roots, registry](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access) || !write_allowed(access, res))
            return;
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
        } catch (const std::exception& ex) {
            send_json(res, 400, fail_body("EINVAL", ex.what()));
            return;
        }
        Located loc;
        std::string err;
        if (!body_location(body, loc, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        const auto roots = visible_roots(shared_roots(), access);
        if (!find_root(roots, loc.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        pm::vfs::Error open_err;
        const auto store = registry->get(roots, open_err);
        if (open_err || !store) {
            send_store_error(res, open_err);
            return;
        }
        const auto made = store->mkdir(pm::vfs::Caller{}, loc.mount, loc.path, op_ctx(access));
        if (made.error) {
            send_store_error(res, made.error);
            return;
        }
        send_json(res, 200, {{"ok", true}, {"mount", loc.mount}, {"node", node_json(made.node)}});
    });

    svr.Post("/v1/vfs/delete", [guard, shared_roots, registry](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access) || !write_allowed(access, res))
            return;
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
        } catch (const std::exception& ex) {
            send_json(res, 400, fail_body("EINVAL", ex.what()));
            return;
        }
        Located loc;
        std::string err;
        if (!body_location(body, loc, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        const auto roots = visible_roots(shared_roots(), access);
        if (!find_root(roots, loc.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        pm::vfs::Error open_err;
        const auto store = registry->get(roots, open_err);
        if (open_err || !store) {
            send_store_error(res, open_err);
            return;
        }
        if (loc.path.empty()) {
            send_json(res, 400, fail_body("EINVAL", "path is required"));
            return;
        }
        bool recursive = false;
        if (!body_bool_field(body, "recursive", recursive, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        const auto removed =
            store->remove(pm::vfs::Caller{}, loc.mount, loc.path, recursive, op_ctx(access));
        if (removed) {
            send_store_error(res, removed);
            return;
        }
        send_json(res, 200, {{"ok", true}, {"mount", loc.mount}, {"path", loc.path}});
    });

    svr.Post("/v1/vfs/move", [guard, shared_roots, registry](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access) || !write_allowed(access, res))
            return;
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
        } catch (const std::exception& ex) {
            send_json(res, 400, fail_body("EINVAL", ex.what()));
            return;
        }
        Located from;
        std::string err;
        if (!body_location(body, from, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        Located to;
        if (!json_string_field(body, "toMount", to.mount, err, true)
            || !json_string_field(body, "toPath", to.path, err, true)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        if (from.path.empty()) {
            send_json(res, 400, fail_body("EINVAL", "path is required"));
            return;
        }
        const auto roots = visible_roots(shared_roots(), access);
        if (!find_root(roots, from.mount) || !find_root(roots, to.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        pm::vfs::Error open_err;
        const auto store = registry->get(roots, open_err);
        if (open_err || !store) {
            send_store_error(res, open_err);
            return;
        }
        const auto moved = store->relocate(pm::vfs::Caller{}, from.mount, from.path, to.mount, to.path,
                                           op_ctx(access));
        if (moved.error) {
            send_store_error(res, moved.error);
            return;
        }
        send_json(res, 200, {{"ok", true}, {"mount", to.mount}, {"node", node_json(moved.node)}});
    });
}

} // namespace media_cli
