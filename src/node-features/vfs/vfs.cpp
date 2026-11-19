#include "pm/server/vfs.hpp"

#include "fs/path_sanitizer.hpp"
#include "logging/logger.h"
#include "pm/vfs/store.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include "string/string_utils.hpp"

namespace media_cli {
namespace {

constexpr std::size_t k_max_body = 8u * 1024u * 1024u;

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

pm::vfs::Store open_store(const std::vector<SharedRoot>& roots, pm::vfs::Error& err)
{
    nlohmann::json mounts = nlohmann::json::array();
    for (const auto& root : roots) {
        mounts.push_back({
            {"name", root.name},
            {"type", "fs"},
            {"path", root.path},
            {"isPublic", false},
        });
    }
    return pm::vfs::Store::open_json(mounts.dump(), "[]", {}, err);
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

bool body_location(const nlohmann::json& body, Located& loc, std::string& err)
{
    loc.mount = body.value("mount", std::string{});
    loc.path = body.value("path", std::string{});
    if (loc.mount.empty()) {
        err = "mount is required";
        return false;
    }
    return true;
}

bool absolute_request(std::string_view raw)
{
    if (raw.size() >= 3 &&
        ((raw[0] >= 'A' && raw[0] <= 'Z') || (raw[0] >= 'a' && raw[0] <= 'z')) &&
        raw[1] == ':' && (raw[2] == '\\' || raw[2] == '/'))
        return true;
    if (raw.size() >= 2 &&
        ((raw[0] == '\\' && raw[1] == '\\') || (raw[0] == '/' && raw[1] == '/')))
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
    while (key.size() > 3 && key.back() == '/')
        key.pop_back();
    return key;
}

std::filesystem::path canonical_abs(const std::filesystem::path& input, std::error_code& ec)
{
    ec.clear();
    std::filesystem::path abs = std::filesystem::absolute(input, ec);
    if (ec)
        return {};
    abs = abs.lexically_normal();
    std::error_code canon_ec;
    const std::filesystem::path canon = std::filesystem::weakly_canonical(abs, canon_ec);
    if (!canon_ec)
        abs = canon.lexically_normal();
    return abs;
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

std::optional<SharedHit> locate(
    const std::string& raw, const std::vector<SharedRoot>& roots, const std::string& authority)
{
    if (raw.empty() || raw.size() > 4096 || !absolute_request(raw))
        return std::nullopt;
    try {
        std::error_code ec;
        const std::filesystem::path file = canonical_abs(media::path::path_from_utf8(raw), ec);
        if (ec || file.empty())
            return std::nullopt;
        const std::string file_key = fold_key(file);
        const SharedRoot* best = nullptr;
        std::filesystem::path best_root;
        std::size_t best_len = 0;
        for (const auto& root : roots) {
            if (root.path.empty())
                continue;
            ec.clear();
            const std::filesystem::path folder = canonical_abs(media::path::path_from_utf8(root.path), ec);
            if (ec || folder.empty())
                continue;
            const std::string root_key = fold_key(folder);
            if (root_key.empty())
                continue;
            const bool inside = file_key == root_key ||
                (file_key.size() > root_key.size() &&
                 file_key.compare(0, root_key.size(), root_key) == 0 &&
                 file_key[root_key.size()] == '/');
            if (!inside || root_key.size() <= best_len)
                continue;
            best = &root;
            best_root = folder;
            best_len = root_key.size();
        }
        if (!best)
            return std::nullopt;
        std::string rel = media::path::path_to_generic_utf8(file.lexically_relative(best_root));
        if (rel == ".")
            rel.clear();
        if (rel == ".." || rel.rfind("../", 0) == 0 || rel.find("/../") != std::string::npos)
            return std::nullopt;
        SharedHit hit;
        hit.mount = best->name;
        hit.rel = rel;
        hit.uri = vfs_uri(authority, best->name, rel);
        return hit;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// A relative path is shared only when the file exists in exactly one bookmark.
// This stats the candidate; it does not read the file.
std::optional<SharedHit> locate_relative(
    const std::string& raw, const std::vector<SharedRoot>& roots, const std::string& authority)
{
    if (raw.empty() || raw.size() > 4096 || absolute_request(raw))
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
    if (rel.empty() || rel.find(':') != std::string::npos || rel.find("..") != std::string::npos ||
        rel.find('/') == std::string::npos)
        return std::nullopt;

    std::optional<SharedHit> found;
    try {
        for (const auto& root : roots) {
            if (root.path.empty())
                continue;
            std::error_code ec;
            const std::filesystem::path folder = canonical_abs(media::path::path_from_utf8(root.path), ec);
            if (ec || folder.empty())
                continue;
            const std::filesystem::path candidate = folder / media::path::path_from_utf8(rel);
            ec.clear();
            if (!std::filesystem::is_regular_file(candidate, ec))
                continue;
            const auto hit = locate(media::path::path_to_generic_utf8(candidate), roots, authority);
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
    const std::vector<SharedRoot>& roots,
    const std::string& authority,
    const std::string& mount,
    const std::string& rel)
{
    if (!find_root(roots, mount)) {
        send_json(res, 404, fail_body("ENOENT", "unknown mount"));
        return;
    }
    pm::vfs::Error open_err;
    const pm::vfs::Store store = open_store(roots, open_err);
    if (open_err) {
        send_store_error(res, open_err);
        return;
    }
    const auto body = store.read(pm::vfs::Caller{}, mount, rel);
    if (body.error) {
        send_store_error(res, body.error);
        return;
    }
    res.status = 200;
    res.set_header("X-Vfs-Mount", mount);
    res.set_header("X-Vfs-Uri", vfs_uri(authority, mount, rel));
    res.set_content(body.body, body.mime.empty() ? "application/octet-stream" : body.mime);
}

bool write_allowed(const LlmVfsAccess& access, httplib::Response& res)
{
    if (access.full || access.write)
        return true;
    nlohmann::json body = fail_body("EACCES", "write is not granted");
    if (access.grant_revision > 0) {
        body["revision"] = access.grant_revision;
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
        for (const auto& root : shared_roots()) {
            mounts.push_back({
                {"name", root.name},
                {"label", root.label.empty() ? root.name : root.label},
                {"uri", vfs_uri(authority, root.name, {})},
                {"host", authority},
                {"kind", "folder"},
                {"can", access.full || access.write
                    ? nlohmann::json::array({"list", "stat", "read", "write"})
                    : nlohmann::json::array({"list", "stat", "read"})},
            });
        }
        send_json(res, 200, {{"ok", true}, {"mounts", std::move(mounts)}});
    });

    svr.Get("/v1/vfs/list", [guard, shared_roots, authority](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access))
            return;
        Located loc;
        std::string err;
        if (!query_location(req, loc, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        const auto roots = shared_roots();
        if (!find_root(roots, loc.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        pm::vfs::Error open_err;
        const pm::vfs::Store store = open_store(roots, open_err);
        if (open_err) {
            send_store_error(res, open_err);
            return;
        }
        const auto listed = store.list(pm::vfs::Caller{}, loc.mount, loc.path);
        if (listed.error) {
            send_store_error(res, listed.error);
            return;
        }
        nlohmann::json entries = nlohmann::json::array();
        for (const auto& node : listed.entries)
            entries.push_back(node_json(node));
        send_json(res, 200, {
            {"ok", true},
            {"mount", loc.mount},
            {"uri", vfs_uri(authority, loc.mount, loc.path)},
            {"entries", std::move(entries)},
        });
    });

    svr.Get("/v1/vfs/stat", [guard, shared_roots](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access))
            return;
        Located loc;
        std::string err;
        if (!query_location(req, loc, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        const auto roots = shared_roots();
        if (!find_root(roots, loc.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        pm::vfs::Error open_err;
        const pm::vfs::Store store = open_store(roots, open_err);
        if (open_err) {
            send_store_error(res, open_err);
            return;
        }
        const auto st = store.stat(pm::vfs::Caller{}, loc.mount, loc.path);
        if (st.error) {
            send_store_error(res, st.error);
            return;
        }
        send_json(res, 200, {{"ok", true}, {"mount", loc.mount}, {"node", node_json(st.node)}});
    });

    auto resolve_paths = [shared_roots, authority](
                             const nlohmann::json& paths, nlohmann::json& items, std::string& err) {
        if (!paths.is_array()) {
            err = "paths must be an array";
            return false;
        }
        if (paths.size() > 64) {
            err = "at most 64 paths";
            return false;
        }
        const auto roots = shared_roots();
        for (const auto& row : paths) {
            if (!row.is_string())
                continue;
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
        if (!resolve_paths(batch, items, err)) {
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
        if (!resolve_paths(paths, items, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        send_json(res, 200, {{"ok", true}, {"items", std::move(items)}});
    });

    svr.Get("/v1/vfs/read", [guard, shared_roots, authority](const httplib::Request& req, httplib::Response& res) {
        LlmVfsAccess access;
        if (!guard(req, res, access))
            return;
        const std::string file = req.get_param_value("file");
        if (!file.empty()) {
            if (!absolute_request(file)) {
                send_json(res, 400, fail_body("EINVAL", "file must be an absolute path"));
                return;
            }
            const auto roots = shared_roots();
            const auto hit = locate(file, roots, authority);
            if (!hit || hit->rel.empty()) {
                send_json(res, 404, fail_body("ENOENT", "not a shared file"));
                return;
            }
            send_shared_bytes(res, roots, authority, hit->mount, hit->rel);
            return;
        }
        Located loc;
        std::string err;
        if (!query_location(req, loc, err)) {
            send_json(res, 400, fail_body("EINVAL", err));
            return;
        }
        send_shared_bytes(res, shared_roots(), authority, loc.mount, loc.path);
    });

    svr.Put("/v1/vfs/write", [guard, shared_roots](const httplib::Request& req, httplib::Response& res) {
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
        const auto roots = shared_roots();
        if (!find_root(roots, loc.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        pm::vfs::Error open_err;
        const pm::vfs::Store store = open_store(roots, open_err);
        if (open_err) {
            send_store_error(res, open_err);
            return;
        }
        const auto written = store.write(pm::vfs::Caller{}, loc.mount, loc.path, req.body);
        if (written.error) {
            send_store_error(res, written.error);
            return;
        }
        send_json(res, 200, {{"ok", true}, {"mount", loc.mount}, {"node", node_json(written.node)}});
    });

    svr.Post("/v1/vfs/mkdir", [guard, shared_roots](const httplib::Request& req, httplib::Response& res) {
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
        const auto roots = shared_roots();
        if (!find_root(roots, loc.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        pm::vfs::Error open_err;
        const pm::vfs::Store store = open_store(roots, open_err);
        if (open_err) {
            send_store_error(res, open_err);
            return;
        }
        const auto made = store.mkdir(pm::vfs::Caller{}, loc.mount, loc.path);
        if (made.error) {
            send_store_error(res, made.error);
            return;
        }
        send_json(res, 200, {{"ok", true}, {"mount", loc.mount}, {"node", node_json(made.node)}});
    });

    svr.Post("/v1/vfs/delete", [guard, shared_roots](const httplib::Request& req, httplib::Response& res) {
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
        const auto roots = shared_roots();
        if (!find_root(roots, loc.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        pm::vfs::Error open_err;
        const pm::vfs::Store store = open_store(roots, open_err);
        if (open_err) {
            send_store_error(res, open_err);
            return;
        }
        const bool recursive = body.value("recursive", false);
        const auto removed = store.remove(pm::vfs::Caller{}, loc.mount, loc.path, recursive);
        if (removed) {
            send_store_error(res, removed);
            return;
        }
        send_json(res, 200, {{"ok", true}, {"mount", loc.mount}, {"path", loc.path}});
    });

    svr.Post("/v1/vfs/move", [guard, shared_roots](const httplib::Request& req, httplib::Response& res) {
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
        to.mount = body.value("toMount", std::string{});
        to.path = body.value("toPath", std::string{});
        if (to.mount.empty()) {
            send_json(res, 400, fail_body("EINVAL", "toMount is required"));
            return;
        }
        const auto roots = shared_roots();
        if (!find_root(roots, from.mount) || !find_root(roots, to.mount)) {
            send_json(res, 404, fail_body("ENOENT", "unknown mount"));
            return;
        }
        pm::vfs::Error open_err;
        const pm::vfs::Store store = open_store(roots, open_err);
        if (open_err) {
            send_store_error(res, open_err);
            return;
        }
        const auto moved = store.relocate(pm::vfs::Caller{}, from.mount, from.path, to.mount, to.path);
        if (moved.error) {
            send_store_error(res, moved.error);
            return;
        }
        send_json(res, 200, {{"ok", true}, {"mount", to.mount}, {"node", node_json(moved.node)}});
    });
}

} // namespace media_cli
