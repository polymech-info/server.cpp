#pragma once

// A shared folder is a bookmark row the host already parsed. This turns those
// rows into mount roots. The settings file is opened by the host, then the
// rows are passed in.

#include "pm/server/vfs_root.hpp"

#include "core/settings_store.hpp"
#include "logging/logger.h"

#include <set>
#include <string>
#include <utility>
#include <vector>

namespace pm::server {

[[nodiscard]] inline std::string vfs_mount_token(const std::string& raw)
{
    std::string out;
    for (unsigned char c : raw) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<unsigned char>(c - 'A' + 'a');
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')
            out.push_back(static_cast<char>(c));
        else if (c == ' ' || c == '/' || c == '\\')
            out.push_back('-');
    }
    while (!out.empty() && (out.front() == '-' || out.front() == '.'))
        out.erase(out.begin());
    while (!out.empty() && (out.back() == '-' || out.back() == '.'))
        out.pop_back();
    if (out.empty())
        out = "folder";
    return out;
}

[[nodiscard]] inline std::vector<media_cli::VfsRoot> vfs_roots_from_bookmarks(
    const std::vector<media::settings::BookmarkItem>& rows)
{
    std::set<std::string> used;
    std::vector<media_cli::VfsRoot> out;
    for (const auto& row : rows) {
        if (!row.share || row.kind != "node" || row.node_kind != "folder" || row.path.empty())
            continue;
        media_cli::VfsRoot root;
        root.path = row.path;
        root.label = row.label;
        const auto slash = row.path.find_last_of("/\\");
        const std::string leaf = slash == std::string::npos ? row.path : row.path.substr(slash + 1);
        const std::string base = vfs_mount_token(row.label.empty() ? leaf : row.label);
        std::string name = base;
        int n = 2;
        while (!used.insert(name).second)
            name = base + "-" + std::to_string(n++);
        root.name = std::move(name);
        out.push_back(std::move(root));
    }
    return out;
}

/// Host edge. Re-reads the bookmark rows so a folder turned off is gone on
/// the next call. Route code takes the vector and does not call this.
[[nodiscard]] inline std::vector<media_cli::VfsRoot> shared_folder_roots()
{
    std::vector<media::settings::BookmarkItem> rows;
    std::string err;
    if (!media::settings::load_bookmarks(rows, err)) {
        if (!err.empty())
            logger::warn(std::string("vfs mounts: ") + err);
        return {};
    }
    return vfs_roots_from_bookmarks(rows);
}

} // namespace pm::server
