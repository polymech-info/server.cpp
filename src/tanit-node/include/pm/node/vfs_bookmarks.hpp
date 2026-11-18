#pragma once

// The folders a node publishes: folder bookmarks with `share` set, in the
// profile this thread reads. Desktop and phone name mounts the same way, so
// a label gives the same mount id on both.

#include "core/settings_store.hpp"
#include "logging/logger.h"
#include "pm/server/vfs_root.hpp"

#include <set>
#include <string>
#include <vector>

namespace pm::node {

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

[[nodiscard]] inline std::vector<media_cli::VfsRoot> bookmark_vfs_roots()
{
    std::vector<media::settings::BookmarkItem> rows;
    std::string err;
    if (!media::settings::load_bookmarks(rows, err)) {
        if (!err.empty())
            logger::warn(std::string("vfs mounts: ") + err);
        return {};
    }
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

} // namespace pm::node
