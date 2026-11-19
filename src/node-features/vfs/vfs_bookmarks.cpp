#include "pm/node/vfs_bookmarks.hpp"

#include "core/settings_store.hpp"
#include "logging/logger.h"

#include <set>
#include <string>
#include <utility>
#include <vector>

namespace pm::node {

std::vector<media_cli::VfsRoot> bookmark_vfs_roots()
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
