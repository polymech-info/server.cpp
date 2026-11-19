#pragma once

// Mount names for folders a node publishes. The same label gives the same
// mount id on the phone and on the desktop. Which folders are shared is a
// host fact: the settings store is read in vfs_bookmarks.cpp, not here.

#include "pm/server/vfs_root.hpp"

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

/// Folder bookmarks with `share` set. Empty when the profile has none.
[[nodiscard]] std::vector<media_cli::VfsRoot> bookmark_vfs_roots();

} // namespace pm::node
