#pragma once

#include "pm/server/vfs_root.hpp"

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace media_cli {

/// Who is calling `/v1/vfs`. `full` is the serve key or open loopback.
/// A paired peer has `device_id` and `files`.
struct LlmVfsAccess {
    bool        full = false;
    bool        files = false;
    /// Mutating routes. `files` is list, stat, and read.
    bool        write = false;
    std::string device_id;
    /// Revision of the grant that produced this access. Zero when the caller
    /// has no pair row. A 403 for a write reports it.
    int         grant_revision = 0;
    /// Re-read while a write is spilling. Empty means the caller has no pair
    /// row to go stale. False means stop and delete the partial file.
    std::function<bool()> still_granted;
    /// Narrows the published mounts for this caller (the `vfs` capability's
    /// `resources`). Empty means every mount. A mount it refuses is absent from
    /// `/v1/vfs/mounts` and answers 404 everywhere else.
    std::function<bool(std::string_view mount)> mount_allowed;
};

using LlmVfsAuthorize = std::function<bool(const httplib::Request&, httplib::Response&, LlmVfsAccess&)>;

/// What the node hands the routes. The routes read no environment and no
/// settings file: the node names itself and supplies the folders.
struct LlmVfsHost {
    /// `desktop`, or `phone-<device-id>`. Lowercase letters, digits, and `-`.
    std::string authority = "desktop";
    /// Called per request, so a folder turned off is gone on the next call.
    std::function<std::vector<VfsRoot>()> roots;
    LlmVfsAuthorize authorize;
};

[[nodiscard]] bool vfs_authority_valid(std::string_view authority) noexcept;

/// One absolute path that falls inside a published folder.
struct SharedFileRef {
    std::string mount;
    std::string rel;
    std::string uri;
};

/// Empty when @p absolute is not an absolute path, or is outside every root.
/// The longest matching root wins. This does not read the file.
std::optional<SharedFileRef> shared_file_for_path(
    std::string_view absolute, const std::vector<VfsRoot>& roots, std::string_view authority);

/// Mounts are `host.roots()`. Each is `vfs://<authority>/<name>`.
/// An invalid authority registers nothing.
void register_llm_vfs_routes(httplib::Server& svr, LlmVfsHost host);

} // namespace media_cli
