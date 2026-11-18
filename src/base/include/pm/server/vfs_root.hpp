#pragma once

// One published folder. Kept apart from vfs.hpp so a host can name its
// folders without including the HTTP server.

#include <string>

namespace media_cli {

/// `name` is the mount id in `vfs://<authority>/<name>`.
struct VfsRoot {
    std::string name;
    std::string label;
    std::string path;
};

} // namespace media_cli
