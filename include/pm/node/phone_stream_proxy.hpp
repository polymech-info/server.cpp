#pragma once

// Loopback HTTP proxy for phone `/v1/vfs/read` so MPV can Range-seek without
// downloading the whole file first. The phone TLS pin and bearer stay here;
// the player only sees http://127.0.0.1.

#include <cstdint>
#include <string>
#include <string_view>

namespace pm::vfs::phone {

struct StreamOpen {
    bool ok = false;
    std::string err;
    /// `http://127.0.0.1:<port>/s/<ticket>/<leaf>` for MPV / FileViewer.
    std::string url;
};

/// Register a phone file on the process-local loopback proxy and return a URL
/// MPV can open. Videos and other seekable media should use this instead of
/// caching the whole object first.
[[nodiscard]] StreamOpen open_stream(
    std::string_view device,
    std::string_view browse_path,
    std::uint64_t expected_size = 0,
    std::string_view mime = {});

} // namespace pm::vfs::phone