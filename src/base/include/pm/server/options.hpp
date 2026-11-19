#pragma once

// Node-neutral listener options. AgentServerOptions converts into this record;
// node-core does not include the agent option header.

#include "pm/server/features.hpp"
#include "pm/server/vfs_root.hpp"

#include "string/string_utils.hpp"

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace pm::server {

struct ListenOptions {
    std::string host = "127.0.0.1";
    int port = 8090;
    int http_workers = 8;
    std::size_t payload_max = 9u * 1024u * 1024u;

    std::string serve_api_key;
    /// Capabilities the serve key may use. Compiling a feature does not add it.
    std::vector<std::string> serve_capabilities;

    bool lan = false;
    int lan_port = 0;
    std::string lan_name;
    bool pair_on_start = false;
    std::vector<std::string> pair_scopes;

    ServerFeatures features;
    std::string service = "tanit-node";

    /// Folders this listener publishes. The host fills it from parsed bookmark
    /// rows. Empty means this process shares no folders.
    std::function<std::vector<media_cli::VfsRoot>()> vfs_roots;
};

[[nodiscard]] inline ServerFeatures node_features()
{
    ServerFeatures features;
    features.lan = true;
    features.vfs = true;
#if defined(FEATURE_AUDIO_SOURCES) && FEATURE_AUDIO_SOURCES
    features.audio = true;
#else
    features.audio = false;
#endif
#if defined(FEATURE_VIDEO) && FEATURE_VIDEO && defined(FEATURE_VIDEO_STREAM) && FEATURE_VIDEO_STREAM
    features.video = true;
#else
    features.video = false;
#endif
    features.video_control = false;
    features.llm = false;
    features.tools = false;
    features.host = false;
    return features;
}

[[nodiscard]] inline bool loopback_host(std::string_view host) noexcept
{
    return host == "127.0.0.1" || host == "::1" || host == "localhost"
        || host == "[::1]" || host.starts_with("127.")
        || host.find("::ffff:127.") != std::string_view::npos;
}

/// Normalizes text fields and rejects a listener configuration that cannot be
/// made safe. Empty means the record is ready for node-core.
[[nodiscard]] inline std::string validate(ListenOptions& options)
{
    options.host = media::strutil::trim(std::move(options.host));
    options.service = media::strutil::trim(std::move(options.service));
    if (options.host.empty())
        options.host = "127.0.0.1";
    if (options.service.empty())
        return "node service name is empty";
    if (options.port < 1 || options.port > 65535)
        return "node port must be 1-65535";
    if (options.http_workers < 1 || options.http_workers > 512)
        return "node worker count must be 1-512";
    if (options.payload_max == 0)
        return "node payload limit must be greater than zero";
    if (!loopback_host(options.host) && options.serve_api_key.empty())
        return "refusing a non-loopback node bind without a serve key";
    if (options.lan_port != 0
        && (options.lan_port < 1 || options.lan_port > 65535
            || options.lan_port == options.port))
        return "node LAN port must be 1-65535 and differ from the HTTP port";
    return {};
}

} // namespace pm::server
