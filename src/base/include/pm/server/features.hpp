#pragma once

// Which route groups this process mounts. Desktop defaults keep today's
// `llm agent --serve` surface. A phone node turns llm, tools, video_control,
// and host off. A feature that is off is rejected before the handler, so the
// serve key cannot call it either.

#include <string>
#include <string_view>
#include <vector>

namespace pm::server {

struct ServerFeatures {
    bool lan = true;
    bool vfs = true;
    bool audio = true;
    bool video = true;
    bool video_control = true;
    bool llm = true;
    bool tools = true;
    bool host = true;
};

inline ServerFeatures phone_features()
{
    ServerFeatures features;
    // The phone listener mounts lan and vfs only. Audio and video turn on when
    // those routes are registered on the same listener.
    features.audio = false;
    features.video = false;
    features.video_control = false;
    features.llm = false;
    features.tools = false;
    features.host = false;
    return features;
}

/// True when this process should answer @p path. Health and ready always do.
inline bool route_enabled(const ServerFeatures& features, std::string_view path)
{
    if (path == "/health" || path == "/ready")
        return true;
    if (path.rfind("/v1/lan", 0) == 0 || path == "/v1/logs")
        return features.lan;
    if (path.rfind("/v1/vfs", 0) == 0)
        return features.vfs;
    if (path == "/v1/video/control")
        return features.video_control;
    if (path.rfind("/v1/video", 0) == 0)
        return features.video;
    if (path.rfind("/v1/audio", 0) == 0)
        return features.audio;
    if (path == "/v1/host-tool-providers" || path == "/v1/browser/page-model/rank"
        || path == "/v1/ui/open-file" || path == "/v1/sysprobe")
        return features.host;
    if (path == "/v1/llm/path-tools/call" || path == "/v1/llm/each" || path == "/v1/llm/decide"
        || path == "/v1/chat/commands/run" || path == "/v1/ui/open"
        || path == "/v1/realtime/cancel-agent")
        return features.tools;
    // Preset list is a node surface. Completions stay behind llm.
    if (path == "/v1/models")
        return features.lan || features.llm;
    if (path == "/v1/credit" || path.rfind("/v1/chat/", 0) == 0
        || path.rfind("/v1/speak", 0) == 0 || path.rfind("/v1/realtime/", 0) == 0
        || path == "/v1/chat/completions")
        return features.llm;
    if (path.rfind("/v1/", 0) == 0)
        return false;
    return true;
}

/// What a caller must hold once `route_enabled` has accepted the path.
/// `Closed` is 403 for a paired device and for a serve key. `LocalAdmin` is the
/// serve key on a request the proxy did not forward. Loopback alone is not it.
enum class RouteGrant {
    Open,
    AnyPaired,
    Files,
    Audio,
    Video,
    Chat,
    Tools,
    FilesOrTools,
    ChatAndTools,
    LocalAdmin,
    Closed,
};

inline bool route_path_is(std::string_view path, std::string_view root)
{
    if (path == root)
        return true;
    return path.size() > root.size() && path.substr(0, root.size()) == root
           && path[root.size()] == '/';
}

inline RouteGrant route_grant(std::string_view path)
{
    if (path == "/health" || path == "/ready")
        return RouteGrant::Open;
    if (path == "/v1/lan/pair/begin" || path == "/v1/lan/devices"
        || path == "/v1/lan/devices/revoke" || path == "/v1/host-tool-providers"
        || path == "/v1/browser/page-model/rank")
        return RouteGrant::LocalAdmin;
    if (path == "/v1/models" || path == "/v1/lan/info" || path == "/v1/lan/grant")
        return RouteGrant::AnyPaired;
    if (path == "/v1/logs")
        return RouteGrant::Chat;
    if (path == "/v1/video/control" || route_path_is(path, "/v1/video"))
        return RouteGrant::Video;
    if (route_path_is(path, "/v1/audio"))
        return RouteGrant::Audio;
    if (path.rfind("/v1/vfs", 0) == 0 || path == "/v1/lan/phone-vfs")
        return RouteGrant::Files;
    if (path == "/v1/ui/open-file")
        return RouteGrant::FilesOrTools;
    if (path == "/v1/realtime/start")
        return RouteGrant::ChatAndTools;
    if (path == "/v1/llm/path-tools/call" || path == "/v1/chat/commands/run"
        || path == "/v1/llm/each" || path == "/v1/llm/decide" || path == "/v1/ui/open"
        || path == "/v1/realtime/cancel-agent" || path == "/v1/sysprobe")
        return RouteGrant::Tools;
    if (path == "/v1/credit" || path == "/v1/speak" || path == "/v1/speak/stop"
        || path == "/v1/speak/pause" || path == "/v1/speak/resume"
        || path == "/v1/chat/completions" || path == "/v1/chat/commands"
        || path == "/v1/chat/events" || path == "/v1/chat/consent"
        || path == "/v1/chat/ask" || path == "/v1/chat/skills"
        || path == "/v1/chat/recent-paths" || path == "/v1/chat/typeahead-presets"
        || path == "/v1/chat/search-names" || path == "/v1/chat/xblox-artifacts"
        || path == "/v1/chat/sessions" || path == "/v1/chat/session"
        || path == "/v1/realtime/stop" || path == "/v1/realtime/ptt"
        || path == "/v1/realtime/speaker" || path == "/v1/realtime/events")
        return RouteGrant::Chat;
    if (path.rfind("/v1/", 0) == 0)
        return RouteGrant::Closed;
    return RouteGrant::Open;
}

inline bool capability_named(const std::vector<std::string>& capabilities, std::string_view name)
{
    for (const auto& value : capabilities)
        if (value == name)
            return true;
    return false;
}

/// `capabilities` is the serve key's startup set, or a paired device's scopes.
/// An empty set does not pass `AnyPaired`: a key with no grant is not a peer.
inline bool route_grant_allows(RouteGrant grant, const std::vector<std::string>& capabilities)
{
    switch (grant) {
    case RouteGrant::Open:
        return true;
    case RouteGrant::AnyPaired:
        return !capabilities.empty();
    case RouteGrant::Files:
        return capability_named(capabilities, "files");
    case RouteGrant::Audio:
        return capability_named(capabilities, "audio");
    case RouteGrant::Video:
        return capability_named(capabilities, "video");
    case RouteGrant::Chat:
        return capability_named(capabilities, "chat");
    case RouteGrant::Tools:
        return capability_named(capabilities, "tools");
    case RouteGrant::FilesOrTools:
        return capability_named(capabilities, "files") || capability_named(capabilities, "tools");
    case RouteGrant::ChatAndTools:
        return capability_named(capabilities, "chat") && capability_named(capabilities, "tools");
    case RouteGrant::LocalAdmin:
    case RouteGrant::Closed:
        return false;
    }
    return false;
}

/// A pairing ticket may offer a scope only when this process mounts that feature.
inline bool scope_enabled(const ServerFeatures& features, std::string_view scope)
{
    if (scope == "files")
        return features.vfs;
    if (scope == "audio")
        return features.audio;
    if (scope == "video")
        return features.video;
    if (scope == "chat")
        return features.llm;
    if (scope == "tools")
        return features.tools;
    return false;
}

} // namespace pm::server
