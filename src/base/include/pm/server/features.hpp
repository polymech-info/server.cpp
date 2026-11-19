#pragma once

// Which route groups this process mounts. Desktop defaults keep today's
// `llm agent --serve` surface. A phone node turns llm, tools, video_control,
// and host off. A feature that is off is rejected before the handler, so the
// serve key cannot call it either.

#include <string_view>

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
    if (path == "/v1/models" || path == "/v1/credit" || path.rfind("/v1/chat/", 0) == 0
        || path.rfind("/v1/speak", 0) == 0 || path.rfind("/v1/realtime/", 0) == 0
        || path == "/v1/chat/completions")
        return features.llm;
    if (path.rfind("/v1/", 0) == 0)
        return false;
    return true;
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
