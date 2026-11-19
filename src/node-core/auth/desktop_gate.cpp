#include "pm/node/desktop_gate.hpp"

#include "pm/node/lan_gate.hpp"

namespace media_cli {
namespace node_detail {
namespace {

bool path_prefix(const std::string& path, const char* prefix)
{
    const std::string root = prefix;
    if (path == root)
        return true;
    return path.size() > root.size() && path.compare(0, root.size(), root) == 0
           && path[root.size()] == '/';
}

bool device_scope_ok(const lan::DeviceAuth& dev, const httplib::Request& req)
{
    const std::string& path = req.path;
    if (path == "/v1/models" || path == "/v1/lan/info")
        return true;
    if (path == "/v1/logs")
        return dev.has("chat");
    if (path_prefix(path, "/v1/video"))
        return dev.has("video");
    if (path_prefix(path, "/v1/audio"))
        return dev.has("audio");
    if (path.rfind("/v1/vfs", 0) == 0 || path == "/v1/lan/phone-vfs")
        return dev.has("files");
    if (path == "/v1/llm/path-tools/call")
        return dev.has("tools");
    if (path == "/v1/ui/open-file")
        return dev.has("files") || dev.has("tools");
    if (path == "/v1/chat/commands/run" || path == "/v1/llm/each" || path == "/v1/llm/decide"
        || path == "/v1/ui/open" || path == "/v1/realtime/cancel-agent"
        || path == "/v1/sysprobe")
        return dev.has("tools");
    if (path == "/v1/realtime/start")
        return dev.has("chat") && dev.has("tools");
    if (path == "/v1/host-tool-providers" || path == "/v1/browser/page-model/rank")
        return false;
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
        return dev.has("chat");
    return false;
}

} // namespace

bool desktop_authorize(const pm::server::ListenOptions& options, const httplib::Request& req,
                       httplib::Response& res)
{
    if (!pm::server::route_enabled(options.features, req.path)) {
        res.status = 404;
        res.set_content(route_error("not found").dump(), "application/json");
        return false;
    }
    if (lan_hop_present(req) && !lan_hop_ok(req)) {
        res.status = 400;
        res.set_content(route_error("invalid LAN hop").dump(), "application/json");
        return false;
    }
    const bool control = req.path == "/v1/lan/pair/begin" || req.path == "/v1/lan/devices"
                         || req.path == "/v1/lan/devices/revoke";
    const auto secrets = request_secrets(req);
    if (control) {
        if (!machine_local_request(req)) {
            res.status = 403;
            res.set_content(route_error("LAN device admin is local-only").dump(),
                            "application/json");
            return false;
        }
        for (const auto& secret : secrets) {
            if (!options.serve_api_key.empty()
                && lan::constant_time_equal(secret, options.serve_api_key))
                return true;
        }
        res.status = 401;
        res.set_content(route_error("missing or invalid Authorization Bearer token",
                                    "invalid_request_error", "unauthorized")
                            .dump(),
                        "application/json");
        return false;
    }

    if (!options.serve_api_key.empty()) {
        for (const auto& secret : secrets) {
            if (lan::constant_time_equal(secret, options.serve_api_key))
                return true;
        }
    }
    if (g_lan) {
        for (const auto& secret : secrets) {
            lan::DeviceAuth dev;
            if (!g_lan->authorize(secret, dev))
                continue;
            if (!device_scope_ok(dev, req)) {
                res.status = 403;
                res.set_content(route_error("this paired phone is not allowed to call that route",
                                            "invalid_request_error", "insufficient_scope")
                                    .dump(),
                                "application/json");
                return false;
            }
            return true;
        }
    }
    res.status = 401;
    res.set_content(route_error("missing or invalid Authorization Bearer token",
                                "invalid_request_error", "unauthorized")
                        .dump(),
                    "application/json");
    return false;
}

bool desktop_authorize_vfs(const pm::server::ListenOptions& options, const httplib::Request& req,
                           httplib::Response& res, LlmVfsAccess& access)
{
    access = {};
    if (lan_hop_present(req) && !lan_hop_ok(req)) {
        res.status = 400;
        res.set_content(route_error("invalid LAN hop").dump(), "application/json");
        return false;
    }
    const auto secrets = request_secrets(req);
    if (!options.serve_api_key.empty()) {
        for (const auto& secret : secrets) {
            if (lan::constant_time_equal(secret, options.serve_api_key)) {
                access.full = true;
                return true;
            }
        }
    }
    if (g_lan) {
        for (const auto& secret : secrets) {
            lan::DeviceAuth dev;
            if (!g_lan->authorize(secret, dev))
                continue;
            if (!dev.has("files")) {
                res.status = 403;
                res.set_content(route_error("this paired phone is not allowed to call that route",
                                            "invalid_request_error", "insufficient_scope")
                                    .dump(),
                                "application/json");
                return false;
            }
            access.device_id = dev.id;
            access.files = true;
            access.write = true;
            return true;
        }
    }
    res.status = 401;
    res.set_content(route_error("missing or invalid Authorization Bearer token",
                                "invalid_request_error", "unauthorized")
                        .dump(),
                    "application/json");
    return false;
}

} // namespace node_detail
} // namespace media_cli
