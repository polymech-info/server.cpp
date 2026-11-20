#include "pm/node/desktop_gate.hpp"

#include "pm/node/lan_gate.hpp"
#include "pm/server/features.hpp"

#include "logging/logger.h"

namespace media_cli {
namespace node_detail {
namespace {

void deny(httplib::Response& res, int status, const std::string& message, const char* type,
          const char* code)
{
    res.status = status;
    res.set_content(route_error(message, type, code).dump(), "application/json");
}

bool serve_key_matches(const pm::server::ListenOptions& options,
                       const std::vector<std::string>& secrets)
{
    if (options.serve_api_key.empty())
        return false;
    for (const auto& secret : secrets) {
        if (lan::constant_time_equal(secret, options.serve_api_key))
            return true;
    }
    return false;
}

} // namespace

bool desktop_authorize(const pm::server::ListenOptions& options, const httplib::Request& req,
                       httplib::Response& res)
{
    if (!pm::server::route_enabled(options.features, req.path)) {
        deny(res, 404, "not found", "server_error", "agent_error");
        return false;
    }
    if (lan_hop_present(req) && !lan_hop_ok(req)) {
        deny(res, 400, "invalid LAN hop", "server_error", "agent_error");
        return false;
    }
    const auto grant = pm::server::route_grant(req.path);
    const auto secrets = request_secrets(req);
    if (grant == pm::server::RouteGrant::LocalAdmin) {
        if (!machine_local_request(req)) {
            deny(res, 403, "LAN device admin is local-only", "server_error", "agent_error");
            return false;
        }
        if (serve_key_matches(options, secrets))
            return true;
        deny(res, 401, "missing or invalid Authorization Bearer token", "invalid_request_error",
             "unauthorized");
        return false;
    }

    if (serve_key_matches(options, secrets)) {
        if (pm::server::route_grant_allows(grant, options.serve_capabilities))
            return true;
        deny(res, 403, "the serve key was not granted that route", "invalid_request_error",
             "insufficient_scope");
        return false;
    }
    if (g_lan) {
        for (const auto& secret : secrets) {
            lan::DeviceAuth dev;
            if (!g_lan->authorize(secret, dev))
                continue;
            if (!pm::server::route_grant_allows(grant, dev.scopes)) {
                deny(res, 403, "this peer is not allowed to call that route",
                     "invalid_request_error", "insufficient_scope");
                return false;
            }
            return true;
        }
    }
    deny(res, 401, "missing or invalid Authorization Bearer token", "invalid_request_error",
         "unauthorized");
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
    if (serve_key_matches(options, secrets)) {
        if (!pm::server::route_grant_allows(pm::server::RouteGrant::Files,
                                            options.serve_capabilities)) {
            deny(res, 403, "the serve key was not granted that route", "invalid_request_error",
                 "insufficient_scope");
            return false;
        }
        access.full = true;
        return true;
    }
    if (g_lan) {
        for (const auto& secret : secrets) {
            lan::DeviceAuth dev;
            if (!g_lan->authorize(secret, dev))
                continue;
            if (!dev.has("files")) {
                res.status = 403;
                res.set_content(route_error("this peer is not allowed to call that route",
                                            "invalid_request_error", "insufficient_scope")
                                    .dump(),
                                "application/json");
                return false;
            }
            access.device_id = dev.id;
            access.files = true;
            logger::info(std::string("[peer] vfs ") + dev.id);
            access.write = dev.write;
            access.grant_revision = dev.revision;
            access.still_granted = [id = dev.id, revision = dev.revision]() {
                if (!g_lan)
                    return false;
                for (const auto& info : g_lan->devices()) {
                    if (info.id != id)
                        continue;
                    if (info.revoked || info.revision != revision)
                        return false;
                    return info.vfs == "write";
                }
                return false;
            };
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
