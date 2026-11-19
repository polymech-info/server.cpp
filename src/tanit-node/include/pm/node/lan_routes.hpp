#pragma once

// LAN route registration and the JSON error envelope those routes share with
// the desktop gate. No agent include.

#include "pm/server/features.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <string>

namespace media_cli {
namespace node_detail {

inline nlohmann::json route_error(const std::string& message,
                                  const std::string& type = "server_error",
                                  const std::string& code = "agent_error")
{
    return nlohmann::json{{"error",
                           {{"message", message},
                            {"type", type},
                            {"code", code},
                            {"param", nullptr}}}};
}

inline std::string clip_route_text(std::string text, std::size_t max)
{
    if (text.size() > max)
        text.resize(max);
    return text;
}

using AuthFn = std::function<bool(const httplib::Request&, httplib::Response&)>;

void register_lan_routes(httplib::Server& svr, const AuthFn& require_v1_auth,
                         const pm::server::ServerFeatures& features);

} // namespace node_detail
} // namespace media_cli
