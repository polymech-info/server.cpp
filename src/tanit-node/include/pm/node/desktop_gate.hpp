#pragma once

// Desktop route gate. Loopback is not a credential. No agent include.

#include "pm/node/lan_routes.hpp"
#include "pm/server/options.hpp"
#include "pm/server/vfs.hpp"

namespace media_cli {
namespace node_detail {

bool desktop_authorize(const pm::server::ListenOptions& options, const httplib::Request& req,
                       httplib::Response& res);

bool desktop_authorize_vfs(const pm::server::ListenOptions& options, const httplib::Request& req,
                           httplib::Response& res, LlmVfsAccess& access);

} // namespace node_detail
} // namespace media_cli
