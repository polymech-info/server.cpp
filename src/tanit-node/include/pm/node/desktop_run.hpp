#pragma once

// Desktop listen loop. Route registration stays with the caller. This header
// does not include the agent.

#include "pm/server/options.hpp"

#include <httplib.h>

#include <functional>
#include <iosfwd>
#include <string>

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
#include "core/cmd_ipc.hpp"
#endif

namespace pm::node {

struct DesktopHooks {
    /// Runs after the LAN proxy is prepared and before routes are mounted.
    std::function<void()> starting;
    std::function<void(httplib::Server&)> mount;
    /// Runs after the LAN proxy stops and before the HTTP server stops.
    std::function<void()> stopping;
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    std::function<void(media::cmd_ipc::InstanceServer&)> attach_ipc;
    media::cmd_ipc::ProcessKind process_kind = media::cmd_ipc::ProcessKind::LlmAgent;
#endif
    std::string label;
    std::string fail_prefix = "node";
    /// Prepended to the IPC registration failure. Empty uses fail_prefix.
    std::string ipc_skip_prefix;
    std::function<void(std::ostream&)> banner;
};

/// Bind, serve, and stop. Returns 0 when the process is cancelled.
int run_desktop(const pm::server::ListenOptions& options, DesktopHooks hooks);

} // namespace pm::node
