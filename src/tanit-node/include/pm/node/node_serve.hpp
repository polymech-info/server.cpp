#pragma once

#include "pm/server/options.hpp"

namespace pm::node {

/// Listen with lan and vfs. Agent, audio, video, and host routes are not mounted.
int run_node_serve(const pm::server::ListenOptions& options);

} // namespace pm::node
