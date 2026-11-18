#pragma once

// One Tanit listener. Desktop and phone fill ServerFeatures, then call the
// same HTTP server. The desktop entry is run_llm_agent_openai_server.

#include "pm/server/features.hpp"

namespace pm::node {

inline pm::server::ServerFeatures desktop_features()
{
    return {};
}

inline pm::server::ServerFeatures phone_features()
{
    return pm::server::phone_features();
}

/// Feature set the Android process actually mounts. Defined in android/node.cpp.
[[nodiscard]] pm::server::ServerFeatures android_listener_features();

} // namespace pm::node
