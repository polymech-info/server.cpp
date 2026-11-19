#pragma once

// Public seams between node-core and host-compiled route groups. A feature
// receives Router, never httplib::Server and never an authorization callback.

#include "lan/pair_store.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pm::node {

enum class PrincipalKind {
    RemotePair,
    ServeKey,
    LocalAdmin,
    LocalAgent,
};

struct RequestContext {
    PrincipalKind principal = PrincipalKind::RemotePair;
    std::string peer_id;
    pm::lan::Grant grant;
    std::string tls_fp;
    int grant_revision = 0;
    /// Used by serve keys and local agents. Remote pairs use Grant.
    std::vector<std::string> capabilities;
    bool consented = false;

    [[nodiscard]] bool has(std::string_view capability) const noexcept
    {
        for (const auto& value : capabilities)
            if (value == capability)
                return true;
        return false;
    }
};

struct RoutePolicy {
    /// `files`, `audio`, `video`, `chat`, `tools`, or empty for any paired peer.
    std::string capability;
    bool paired_only = false;
    bool local_admin = false;
    /// Zero inherits the process ceiling.
    std::size_t max_body = 0;
};

enum class HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
};

using RouteHandler =
    std::function<void(const httplib::Request&, httplib::Response&, const RequestContext&)>;

class Router {
public:
    virtual ~Router() = default;

    virtual void add(HttpMethod method, std::string path, RoutePolicy policy,
                     RouteHandler handler) = 0;
};

/// Optional routes and health fields supplied by the LLM process. The node
/// owns listener startup, authorization, IPC, cancellation, and shutdown.
class DesktopLayer {
public:
    virtual ~DesktopLayer() = default;

    virtual void mount(Router& router) = 0;
    virtual void health(nlohmann::json& body) const = 0;
    virtual void stopped() noexcept {}
    [[nodiscard]] virtual std::string_view service() const noexcept
    {
        return "tanit-llm-agent";
    }
};

} // namespace pm::node
