#include "pm/node/node_serve.hpp"

#include "pm/node/desktop_gate.hpp"
#include "pm/node/desktop_run.hpp"
#include "pm/node/lan_routes.hpp"
#include "pm/node/media_routes.hpp"

#include "logging/logger.h"
#include "settings/settings_runtime.hpp"

#include <nlohmann/json.hpp>

#include <ctime>
#include <iostream>
#include <string>
#include <vector>

namespace pm::node {
namespace {

// Same rows the agent returns from GET /v1/models. The phone settings sheet
// reads this list from whichever desktop it paired with.
nlohmann::json preset_models_json()
{
    nlohmann::json data = nlohmann::json::array();
    std::vector<media::runtime_settings::ChatProviderPreset> presets;
    std::string err;
    (void)media::runtime_settings::load_chat_provider_presets(presets, err);
    const long created = static_cast<long>(std::time(nullptr));
    if (presets.empty()) {
        data.push_back({
            {"id", "default"},
            {"object", "model"},
            {"created", created},
            {"owned_by", "tanit"},
        });
    } else {
        for (const auto& preset : presets) {
            const std::string id = !preset.name.empty() ? preset.name
                : (!preset.id.empty() ? preset.id : "preset");
            data.push_back({
                {"id", id},
                {"object", "model"},
                {"created", created},
                {"owned_by", "tanit"},
                {"tanit_preset_id", preset.id},
                {"tanit_is_default", preset.is_default},
            });
        }
    }
    return nlohmann::json{{"object", "list"}, {"data", std::move(data)}};
}

void mount_node(httplib::Server& server, const pm::server::ListenOptions& options)
{
    auto require_v1_auth = [options](const httplib::Request& req, httplib::Response& res) {
        return media_cli::node_detail::desktop_authorize(options, req, res);
    };
    media_cli::LlmVfsHost vfs_host;
    vfs_host.authority = "desktop";
    vfs_host.roots = options.vfs_roots
        ? options.vfs_roots
        : [] { return std::vector<media_cli::VfsRoot>{}; };
    vfs_host.authorize = [options](const httplib::Request& req, httplib::Response& res,
                                   media_cli::LlmVfsAccess& access) {
        return media_cli::node_detail::desktop_authorize_vfs(options, req, res, access);
    };
    media_cli::register_llm_vfs_routes(server, std::move(vfs_host));

    server.Get("/health", [options](const httplib::Request&, httplib::Response& res) {
        nlohmann::json body{{"ok", true},
                            {"ready", true},
                            {"service", options.service},
                            {"auth_required", !options.serve_api_key.empty()}};
        res.status = 200;
        res.set_content(body.dump(), "application/json");
    });
    server.Get("/ready", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}, {"ready", true}}.dump(), "application/json");
    });
    media_cli::node_detail::register_lan_routes(server, require_v1_auth, options.features);
    server.Get("/v1/models", [options](const httplib::Request& req, httplib::Response& res) {
        // route_enabled hides this path while llm is off. The list is presets, not chat.
        pm::server::ListenOptions gate = options;
        gate.features.llm = true;
        if (!media_cli::node_detail::desktop_authorize(gate, req, res))
            return;
        res.status = 200;
        res.set_content(preset_models_json().dump(), "application/json");
    });
    if (options.features.audio)
        media_cli::node_detail::register_audio_routes(server, require_v1_auth);
    if (options.features.video)
        media_cli::node_detail::register_video_routes(server, require_v1_auth);
}

} // namespace

int run_node_serve(const pm::server::ListenOptions& incoming)
{
    pm::server::ListenOptions options = incoming;
    options.features = pm::server::node_features();
    if (options.service.empty())
        options.service = "tanit-node";
    if (const std::string err = pm::server::validate(options); !err.empty()) {
        std::cerr << "node serve: " << err << "\n";
        return 1;
    }
    if (options.pair_on_start) {
        std::vector<std::string> offered;
        for (const auto& scope : options.pair_scopes) {
            if (pm::server::scope_enabled(options.features, scope))
                offered.push_back(scope);
        }
        if (offered.empty()) {
            std::cerr << "node serve: none of the pair scopes are enabled\n";
            return 1;
        }
        options.pair_scopes = std::move(offered);
    }
    auto grant = [&](const char* capability, bool on) {
        if (!on)
            return;
        for (const auto& held : options.serve_capabilities)
            if (held == capability)
                return;
        options.serve_capabilities.emplace_back(capability);
    };
    grant("files", options.features.vfs);
    grant("audio", options.features.audio);
    grant("video", options.features.video);
    if (options.serve_api_key.empty()) {
        logger::warn(std::string("node serve: no API key — loopback is not a credential on ")
                     + options.host + ":" + std::to_string(options.port));
    }

    DesktopHooks hooks;
    hooks.fail_prefix = "node serve";
    hooks.label = "node :" + std::to_string(options.port);
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    hooks.process_kind = media::cmd_ipc::ProcessKind::Node;
#endif
    hooks.stopping = [] {
        media_cli::node_detail::stop_llm_video_host();
        media_cli::node_detail::stop_llm_audio_host();
    };
    hooks.mount = [options](httplib::Server& server) { mount_node(server, options); };
    hooks.banner = [options](std::ostream& out) {
        const std::string base = "http://" + options.host + ":" + std::to_string(options.port);
        out << "node serve: " << base << "  (GET /health, /v1/vfs; auth="
            << (options.serve_api_key.empty() ? "off" : "on");
        if (options.lan)
            out << "; lan=on";
        out << ")\n  stop: Ctrl+C\n" << std::flush;
        logger::info(std::string("node serve listening on ") + base);
    };
    return run_desktop(options, std::move(hooks));
}

} // namespace pm::node
