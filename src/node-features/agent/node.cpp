// OpenAI HTTP server for `llm agent --serve`.
// Feature routes are node_llm.cpp, node_chat.cpp, node_realtime.cpp,
// node_audio.cpp, node_video.cpp, node_host.cpp, and node_lan.cpp.
// pm-llm does not link these translation units.

#include "node_internal.hpp"

#include "pm/node/desktop_gate.hpp"
#include "pm/node/desktop_run.hpp"
#include "pm/server/shared_folder.hpp"

namespace media_cli {
namespace node_detail {

void register_routes(httplib::Server& svr, const AgentServerOptions& opt, InflightGate& gate)
{
    install_chat_event_sources();
    auto require_v1_auth = [&opt](const httplib::Request& req, httplib::Response& res) -> bool {
        pm::server::ListenOptions gate;
        gate.serve_api_key = opt.serve_api_key;
        gate.features = opt.features;
        gate.serve_capabilities = {"files", "audio", "video", "chat", "tools"};
        return desktop_authorize(gate, req, res);
    };

    const auto shared_roots = [] { return pm::server::shared_folder_roots(); };
    LlmVfsHost vfs_host;
    vfs_host.authority = "desktop";
    vfs_host.roots = shared_roots;
    vfs_host.authorize =
        [&opt](const httplib::Request& req, httplib::Response& res, LlmVfsAccess& access) {
            pm::server::ListenOptions gate;
            gate.serve_api_key = opt.serve_api_key;
            gate.features = opt.features;
            gate.serve_capabilities = {"files", "audio", "video", "chat", "tools"};
            return desktop_authorize_vfs(gate, req, res, access);
        };
    register_llm_vfs_routes(svr, std::move(vfs_host));

    svr.Get("/health", [&gate, &opt](const httplib::Request&, httplib::Response& res) {
        const auto gs = gate.stats();
        nlohmann::json j{
            {"ok", true},
            {"ready", true},
            {"service", "tanit-llm-agent"},
            {"auth_required", !opt.serve_api_key.empty()},
            {"concurrency",
             {{"limit", gs.concurrency},
              {"inflight", gs.inflight},
              {"waiting", gs.waiting},
              {"max_waiting", gs.max_waiting},
              {"peak_inflight", gs.peak_inflight},
              {"peak_waiting", gs.peak_waiting},
              {"accepted", gs.accepted},
              {"waited", gs.waited},
              {"rejected", gs.rejected},
              // Excess turns block until a slot frees, up to max_waiting parkers.
              // Beyond that: HTTP 503 queue_full (keeps workers free for consent).
              {"policy", "queue-block"},
             }},
            {"preset", opt.preset},
        };
        if (g_lan) {
            const lan::PublicInfo info = g_lan->info();
            j["lan"] = {
                {"enabled", true},
                {"protocol", lan::k_protocol_version},
                {"name", info.name},
                {"fingerprint", info.fingerprint},
                {"tls_port", info.tls_port},
                {"pairing", info.pairing_open},
                {"mdns", info.mdns},
                {"addresses", info.addresses},
            };
        }
#if defined(_WIN32)
        // Cheap host WS peek without advancing CPU deltas (use /v1/sysprobe for full sample).
        try {
            const auto snap = pm::perf::last_sample();
            if (snap.tick_ms != 0) {
                j["hostWsMb"] = snap.host_ws_mb;
                j["hostCpu"]  = snap.host_cpu_pct;
                j["sysCpu"]   = snap.sys_cpu_pct;
                j["sysMem"]   = snap.sys_mem_pct;
            }
        } catch (...) {
        }
#endif
        res.status = 200;
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/ready", [&gate](const httplib::Request&, httplib::Response& res) {
        const auto gs = gate.stats();
        nlohmann::json j{
            {"ok", true},
            {"ready", true},
            {"inflight", gs.inflight},
            {"waiting", gs.waiting},
            {"limit", gs.concurrency},
        };
        res.status = 200;
        res.set_content(j.dump(), "application/json");
    });
    register_host_routes(svr, require_v1_auth);
    register_llm_routes(svr, opt, gate, require_v1_auth);
    register_chat_routes(svr, require_v1_auth, shared_roots);
    register_realtime_routes(svr, opt, require_v1_auth);
    register_video_routes(svr, require_v1_auth);
    register_audio_routes(svr, require_v1_auth);
    register_log_routes(svr, require_v1_auth);
    register_lan_routes(svr, require_v1_auth, opt.features);
}

} // namespace node_detail

int run_llm_agent_openai_server(const AgentServerOptions& opt)
{
    using namespace node_detail;
    AgentServerOptions options = opt;
    if (const std::string err = media::llm::agent::cliopt::validate_server_options(options); !err.empty()) {
        std::cerr << "llm agent --serve: " << err << "\n";
        if (err.find("non-loopback") != std::string::npos)
            std::cerr << "  phones should use --host 127.0.0.1 --lan (TLS), not cleartext HTTP\n";
        return 1;
    }
    pm::server::ListenOptions listen_options =
        media::llm::agent::cliopt::node_listen_options(options);
    if (options.lan && options.pair_on_start) {
        std::string scope_err;
        if (!lan::parse_scopes(options.pair_scopes, listen_options.pair_scopes, scope_err)) {
            std::cerr << "llm agent --serve: " << scope_err << "\n";
            return 1;
        }
        std::vector<std::string> offered;
        for (const auto& scope : listen_options.pair_scopes) {
            if (pm::server::scope_enabled(options.features, scope))
                offered.push_back(scope);
        }
        if (offered.empty()) {
            std::cerr << "llm agent --serve: none of the pair scopes are enabled\n";
            return 1;
        }
        listen_options.pair_scopes = std::move(offered);
    }
    if (options.serve_api_key.empty()) {
        logger::warn(std::string("llm agent --serve: no API key — loopback is not a credential on ")
                     + options.host + ":" + std::to_string(options.port));
    }

    const int http_workers = listen_options.http_workers;
    const int reserve_control = (std::min)(4, (std::max)(1, http_workers / 8));
    const int max_waiting =
        (std::max)(0, http_workers - options.concurrency - reserve_control);
    auto gate = std::make_shared<InflightGate>(options.concurrency, max_waiting);

    pm::node::DesktopHooks hooks;
    hooks.fail_prefix = "llm agent --serve";
    hooks.ipc_skip_prefix = "llm agent server: activity registration skipped: ";
    hooks.label = "llm agent :" + std::to_string(options.port);
    hooks.starting = [options] { register_cli_host_tool_providers(options); };
    hooks.mount = [options, gate](httplib::Server& server) {
        register_routes(server, options, *gate);
    };
    hooks.stopping = [] {
        stop_llm_video_host();
        stop_llm_audio_host();
    };
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    hooks.process_kind = media::cmd_ipc::ProcessKind::LlmAgent;
    hooks.attach_ipc = [](media::cmd_ipc::InstanceServer& ipc) { attach_chat_host_ipc(ipc); };
#endif
    hooks.banner = [=](std::ostream& out) {
        const std::string base = "http://" + listen_options.host + ":"
            + std::to_string(listen_options.port);
        out << "llm agent --serve: " << base
            << "  (GET /health, GET /v1/models, POST /v1/chat/completions,"
            << " POST /v1/llm/each, POST /v1/llm/decide, GET /v1/video/status,"
            << " GET /v1/audio/sources, GET /v1/audio/outputs; concurrency="
            << options.concurrency << "; max_waiting=" << max_waiting
            << "; http_workers=" << http_workers
            << "; auth=" << (options.serve_api_key.empty() ? "off" : "on")
            << "; consent=" << options.consent_ui;
        if (options.lan)
            out << "; lan=on";
        out << ")\n  stop: Ctrl+C\n" << std::flush;
        logger::info(std::string("llm agent server listening on ") + base
                     + " concurrency=" + std::to_string(options.concurrency)
                     + " max_waiting=" + std::to_string(max_waiting)
                     + " http_workers=" + std::to_string(http_workers)
                     + " auth=" + (options.serve_api_key.empty() ? "off" : "on"));
    };
    return pm::node::run_desktop(listen_options, std::move(hooks));
}

} // namespace media_cli
