// OpenAI HTTP server for `llm agent --serve`.
// Feature routes are node_llm.cpp, node_chat.cpp, node_realtime.cpp,
// node_audio.cpp, node_video.cpp, node_host.cpp, and node_lan.cpp.
// pm-llm does not link these translation units.

#include "node_internal.hpp"

namespace media_cli {
namespace node_detail {

bool is_loopback_addr(std::string_view addr)
{
    return media::llm::agent::cliopt::is_loopback_host(addr);
}

/// Set while `llm agent --serve --lan` is running. Proxied phones are not loopback.
lan::Service* g_lan = nullptr;

bool lan_hop_present(const httplib::Request& req)
{
    return req.has_header(lan::k_hop_header);
}

bool lan_hop_ok(const httplib::Request& req)
{
    if (!g_lan || !lan_hop_present(req))
        return false;
    return g_lan->hop_matches(req.get_header_value(lan::k_hop_header));
}

/// True for a client that dialed this process directly on loopback.
/// A phone forwarded by the TLS proxy is loopback at the TCP layer and is not local.
bool machine_local_request(const httplib::Request& req)
{
    if (lan_hop_present(req))
        return false;
    return is_loopback_addr(req.remote_addr);
}

std::vector<std::string> request_secrets(const httplib::Request& req)
{
    std::vector<std::string> out;
    auto add = [&](std::string s) {
        s = trim_ascii(std::move(s));
        if (!s.empty())
            out.push_back(std::move(s));
    };
    const std::string auth = trim_ascii(req.get_header_value("Authorization"));
    if (auth.size() >= 7) {
        bool bearer = true;
        const char pfx[] = "bearer ";
        for (int i = 0; i < 7; ++i) {
            const auto c = static_cast<unsigned char>(auth[static_cast<size_t>(i)]);
            if (std::tolower(c) != static_cast<unsigned char>(pfx[i])) {
                bearer = false;
                break;
            }
        }
        if (bearer)
            add(auth.substr(7));
    }
    for (const char* h : {"x-api-key", "api-key"})
        add(req.get_header_value(h));
    return out;
}

bool device_scope_ok(const lan::DeviceAuth& dev, const httplib::Request& req)
{
    const std::string& path = req.path;
    if (path == "/v1/models" || path == "/v1/lan/info")
        return true;
    if (path == "/v1/logs")
        return dev.has("chat");
    if (is_video_route(path))
        return dev.has("video");
    if (is_audio_route(path))
        return dev.has("audio");
    if (path.rfind("/v1/vfs", 0) == 0)
        return dev.has("files");
    // This endpoint dispatches the complete path-tool registry, including
    // run, computer-use, browser, file deletion, and service tools. A files
    // grant is intentionally limited to VFS and opening a selected file.
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
    // Scope routing is a security boundary. New routes must opt into a scope.
    return false;
}

void register_routes(httplib::Server& svr, const AgentServerOptions& opt, InflightGate& gate)
{
    install_chat_event_sources();
    auto require_v1_auth = [&opt](const httplib::Request& req, httplib::Response& res) -> bool {
        // Runs only after the transport has accepted the body. The 500 MiB
        // Content-Length cap is a pre-routing check, not this gate.
        if (!pm::server::route_enabled(opt.features, req.path)) {
            res.status = 404;
            res.set_content(openai_error("not found").dump(), "application/json");
            return false;
        }
        if (lan_hop_present(req) && !lan_hop_ok(req)) {
            res.status = 400;
            res.set_content(openai_error("invalid LAN hop").dump(), "application/json");
            return false;
        }
        const bool via_tls = lan_hop_ok(req);
        const bool control = req.path == "/v1/lan/pair/begin" || req.path == "/v1/lan/devices"
                             || req.path == "/v1/lan/devices/revoke";
        if (control) {
            if (!machine_local_request(req)) {
                res.status = 403;
                res.set_content(openai_error("LAN device admin is local-only").dump(),
                                "application/json");
                return false;
            }
            return true;
        }

        const auto secrets = request_secrets(req);
        if (!opt.serve_api_key.empty()) {
            for (const auto& secret : secrets) {
                if (lan::constant_time_equal(secret, opt.serve_api_key))
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
                    res.set_content(
                        openai_error("this paired phone is not allowed to call that route",
                                     "invalid_request_error", "insufficient_scope")
                            .dump(),
                        "application/json");
                    return false;
                }
                return true;
            }
        }
        // Direct loopback with no serve key stays open for local tools. A phone on the
        // TLS proxy always needs a paired device token or the serve key.
        if (!via_tls && opt.serve_api_key.empty())
            return true;
        res.status = 401;
        res.set_content(
            openai_error("missing or invalid Authorization Bearer token", "invalid_request_error",
                         "unauthorized")
                .dump(),
            "application/json");
        return false;
    };

    LlmVfsHost vfs_host;
    vfs_host.authority = "desktop";
    vfs_host.roots = [] { return pm::node::bookmark_vfs_roots(); };
    vfs_host.authorize =
        [&opt](const httplib::Request& req, httplib::Response& res, LlmVfsAccess& access) {
            access = {};
            if (lan_hop_present(req) && !lan_hop_ok(req)) {
                res.status = 400;
                res.set_content(openai_error("invalid LAN hop").dump(), "application/json");
                return false;
            }
            const bool via_tls = lan_hop_ok(req);
            const auto secrets = request_secrets(req);
            if (!opt.serve_api_key.empty()) {
                for (const auto& secret : secrets) {
                    if (lan::constant_time_equal(secret, opt.serve_api_key)) {
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
                        res.set_content(
                            openai_error("this paired phone is not allowed to call that route",
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
            if (!via_tls && opt.serve_api_key.empty()) {
                access.full = true;
                return true;
            }
            res.status = 401;
            res.set_content(
                openai_error("missing or invalid Authorization Bearer token", "invalid_request_error",
                             "unauthorized")
                    .dump(),
                "application/json");
            return false;
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
    register_chat_routes(svr, require_v1_auth);
    register_realtime_routes(svr, opt, require_v1_auth);
    register_video_routes(svr, require_v1_auth);
    register_audio_routes(svr, require_v1_auth);
    register_lan_routes(svr, require_v1_auth);
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
    const int http_workers = media::llm::agent::cliopt::resolved_http_workers(options);
    std::vector<std::string> pair_scopes;
    if (options.lan && options.pair_on_start) {
        std::string scope_err;
        if (!lan::parse_scopes(options.pair_scopes, pair_scopes, scope_err)) {
            std::cerr << "llm agent --serve: " << scope_err << "\n";
            return 1;
        }
    }

    std::unique_ptr<lan::Service> lan_service;
    if (options.lan) {
        lan_service = std::make_unique<lan::Service>();
        std::string lan_err;
        if (!lan_service->prepare(options.lan_name, lan_err)) {
            std::cerr << "llm agent --serve: " << lan_err << "\n";
            return 1;
        }
        g_lan = lan_service.get();
    }
    if (options.serve_api_key.empty()) {
        logger::warn(std::string("llm agent --serve: no API key — /v1 is open on ")
                     + options.host + ":" + std::to_string(options.port)
                     + " (dev/loopback only; treat as full desktop trust)");
    }

    register_cli_host_tool_providers(options);

    // Keep a few HTTP workers free for consent / health / stop while turns wait.
    const int reserve_control = (std::min)(4, (std::max)(1, http_workers / 8));
    const int max_waiting =
        (std::max)(0, http_workers - options.concurrency - reserve_control);
    InflightGate gate(options.concurrency, max_waiting);
    auto         svr = std::make_shared<httplib::Server>();
    // Transport ceiling. Individual routes retain their smaller limits
    // (for example, 32 MiB decoded mobile attachments and 8 MiB VFS writes).
    // cpp-httplib materializes request bodies, so callers should not send
    // several near-limit requests concurrently.
    // The library applies that ceiling only while reading body bytes. A
    // declared Content-Length over the cap, with no bytes following, would
    // sit in the read timeout. Reject it here, before the body is read.
    constexpr size_t k_payload_max = 500u * 1024u * 1024u;
    svr->set_payload_max_length(k_payload_max);
    svr->set_pre_routing_handler([k_payload_max](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_header("Content-Length"))
            return httplib::Server::HandlerResponse::Unhandled;
        const auto len = req.get_header_value_u64("Content-Length");
        if (len <= k_payload_max)
            return httplib::Server::HandlerResponse::Unhandled;
        res.status = 413;
        res.set_content(media::llm::agent::cliopt::openai_error(
                            "request body exceeds 500 MiB", "invalid_request_error")
                            .dump(),
                        "application/json");
        return httplib::Server::HandlerResponse::Handled;
    });
    svr->new_task_queue = [http_workers] {
        return new httplib::ThreadPool(static_cast<size_t>(http_workers));
    };
    register_routes(*svr, options, gate);

    if (!svr->bind_to_port(options.host, options.port)) {
        std::cerr << "llm agent --serve: could not bind " << options.host << ":" << options.port
                  << "\n";
        g_lan = nullptr;
        return 1;
    }

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    media::cmd_ipc::InstanceServer ipc_server;
    ipc_server.set_stop_hook([] { media::cli::request_cancel(); });
    attach_chat_host_ipc(ipc_server);
    std::error_code cwd_ec;
    std::string cwd = media::path::path_to_utf8(std::filesystem::current_path(cwd_ec));
    if (cwd.empty())
        cwd = ".";
    std::string ipc_err;
    const std::string label = "llm agent :" + std::to_string(options.port);
    if (!ipc_server.start(media::cmd_ipc::ProcessKind::LlmAgent, cwd, ipc_err, label))
        logger::info(std::string("llm agent server: activity registration skipped: ") + ipc_err);
#endif

    const std::string base = "http://" + options.host + ":" + std::to_string(options.port);
    std::thread server_thread([svr] { (void)svr->listen_after_bind(); });

    if (lan_service) {
        const int tls_port = options.lan_port > 0 ? options.lan_port : options.port + 1;
        std::string lan_err;
        if (tls_port > 65535 || !lan_service->listen(options.host, options.port, tls_port, lan_err)) {
            std::cerr << "llm agent --serve: "
                      << (lan_err.empty() ? "could not start LAN discovery" : lan_err) << "\n";
            stop_llm_video_host();
            stop_llm_audio_host();
            svr->stop();
            if (server_thread.joinable())
                server_thread.join();
            g_lan = nullptr;
            return 1;
        }
        const lan::PublicInfo info = lan_service->info();
        std::cout << "Tanit LAN\n"
                  << "  name: " << info.name << "\n"
                  << "  tls:  "
                  << (info.addresses.empty() ? std::string(info.name) : info.addresses.front())
                  << ":" << info.tls_port << "\n";
        if (info.addresses.size() > 1) {
            std::cout << "  also:";
            for (size_t i = 1; i < info.addresses.size(); ++i)
                std::cout << " " << info.addresses[i];
            std::cout << "\n";
        }
        std::cout << "  fingerprint: " << info.fingerprint_colon << "\n"
                  << "  mdns: " << (info.mdns ? "_tanit._tcp" : "unavailable — type the address")
                  << "\n"
                  << "  trust the fingerprint, not the advertised name\n"
                  << std::flush;
        if (options.pair_on_start) {
            lan::PairingTicket ticket;
            std::string pair_err;
            if (!lan_service->open_pairing(pair_scopes, 300, ticket, pair_err)) {
                std::cerr << "llm agent --serve: " << pair_err << "\n";
            } else {
                ticket.image_path = lan_service->reveal_qr(ticket);
                std::cout << "\nPair phone (one-time, expires " << ticket.expires_at << ")\n"
                          << "  scopes:";
                for (const auto& scope : ticket.scopes)
                    std::cout << " " << scope;
                std::cout << "\n";
                if (!ticket.qr_ascii.empty())
                    std::cout << ticket.qr_ascii;
                if (!ticket.qr_error.empty())
                    std::cout << "  QR: " << ticket.qr_error << "\n";
                if (!ticket.image_path.empty())
                    std::cout << "  image: " << ticket.image_path << "\n";
                std::cout << "  uri: " << ticket.uri << "\n" << std::flush;
            }
        }
    }

    std::cout << "llm agent --serve: " << base
              << "  (GET /health, GET /v1/models, POST /v1/chat/completions,"
              << " POST /v1/llm/each, POST /v1/llm/decide, GET /v1/video/status,"
              << " GET /v1/audio/sources, GET /v1/audio/outputs; concurrency="
              << options.concurrency << "; max_waiting=" << max_waiting
              << "; http_workers=" << http_workers
              << "; auth=" << (options.serve_api_key.empty() ? "off" : "on")
              << "; consent=" << options.consent_ui;
    if (options.lan)
        std::cout << "; lan=on";
    std::cout << ")\n  stop: Ctrl+C\n" << std::flush;
    logger::info(std::string("llm agent server listening on ") + base
                 + " concurrency=" + std::to_string(options.concurrency)
                 + " max_waiting=" + std::to_string(max_waiting)
                 + " http_workers=" + std::to_string(http_workers)
                 + " auth=" + (options.serve_api_key.empty() ? "off" : "on"));

    while (!media::cli::cancel_requested())
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (lan_service)
        lan_service->stop();
    stop_llm_video_host();
    stop_llm_audio_host();
    svr->stop();
    if (server_thread.joinable())
        server_thread.join();
    g_lan = nullptr;
    return 0;
}

} // namespace media_cli
