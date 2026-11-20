#include "pm/node/desktop_run.hpp"

#include "pm/node/lan_gate.hpp"

#include "core/cli_cancel.hpp"
#include "fs/path_sanitizer.hpp"
#include "lan/tanit_lan.hpp"
#include "logging/logger.h"

#include <nlohmann/json.hpp>

#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace pm::node {
namespace {

nlohmann::json payload_error(std::size_t limit)
{
    std::string message = "request body exceeds " + std::to_string(limit) + " bytes";
    if (limit == 500u * 1024u * 1024u)
        message = "request body exceeds 500 MiB";
    return nlohmann::json{{"error",
                           {{"message", std::move(message)},
                            {"type", "invalid_request_error"},
                            {"code", "agent_error"},
                            {"param", nullptr}}}};
}

// A leftover node or agent still registered on this HTTP port. Binding again
// is allowed by SO_REUSEADDR, and the two hop secrets then answer 400 and 401.
std::string listener_already_serving(int port)
{
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    const std::string suffix = ":" + std::to_string(port);
#if defined(_WIN32)
    const auto self = static_cast<std::int64_t>(::GetCurrentProcessId());
#else
    const auto self = static_cast<std::int64_t>(::getpid());
#endif
    for (const auto& inst : media::cmd_ipc::list_instances()) {
        if (inst.pid == 0 || inst.pid == self)
            continue;
        if (inst.kind != media::cmd_ipc::ProcessKind::Node
            && inst.kind != media::cmd_ipc::ProcessKind::LlmAgent)
            continue;
        if (inst.label.size() < suffix.size()
            || inst.label.compare(inst.label.size() - suffix.size(), suffix.size(), suffix) != 0)
            continue;
        return std::string(media::cmd_ipc::kind_str(inst.kind)) + " pid "
            + std::to_string(inst.pid);
    }
#else
    (void)port;
#endif
    return {};
}

} // namespace

int run_desktop(const pm::server::ListenOptions& options, DesktopHooks hooks)
{
    using media_cli::node_detail::g_lan;
    const std::string& prefix = hooks.fail_prefix;
    std::unique_ptr<media_cli::lan::Service> lan_service;
    if (options.lan) {
        lan_service = std::make_unique<media_cli::lan::Service>();
        std::string lan_err;
        if (!lan_service->prepare(options.lan_name, lan_err)) {
            std::cerr << prefix << ": " << lan_err << "\n";
            return 1;
        }
        g_lan = lan_service.get();
    }
    if (hooks.starting)
        hooks.starting();

    const int http_workers = options.http_workers;
    auto svr = std::make_shared<httplib::Server>();
    const std::size_t payload_max = options.payload_max;
    svr->set_payload_max_length(payload_max);
    svr->set_pre_routing_handler([payload_max](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_header("Content-Length"))
            return httplib::Server::HandlerResponse::Unhandled;
        const auto len = req.get_header_value_u64("Content-Length");
        if (len <= payload_max)
            return httplib::Server::HandlerResponse::Unhandled;
        res.status = 413;
        res.set_content(payload_error(payload_max).dump(), "application/json");
        return httplib::Server::HandlerResponse::Handled;
    });
    svr->new_task_queue = [http_workers] {
        return new httplib::ThreadPool(static_cast<size_t>(http_workers));
    };
    if (hooks.mount)
        hooks.mount(*svr);

    if (const std::string occupied = listener_already_serving(options.port); !occupied.empty()) {
        std::cerr << prefix << ": " << options.host << ":" << options.port
                  << " is already served by " << occupied << "\n";
        g_lan = nullptr;
        return 1;
    }

    if (!svr->bind_to_port(options.host, options.port)) {
        std::cerr << prefix << ": could not bind " << options.host << ":" << options.port << "\n";
        g_lan = nullptr;
        return 1;
    }

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    media::cmd_ipc::InstanceServer ipc_server;
    ipc_server.set_stop_hook([] { media::cli::request_cancel(); });
    // The IPC socket is local admin. HTTP loopback is not. `pair` opens a ticket
    // without the serve key; a hopped or credential-less HTTP call cannot.
    ipc_server.add_handler([&](const nlohmann::json& req) {
        if (req.value("action", std::string{}) != "pair")
            return nlohmann::json();
        if (!lan_service)
            return nlohmann::json{{"type", "error"}, {"error", "LAN pairing is off"}};
        std::vector<std::string> scopes = options.pair_scopes;
        if (req.contains("scopes") && req["scopes"].is_string()) {
            std::vector<std::string> asked;
            std::string scope_err;
            if (media_cli::lan::parse_scopes(req["scopes"].get<std::string>(), asked, scope_err))
                scopes = std::move(asked);
        }
        if (scopes.empty() && pm::server::scope_enabled(options.features, "files"))
            scopes.emplace_back("files");
        std::vector<std::string> offered;
        for (const auto& scope : scopes) {
            if (pm::server::scope_enabled(options.features, scope))
                offered.push_back(scope);
        }
        if (offered.empty())
            return nlohmann::json{{"type", "error"}, {"error", "no pairing scope is enabled"}};
        media_cli::lan::PairingTicket ticket;
        std::string err;
        if (!lan_service->open_pairing(offered, 300, ticket, err)) {
            return nlohmann::json{{"type", "error"},
                                  {"error", err.empty() ? "could not open a ticket" : err}};
        }
        ticket.image_path = lan_service->reveal_qr(ticket, false);
        const media_cli::lan::PublicInfo pub = lan_service->info();
        const std::string fingerprint = ticket.fingerprint_colon.empty()
            ? ticket.fingerprint : ticket.fingerprint_colon;
        return nlohmann::json{{"type", "pair"},
                              {"ok", true},
                              {"uri", ticket.uri},
                              {"expires_at", ticket.expires_at},
                              {"scopes", ticket.scopes},
                              {"image", ticket.image_path},
                              {"host", ticket.host},
                              {"port", ticket.port},
                              {"fingerprint", fingerprint},
                              {"name", pub.name}};
    });
    if (hooks.attach_ipc)
        hooks.attach_ipc(ipc_server);
    std::error_code cwd_ec;
    std::string cwd = media::path::path_to_utf8(std::filesystem::current_path(cwd_ec));
    if (cwd.empty())
        cwd = ".";
    std::string ipc_err;
    if (!ipc_server.start(hooks.process_kind, cwd, ipc_err, hooks.label)) {
        const std::string lead = hooks.ipc_skip_prefix.empty()
            ? prefix + ": activity registration skipped: "
            : hooks.ipc_skip_prefix;
        logger::info(lead + ipc_err);
    }
#endif

    std::thread server_thread([svr] { (void)svr->listen_after_bind(); });

    if (lan_service) {
        const int tls_port = options.lan_port > 0 ? options.lan_port : options.port + 1;
        std::string lan_err;
        if (tls_port > 65535
            || !lan_service->listen(options.host, options.port, tls_port, lan_err)) {
            std::cerr << prefix << ": "
                      << (lan_err.empty() ? "could not start LAN discovery" : lan_err) << "\n";
            if (hooks.stopping)
                hooks.stopping();
            svr->stop();
            if (server_thread.joinable())
                server_thread.join();
            g_lan = nullptr;
            return 1;
        }
        const media_cli::lan::PublicInfo info = lan_service->info();
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
            media_cli::lan::PairingTicket ticket;
            std::string pair_err;
            if (!lan_service->open_pairing(options.pair_scopes, 300, ticket, pair_err)) {
                std::cerr << prefix << ": " << pair_err << "\n";
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

    if (hooks.banner)
        hooks.banner(std::cout);

    while (!media::cli::cancel_requested())
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (lan_service)
        lan_service->stop();
    if (hooks.stopping)
        hooks.stopping();
    svr->stop();
    if (server_thread.joinable())
        server_thread.join();
    g_lan = nullptr;
    return 0;
}

} // namespace pm::node
