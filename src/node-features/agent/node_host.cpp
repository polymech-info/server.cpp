// Desktop node: host tool providers, sysprobe, page model, UI open.
#include "node_internal.hpp"

namespace media_cli {
namespace node_detail {

bool try_register_host_provider(const std::string& id, const std::string& url, std::string& err)
{
    if (!media::llm::agent::register_http_host_tool_provider(id, url, &err)) {
        if (err.empty())
            err = "invalid host tool provider (need id=http://127.0.0.1/...)";
        return false;
    }
    std::string shown = url;
    const auto qmark = shown.find('?');
    if (qmark != std::string::npos)
        shown.resize(qmark);
    logger::info(std::string("host tool provider registered: ") + id + " -> " + shown);
    return true;
}

void register_cli_host_tool_providers(const AgentServerOptions& opt)
{
    for (const auto& spec : opt.host_tool_providers) {
        std::string id;
        std::string url;
        std::string err;
        if (!parse_host_tool_provider_spec(spec, id, url)
            || !try_register_host_provider(id, url, err)) {
            logger::warn(std::string("llm agent --serve: ignored --host-tool-provider '")
                         + spec + "'" + (err.empty() ? "" : (": " + err)));
        }
    }
}

#if defined(_WIN32)
std::wstring tanit_gui_exe()
{
    wchar_t self[MAX_PATH]{};
    const DWORD n = ::GetModuleFileNameW(nullptr, self, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        std::wstring path(self, n);
        const auto slash = path.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            const std::wstring sibling = path.substr(0, slash) + L"\\tanit.exe";
            if (::GetFileAttributesW(sibling.c_str()) != INVALID_FILE_ATTRIBUTES)
                return sibling;
        }
    }
    wchar_t local[MAX_PATH]{};
    if (SUCCEEDED(::SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, local))) {
        const std::wstring alias = std::wstring(local) + L"\\Microsoft\\WindowsApps\\tanit.exe";
        if (::GetFileAttributesW(alias.c_str()) != INVALID_FILE_ATTRIBUTES)
            return alias;
    }
    return {};
}

bool settings_section_ok(const std::string& section)
{
    if (section.empty() || section.size() > 200)
        return false;
    for (unsigned char c : section) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || c == '_' || c == '-' || c == '?' || c == '=' || c == '&' || c == '%' || c == '.';
        if (!ok)
            return false;
    }
    return true;
}

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
std::optional<media::cmd_ipc::InstanceDescriptor> newest_ui_instance()
{
    std::optional<media::cmd_ipc::InstanceDescriptor> best;
    for (const auto& inst : media::cmd_ipc::list_instances()) {
        if (inst.kind != media::cmd_ipc::ProcessKind::Ui)
            continue;
        if (!best || inst.started_unix_ms > best->started_unix_ms)
            best = inst;
    }
    return best;
}

nlohmann::json spawn_tanit_ui(const std::wstring& args)
{
    const std::wstring exe = tanit_gui_exe();
    if (exe.empty())
        return {{"ok", false}, {"error", "tanit.exe was not found"}};
    std::wstring cmd = L"\"" + exe + L"\" " + args;
    std::vector<wchar_t> mutable_cmd(cmd.begin(), cmd.end());
    mutable_cmd.push_back(L'\0');
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(exe.c_str(), mutable_cmd.data(), nullptr, nullptr, FALSE,
                          CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &si, &pi)) {
        return {{"ok", false}, {"error", "tanit.exe did not start"}};
    }
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(12);
    while (!newest_ui_instance() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    if (!newest_ui_instance())
        return {{"ok", false}, {"error", "tanit ui did not register"}};
    return {{"ok", true}};
}

nlohmann::json send_ui_app_cmd(const std::string& command, const nlohmann::json& args)
{
    const auto inst = newest_ui_instance();
    if (!inst)
        return {{"ok", false}, {"error", "tanit ui did not register"}};
    nlohmann::json reply;
    std::string err;
    const bool sent = media::cmd_ipc::send_action(*inst, "app_cmd", {
        {"command", command},
        {"args", args},
    }, reply, err, 8000);
    if (!sent || reply.value("type", std::string{}) != "app_cmd_ack") {
        return {{"ok", false}, {"error", err.empty() ? command + " was not accepted" : err}};
    }
    return {{"ok", true}};
}
#endif

// Same sequence as scripts/screenshots.mjs settings: start `tanit --ui-preset main`,
// then `run-ipc app-cmd settings|<section>` (section may be `chat?preset=<id>`).
nlohmann::json open_settings_ui(const std::string& section)
{
#if !defined(FEATURE_COMMAND_IPC_NEXT) || !FEATURE_COMMAND_IPC_NEXT
    return {{"ok", false}, {"error", "ui ipc is not available"}};
#else
    const std::string route = settings_section_ok(section) ? section : std::string("chat");
    if (!newest_ui_instance()) {
        const nlohmann::json spawned = spawn_tanit_ui(L"--ui-preset=main");
        if (!spawned.value("ok", false))
            return spawned;
    }
    nlohmann::json sent = send_ui_app_cmd("settings", {{"path", route}});
    if (sent.value("ok", false))
        sent["section"] = route;
    return sent;
#endif
}

bool ui_file_path_ok(const std::string& path)
{
    if (path.empty() || path.size() > 1024)
        return false;
    for (unsigned char c : path) {
        if (c < 0x20 || c == '"' || c == ';')
            return false;
    }
    return true;
}

// Centre file viewer: `tanit --ui-preset=viewer` when no window is up, then `open|<path>`.
nlohmann::json open_file_ui(const std::string& path, const nlohmann::json& paths, bool fullscreen)
{
#if !defined(FEATURE_COMMAND_IPC_NEXT) || !FEATURE_COMMAND_IPC_NEXT
    (void)path;
    (void)paths;
    (void)fullscreen;
    return {{"ok", false}, {"error", "ui ipc is not available"}};
#else
    if (!ui_file_path_ok(path))
        return {{"ok", false}, {"error", "path is not usable"}};
    std::string joined = path;
    if (paths.is_array()) {
        for (const auto& item : paths) {
            if (!item.is_string())
                continue;
            const std::string one = item.get<std::string>();
            if (!ui_file_path_ok(one) || one == path)
                continue;
            if (joined.size() + 1 + one.size() > 32000)
                break;
            joined += ";";
            joined += one;
        }
    }
    if (!newest_ui_instance()) {
        std::wstring src = wide_from_utf8(path);
        for (wchar_t& c : src) {
            if (c == L'/')
                c = L'\\';
        }
        const nlohmann::json spawned = spawn_tanit_ui(L"--ui-preset=viewer --src \"" + src + L"\"");
        if (!spawned.value("ok", false))
            return spawned;
    }
    nlohmann::json sent = send_ui_app_cmd("open", {{"path", joined}});
    if (!sent.value("ok", false))
        return sent;
    if (fullscreen) {
        const nlohmann::json full = send_ui_app_cmd("startfullscreen", nlohmann::json::object());
        if (!full.value("ok", false))
            return full;
    }
    return {{"ok", true}, {"path", path}};
#endif
}
#endif

void register_host_routes(httplib::Server& svr, const AuthFn& require_v1_auth)
{
    svr.Get("/v1/host-tool-providers",
            [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
                if (!require_v1_auth(req, res))
                    return;
                if (!machine_local_request(req)) {
                    res.status = 403;
                    res.set_content(
                        openai_error("host tool providers are loopback-only").dump(),
                        "application/json");
                    return;
                }
                res.status = 200;
                res.set_content(
                    media::llm::agent::list_registered_host_tool_providers().dump(),
                    "application/json");
            });

    svr.Post("/v1/host-tool-providers",
             [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
                 if (!require_v1_auth(req, res))
                     return;
                 if (!machine_local_request(req)) {
                     res.status = 403;
                     res.set_content(
                         openai_error("host tool providers are loopback-only").dump(),
                         "application/json");
                     return;
                 }
                 nlohmann::json body;
                 try {
                     body = nlohmann::json::parse(req.body);
                 } catch (...) {
                     res.status = 400;
                     res.set_content(openai_error("invalid JSON body").dump(),
                                     "application/json");
                     return;
                 }
                 const std::string id  = body.value("id", std::string{});
                 const std::string url = body.value("url", std::string{});
                 const std::string token = body.value("token", std::string{});
                 std::string       clean = url;
                 const auto        qmark = clean.find('?');
                 if (qmark != std::string::npos && clean.find("token=") != std::string::npos)
                     clean.resize(qmark);
                 std::string registered = url;
                 if (!token.empty() && registered.find("token=") == std::string::npos) {
                     registered += registered.find('?') == std::string::npos ? "?" : "&";
                     registered += "token=";
                     registered += token;
                 }
                 std::string       err;
                 if (id.empty() || url.empty()
                     || !try_register_host_provider(id, registered, err)) {
                     res.status = 400;
                     res.set_content(
                         openai_error(err.empty()
                                          ? "need {id, url} with loopback http URL"
                                          : err)
                             .dump(),
                         "application/json");
                     return;
                 }
                 res.status = 200;
                 res.set_content(
                     nlohmann::json{{"ok", true}, {"id", id}, {"url", clean}}.dump(),
                     "application/json");
             });

    // Pure BM25 over a page model the caller already holds. Loopback only:
    // the body is live page text. Does not open a tab.
    svr.Post("/v1/browser/page-model/rank",
             [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
                 auto fail = [&res](const std::string& error) {
                     res.status = 200;
                     res.set_content(nlohmann::json{{"ok", false}, {"error", error}}.dump(),
                                     "application/json");
                 };
                 if (!require_v1_auth(req, res))
                     return;
                 if (!machine_local_request(req)) {
                     res.status = 403;
                     res.set_content(
                         openai_error("page model rank is loopback-only").dump(),
                         "application/json");
                     return;
                 }
                 nlohmann::json body;
                 try {
                     body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
                 } catch (...) {
                     fail("invalid JSON body");
                     return;
                 }
                 if (!body.is_object()) {
                     fail("JSON body must be an object");
                     return;
                 }
                 std::string query;
                 if (body.contains("query") && body["query"].is_string())
                     query = body["query"].get<std::string>();
                 if (query.empty()) {
                     fail("query is required");
                     return;
                 }
                 nlohmann::json model;
                 if (body.contains("model") && body["model"].is_object())
                     model = body["model"];
                 else if (body.contains("data") && body["data"].is_object()
                          && body["data"].contains("model") && body["data"]["model"].is_object())
                     model = body["data"]["model"];
                 else {
                     fail("model object is required");
                     return;
                 }
                 std::size_t top_k = 5;
                 if (body.contains("topK") && body["topK"].is_number()) {
                     const double raw = body["topK"].get<double>();
                     if (std::isfinite(raw) && raw >= 1.0 && raw <= 16.0)
                         top_k = static_cast<std::size_t>(raw);
                 }
                 const std::size_t zone_count =
                     model.contains("zones") && model["zones"].is_array() ? model["zones"].size() : 0;
#if defined(FEATURE_BROWSER_PAGE_MODEL) && FEATURE_BROWSER_PAGE_MODEL
                 media::llm::browser_use::rank_page_model_zones(model, query, top_k);
                 nlohmann::json ranked = nlohmann::json::array();
                 if (model.contains("rankedZones") && model["rankedZones"].is_array())
                     ranked = model["rankedZones"];
                 res.status = 200;
                 res.set_content(
                     nlohmann::json{{"ok", true},
                                    {"data",
                                     {{"rankedZones", std::move(ranked)},
                                      {"zoneCount", zone_count},
                                      {"topK", top_k}}}}
                         .dump(),
                     "application/json");
#else
                 (void)top_k;
                 fail("page model ranking is not built");
                 (void)zone_count;
#endif
             });

#if defined(_WIN32)
    // Same counters as Statusbar / perfui (`pm::perf::sample`).
    // ?mode=last → last sample without advancing CPU deltas (post-workload WS/GPU).
    // Full sample also attaches peak host/sys CPU + WS over recent ring.
    svr.Get("/v1/sysprobe", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        try {
            const std::string mode = req.get_param_value("mode");
            const bool peek_last   = (mode == "last" || mode == "peek");
            const auto snap =
                peek_last ? pm::perf::last_sample() : pm::perf::sample();
            nlohmann::json j = nlohmann::json::parse(pm::perf::sample_to_json_object(snap));
            int      peak_host_cpu = snap.host_cpu_pct;
            int      peak_sys_cpu  = snap.sys_cpu_pct;
            unsigned peak_ws_mb    = snap.host_ws_mb;
            for (const auto& s : pm::perf::recent_samples(60)) {
                peak_host_cpu = (std::max)(peak_host_cpu, s.host_cpu_pct);
                peak_sys_cpu  = (std::max)(peak_sys_cpu, s.sys_cpu_pct);
                peak_ws_mb    = (std::max)(peak_ws_mb, s.host_ws_mb);
            }
            j["hostCpuPeak"] = peak_host_cpu;
            j["sysCpuPeak"]  = peak_sys_cpu;
            j["hostWsMbPeak"] = peak_ws_mb;
            j["sampleMode"]  = peek_last ? "last" : "interval";
            res.status = 200;
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(openai_error(std::string("sysprobe: ") + e.what()).dump(),
                            "application/json");
        }
    });
#else
    svr.Get("/v1/sysprobe", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        res.status = 501;
        res.set_content(openai_error("sysprobe unavailable on this platform", "server_error",
                                     "sysprobe_unsupported")
                            .dump(),
                        "application/json");
    });
#endif

#if defined(_WIN32)
    svr.Post("/v1/ui/open", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        std::string section = "chat";
        if (!req.body.empty()) {
            const auto body = media::json::try_parse(req.body);
            if (body.is_object())
                section = body.value("section", section);
        }
        const nlohmann::json out = open_settings_ui(section);
        res.status = 200;
        res.set_content(out.dump(), "application/json");
    });

    svr.Post("/v1/ui/open-file", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        std::string path;
        nlohmann::json paths = nlohmann::json::array();
        bool fullscreen = false;
        if (!req.body.empty()) {
            const auto body = media::json::try_parse(req.body);
            if (body.is_object()) {
                path = body.value("path", std::string{});
                if (body.contains("paths") && body["paths"].is_array())
                    paths = body["paths"];
                fullscreen = body.value("fullscreen", false);
            }
        }
        const nlohmann::json out = open_file_ui(path, paths, fullscreen);
        res.status = 200;
        res.set_content(out.dump(), "application/json");
    });
#endif
}
} // namespace node_detail
} // namespace media_cli
