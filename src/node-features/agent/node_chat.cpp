// Desktop node: chat hub, sessions, commands, speak, name search.
#include "node_internal.hpp"

namespace media_cli {
namespace node_detail {

constexpr std::int64_t k_chat_keep_ms = 5 * 60 * 1000;

std::int64_t chat_now_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct ChatHub {
    std::mutex mu;
    std::condition_variable cv;
    std::vector<nlohmann::json> events;
    std::uint64_t base = 0;
    std::uint64_t next_id = 1;
    std::vector<std::pair<std::uint64_t, std::string>> origins;
    std::vector<std::int64_t> origin_seen_ms;
};

ChatHub g_chat_hub;
thread_local std::string tls_chat_sender;

void prune_chat_hub_locked(std::int64_t now)
{
    while (!g_chat_hub.events.empty()) {
        const std::int64_t ts = g_chat_hub.events.front().value("ts", std::int64_t{0});
        if (now - ts < k_chat_keep_ms)
            break;
        g_chat_hub.events.erase(g_chat_hub.events.begin());
        ++g_chat_hub.base;
    }
    std::vector<std::pair<std::uint64_t, std::string>> origins;
    std::vector<std::int64_t> seen;
    for (std::size_t i = 0; i < g_chat_hub.origins.size(); ++i) {
        if (now - g_chat_hub.origin_seen_ms[i] >= k_chat_keep_ms)
            continue;
        origins.push_back(g_chat_hub.origins[i]);
        seen.push_back(g_chat_hub.origin_seen_ms[i]);
    }
    g_chat_hub.origins.swap(origins);
    g_chat_hub.origin_seen_ms.swap(seen);
}

void remember_chat_origin(std::uint64_t pid, const std::string& sender)
{
    if (pid == 0 || sender.empty())
        return;
    const std::int64_t now = chat_now_ms();
    std::lock_guard lock(g_chat_hub.mu);
    prune_chat_hub_locked(now);
    for (std::size_t i = 0; i < g_chat_hub.origins.size(); ++i) {
        if (g_chat_hub.origins[i].first == pid) {
            g_chat_hub.origins[i].second = sender;
            g_chat_hub.origin_seen_ms[i] = now;
            return;
        }
    }
    g_chat_hub.origins.emplace_back(pid, sender);
    g_chat_hub.origin_seen_ms.push_back(now);
}

std::string chat_sender_for_pid(std::uint64_t pid)
{
    if (pid == 0)
        return {};
    std::lock_guard lock(g_chat_hub.mu);
    for (const auto& row : g_chat_hub.origins) {
        if (row.first == pid)
            return row.second;
    }
    return {};
}

#if defined(_WIN32)
std::uint64_t parent_pid_of(std::uint64_t pid)
{
    if (pid == 0)
        return 0;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::uint64_t parent = 0;
    if (::Process32FirstW(snap, &pe)) {
        do {
            if (static_cast<std::uint64_t>(pe.th32ProcessID) == pid) {
                parent = pe.th32ParentProcessID;
                break;
            }
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
    return parent;
}
#endif

std::string chat_sender_for_process(std::uint64_t pid)
{
    for (int hop = 0; hop < 8 && pid > 4; ++hop) {
        const std::string sender = chat_sender_for_pid(pid);
        if (!sender.empty())
            return sender;
#if defined(_WIN32)
        pid = parent_pid_of(pid);
#else
        break;
#endif
    }
    return {};
}

bool chat_event_visible(const nlohmann::json& ev, const std::string& subscriber)
{
    const std::string sender = ev.value("sender", std::string{});
    return sender.empty() || subscriber.empty() || sender == subscriber;
}

void chat_emit(const std::string& method, nlohmann::json args, const std::string& sender = {})
{
    const std::int64_t now = chat_now_ms();
    {
        std::lock_guard lock(g_chat_hub.mu);
        prune_chat_hub_locked(now);
        const std::uint64_t id = g_chat_hub.next_id++;
        nlohmann::json ev{{"id", id}, {"ts", now}, {"method", method}, {"args", std::move(args)}};
        if (!sender.empty())
            ev["sender"] = sender;
        g_chat_hub.events.push_back(std::move(ev));
    }
    g_chat_hub.cv.notify_all();
}

void install_chat_event_sources()
{
    static std::once_flag once;
    std::call_once(once, [] {
        media::llm::set_chat_host_emit([](const std::string& method, nlohmann::json args) {
            chat_emit(method, std::move(args));
        });
        media::cmd_run::Runner::instance().subscribe([](const media::cmd_run::RunEvent& ev) {
            const char* phase = "started";
            switch (ev.phase) {
            case media::cmd_run::RunPhase::Started: phase = "started"; break;
            case media::cmd_run::RunPhase::Exited: phase = "exited"; break;
            case media::cmd_run::RunPhase::Failed: phase = "failed"; break;
            case media::cmd_run::RunPhase::Cancelled: phase = "cancelled"; break;
            }
            std::string sender = tls_chat_sender;
            if (ev.phase == media::cmd_run::RunPhase::Started)
                remember_chat_origin(ev.pid, sender);
            else if (sender.empty())
                sender = chat_sender_for_pid(ev.pid);
            chat_emit("commandRunEvent", nlohmann::json::array({nlohmann::json{
                {"phase", phase},
                {"runId", ev.runId},
                {"cmdId", ev.cmdId},
                {"commandId", ev.commandId},
                {"pid", ev.pid},
                {"exitCode", ev.exitCode},
                {"error", ev.error},
                {"running", ev.phase == media::cmd_run::RunPhase::Started},
            }}), sender);
        });
    });
}

#if defined(_WIN32)
std::wstring wide_from_utf8(const std::string& text)
{
    if (text.empty())
        return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (n <= 0)
        return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), n);
    return out;
}

std::string utf8_from_wide(const std::wstring& text)
{
    if (text.empty())
        return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (n <= 0)
        return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                          out.data(), n, nullptr, nullptr);
    return out;
}

bool filename_has_query(std::wstring name, std::wstring query)
{
    auto lower = [](std::wstring s) {
        for (wchar_t& c : s)
            c = static_cast<wchar_t>(::towlower(c));
        return s;
    };
    name = lower(std::move(name));
    query = lower(std::move(query));
    return !query.empty() && name.find(query) != std::wstring::npos;
}

bool skip_search_dir(const std::wstring& name)
{
    return name == L".git" || name == L"node_modules" || name == L"dist"
        || name == L".vs" || name == L"target" || name == L"__pycache__";
}

std::string scope_id_for_path(const std::string& path, const nlohmann::json& scopes)
{
    std::string best_id;
    std::size_t best_len = 0;
    if (!scopes.is_array())
        return best_id;
    std::string norm = path;
    for (char& c : norm)
        if (c == '/')
            c = '\\';
    norm = media::strutil::lower_ascii(std::move(norm));
    for (const auto& scope : scopes) {
        if (!scope.is_object())
            continue;
        std::string root = scope.value("path", std::string{});
        if (root.empty())
            continue;
        for (char& c : root)
            if (c == '/')
                c = '\\';
        while (root.size() > 3 && (root.back() == '\\' || root.back() == '/'))
            root.pop_back();
        root = media::strutil::lower_ascii(std::move(root));
        const bool hit = norm == root
            || (norm.size() > root.size() && norm.compare(0, root.size(), root) == 0 && norm[root.size()] == '\\');
        if (hit && root.size() >= best_len) {
            best_len = root.size();
            best_id = scope.value("id", std::string{});
        }
    }
    return best_id;
}

nlohmann::json search_bookmark_names(const nlohmann::json& req)
{
    std::string query = req.value("query", std::string{});
    int limit = req.value("headLimit", 40);
    if (limit < 1)
        limit = 1;
    if (limit > 60)
        limit = 60;
    const nlohmann::json scopes = req.contains("scopes") && req["scopes"].is_array()
        ? req["scopes"]
        : nlohmann::json::array();
    std::vector<std::wstring> roots;
    auto add_root = [&](const std::string& raw) {
        const std::wstring wide = wide_from_utf8(raw);
        if (wide.empty())
            return;
        std::error_code ec;
        if (!fs::is_directory(wide, ec))
            return;
        roots.push_back(wide);
    };
    if (req.contains("inputs") && req["inputs"].is_array()) {
        for (const auto& row : req["inputs"])
            if (row.is_string())
                add_root(row.get<std::string>());
    }
    if (roots.empty()) {
        std::vector<media::settings::BookmarkItem> bookmarks;
        std::string err;
        if (media::settings::load_bookmarks(bookmarks, err)) {
            for (const auto& item : bookmarks) {
                if (item.searchable && item.kind == "node" && item.node_kind == "folder")
                    add_root(item.path);
            }
        }
    }
    const std::wstring needle = wide_from_utf8(query);
    nlohmann::json hits = nlohmann::json::array();
    int scanned = 0;
    const int scan_cap = 12000;
    const std::function<void(const fs::path&, int)> walk = [&](const fs::path& dir, int depth) {
        if (depth > 12 || static_cast<int>(hits.size()) >= limit || scanned >= scan_cap)
            return;
        std::error_code ec;
        for (fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
             it != end && static_cast<int>(hits.size()) < limit && scanned < scan_cap;
             it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            ++scanned;
            std::error_code fec;
            const fs::path child = it->path();
            if (it->is_symlink(fec))
                continue;
            if (it->is_directory(fec)) {
                if (!skip_search_dir(child.filename().wstring()))
                    walk(child, depth + 1);
                continue;
            }
            if (!it->is_regular_file(fec))
                continue;
            const std::wstring name = child.filename().wstring();
            if (!filename_has_query(name, needle))
                continue;
            const std::string full = utf8_from_wide(child.wstring());
            hits.push_back({
                {"path", full},
                {"title", utf8_from_wide(name)},
                {"scope_id", scope_id_for_path(full, scopes)},
            });
        }
    };
    for (const std::wstring& root : roots) {
        if (static_cast<int>(hits.size()) >= limit || scanned >= scan_cap)
            break;
        walk(std::filesystem::path(root), 0);
    }
    const auto matches = hits.size();
    return {
        {"accepted", true},
        {"taskId", "chrome-names"},
        {"hits", std::move(hits)},
        {"matches", matches},
    };
}

#endif

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
void attach_chat_host_ipc(media::cmd_ipc::InstanceServer& ipc)
{
    ipc.set_extra_action_handler([](const nlohmann::json& req) {
        if (req.value("action", std::string{}) != "chat_host")
            return nlohmann::json();
        const std::string method = req.value("method", std::string{});
        if (method.empty() || !req.contains("args") || !req["args"].is_array()) {
            return nlohmann::json{
                {"type", "error"},
                {"error", "chat_host requires method and args"},
            };
        }
        const auto pid = req.value("pid", std::uint64_t{0});
        const std::string sender = chat_sender_for_process(pid);
        chat_emit(method, req["args"], sender);
        nlohmann::json ack{{"type", "chat_host_ack"}, {"method", method}};
        if (!sender.empty())
            ack["sender"] = sender;
        return ack;
    });
}
#endif

void register_chat_routes(httplib::Server& svr, const AuthFn& require_v1_auth,
                          const std::function<std::vector<media_cli::VfsRoot>()>& shared_roots)
{
    svr.Get("/v1/chat/commands", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}, {"data", media::launcher::chat_commands_catalog_json()}}.dump(),
                        "application/json");
    });

    svr.Post("/v1/chat/commands/run", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        nlohmann::json body = nlohmann::json::object();
        try {
            if (!req.body.empty())
                body = nlohmann::json::parse(req.body);
        } catch (...) {
            res.status = 200;
            res.set_content(nlohmann::json{{"ok", false}, {"error", "invalid JSON body"}}.dump(),
                            "application/json");
            return;
        }
        const std::string id = body.value("id", std::string{});
        tls_chat_sender = body.value("sender", std::string{});
        const nlohmann::json started = media::launcher::run_chat_command(id);
        tls_chat_sender.clear();
        res.status = 200;
        res.set_content(started.dump(), "application/json");
    });

    svr.Get("/v1/chat/events", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");
        res.set_chunked_content_provider(
            "text/event-stream; charset=utf-8",
            [sender = req.has_param("sender") ? req.get_param_value("sender") : std::string{},
             after = req.has_param("after") ? std::strtoull(req.get_param_value("after").c_str(), nullptr, 10) : 0ULL](
                size_t /*offset*/, httplib::DataSink& sink) -> bool {
                std::uint64_t pos = 0;
                std::vector<nlohmann::json> backlog;
                {
                    std::lock_guard lock(g_chat_hub.mu);
                    prune_chat_hub_locked(chat_now_ms());
                    for (const auto& ev : g_chat_hub.events) {
                        if (ev.value("id", std::uint64_t{0}) <= after)
                            continue;
                        if (!chat_event_visible(ev, sender))
                            continue;
                        backlog.push_back(ev);
                    }
                    pos = g_chat_hub.base + g_chat_hub.events.size();
                }
                for (const auto& ev : backlog) {
                    const std::string line = "data: " + ev.dump() + "\n\n";
                    if (!sink.write(line.data(), line.size()))
                        return false;
                }
                for (;;) {
                    std::vector<nlohmann::json> batch;
                    {
                        std::unique_lock lock(g_chat_hub.mu);
                        g_chat_hub.cv.wait_for(lock, std::chrono::seconds(15), [&] {
                            return (g_chat_hub.base + g_chat_hub.events.size()) > pos;
                        });
                        prune_chat_hub_locked(chat_now_ms());
                        if (pos < g_chat_hub.base)
                            pos = g_chat_hub.base;
                        const std::uint64_t end = g_chat_hub.base + g_chat_hub.events.size();
                        while (pos < end) {
                            const auto& ev = g_chat_hub.events[static_cast<size_t>(pos - g_chat_hub.base)];
                            if (chat_event_visible(ev, sender))
                                batch.push_back(ev);
                            ++pos;
                        }
                    }
                    for (const auto& ev : batch) {
                        const std::string line = "data: " + ev.dump() + "\n\n";
                        if (!sink.write(line.data(), line.size()))
                            return false;
                    }
                    if (batch.empty()) {
                        static const char ping[] = ": keepalive\n\n";
                        if (!sink.write(ping, sizeof(ping) - 1u))
                            return false;
                    }
                }
            });
    });

    svr.Post("/v1/chat/consent", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        nlohmann::json body = nlohmann::json::object();
        if (!req.body.empty()) {
            body = media::json::try_parse(req.body);
            if (!body.is_object()) {
                res.status = 200;
                res.set_content(nlohmann::json{{"ok", false}, {"error", "invalid JSON body"}}.dump(),
                                "application/json");
                return;
            }
        }
        if (body.value("cancel", false))
            pm::security::cancel_stream_consent();
        else
            pm::security::resolve_stream_consent(req.body);
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    });

    // Unblocks ask_user when `--consent-ui stream` (SSE `tanit.ask`).
    svr.Post("/v1/chat/ask", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        nlohmann::json body = nlohmann::json::object();
        if (!req.body.empty()) {
            body = media::json::try_parse(req.body);
            if (!body.is_object()) {
                res.status = 200;
                res.set_content(nlohmann::json{{"ok", false}, {"error", "invalid JSON body"}}.dump(),
                                "application/json");
                return;
            }
        }
        if (body.value("cancel", false))
            pm::llm::inquire::cancel_stream_ask();
        else
            pm::llm::inquire::resolve_stream_ask(req.body);
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    });

    svr.Get("/v1/chat/skills", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        const std::string cwd = req.has_param("cwd") ? req.get_param_value("cwd") : std::string{};
        try {
            res.status = 200;
            res.set_content(nlohmann::json{
                {"ok", true},
                {"data", media::llm::skills::list_skills_data_json(cwd)},
            }.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 200;
            res.set_content(nlohmann::json{{"ok", false}, {"error", e.what()}}.dump(), "application/json");
        }
    });

    svr.Get("/v1/chat/recent-paths", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        nlohmann::json files = nlohmann::json::array();
        nlohmann::json folders = nlohmann::json::array();
#if defined(_WIN32)
        media::layout::WindowLayout layout;
        std::string err;
        if (!media::settings::load_window_layout(layout, err) && !err.empty()) {
            res.status = 200;
            res.set_content(nlohmann::json{{"ok", false}, {"error", err}}.dump(), "application/json");
            return;
        }
        for (const auto& path : layout.recent_files) {
            if (!path.empty())
                files.push_back(path);
        }
        for (const auto& path : layout.recent_folders) {
            if (!path.empty())
                folders.push_back(path);
        }
#endif
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}, {"data", {{"files", std::move(files)}, {"folders", std::move(folders)}}}}.dump(),
                        "application/json");
    });

#if defined(_WIN32)
    svr.Get("/v1/chat/typeahead-presets", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        std::vector<media::settings::BookmarkItem> bookmarks;
        std::string err;
        if (!media::settings::load_bookmarks(bookmarks, err)) {
            res.status = 200;
            res.set_content(nlohmann::json{{"ok", false}, {"error", err.empty() ? "bookmarks unavailable" : err}}.dump(),
                            "application/json");
            return;
        }
        const nlohmann::json presets = media::chat_web::typeahead::build_typeahead_presets_json(bookmarks, {});
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}, {"data", {{"presets", presets}}}}.dump(), "application/json");
    });

    svr.Post("/v1/chat/search-names", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        const nlohmann::json body = media::json::parse_or(req.body, nlohmann::json::object());
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}, {"data", search_bookmark_names(body)}}.dump(), "application/json");
    });
#endif

    svr.Get("/v1/chat/xblox-artifacts", [require_v1_auth, shared_roots](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        nlohmann::json doc;
        std::string err;
        if (!media::runtime_settings::load_xblox_artifacts(doc, err)) {
            res.status = 200;
            res.set_content(nlohmann::json{{"ok", false},
                                           {"error", err.empty() ? "xblox artifacts unavailable" : err}}
                                .dump(),
                            "application/json");
            return;
        }
        nlohmann::json items = (doc.contains("items") && doc["items"].is_array())
            ? doc["items"]
            : nlohmann::json::array();
        int limit = 0;
        if (req.has_param("limit")) {
            try {
                limit = std::stoi(req.get_param_value("limit"));
            } catch (...) {
                limit = 0;
            }
        }
        if (limit > 0 && static_cast<std::size_t>(limit) < items.size()) {
            nlohmann::json trimmed = nlohmann::json::array();
            for (std::size_t i = 0; i < static_cast<std::size_t>(limit); ++i)
                trimmed.push_back(items[i]);
            items = std::move(trimmed);
        }
        const auto roots = shared_roots ? shared_roots() : std::vector<media_cli::VfsRoot>{};
        for (auto& item : items) {
            if (!item.is_object())
                continue;
            const std::string path = item.value("path", std::string{});
            const auto shared = shared_file_for_path(path, roots, "desktop");
            if (shared && !shared->rel.empty())
                item["uri"] = shared->uri;
        }
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true},
                                       {"data", {{"version", doc.value("version", 1)}, {"items", std::move(items)}}}}
                            .dump(),
                        "application/json");
    });

    svr.Get("/v1/chat/sessions", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        std::string err;
        nlohmann::json sessions = nlohmann::json::array();
        for (auto& row : media::llm::chat_sessions::list_meta(err))
            sessions.push_back(std::move(row));
        res.status = 200;
        if (!err.empty())
            res.set_content(nlohmann::json{{"ok", false}, {"error", err}}.dump(), "application/json");
        else
            res.set_content(nlohmann::json{{"ok", true}, {"data", {{"sessions", std::move(sessions)}}}}.dump(),
                            "application/json");
    });

    svr.Post("/v1/chat/sessions", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        nlohmann::json session;
        try {
            session = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json{{"ok", false}, {"error", e.what()}}.dump(), "application/json");
            return;
        }
        std::string err;
        const bool ok = session.is_object() && !session.value("id", std::string{}).empty()
                        && media::llm::chat_sessions::save(session, err);
        res.status = 200;
        if (!ok)
            res.set_content(nlohmann::json{{"ok", false},
                                           {"error", err.empty() ? "saveChatSession" : err}}
                                .dump(),
                            "application/json");
        else
            res.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    });

    svr.Get("/v1/chat/session", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        const std::string id = req.get_param_value("id");
        std::string err;
        nlohmann::json session;
        const bool ok = !id.empty() && media::llm::chat_sessions::load(id, session, err);
        res.status = 200;
        if (!ok)
            res.set_content(nlohmann::json{{"ok", false},
                                           {"error", err.empty() ? "loadChatSession" : err}}
                                .dump(),
                            "application/json");
        else
            res.set_content(nlohmann::json{{"ok", true}, {"data", {{"session", std::move(session)}}}}.dump(),
                            "application/json");
    });

    svr.Delete("/v1/chat/session", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        const std::string id = req.get_param_value("id");
        std::string err;
        if (id.empty()) {
            res.status = 200;
            res.set_content(nlohmann::json{{"ok", false}, {"error", "missing id"}}.dump(),
                            "application/json");
            return;
        }
        const auto removed = media::llm::chat_sessions::remove(id, err);
        res.status = 200;
        if (!err.empty())
            res.set_content(nlohmann::json{{"ok", false}, {"error", err}}.dump(), "application/json");
        else
            res.set_content(nlohmann::json{{"ok", true}, {"removed", removed.removed}}.dump(),
                            "application/json");
    });

    svr.Post("/v1/speak", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        nlohmann::json body = media::json::parse_object_or(req.body);
        const auto result = media::llm::path::execute("speak", {
            {"text", body.value("text", std::string{})},
        });
        nlohmann::json out = {{"ok", result.ok}};
        if (!result.ok)
            out["error"] = result.error.empty() ? std::string("speak failed") : result.error;
        res.status = 200;
        res.set_content(out.dump(), "application/json");
    });

    svr.Post("/v1/speak/stop", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        media::llm::path::abort_active_speak();
        res.status = 200;
        res.set_content("{\"ok\":true}", "application/json");
    });

    svr.Post("/v1/speak/pause", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        media::llm::path::pause_active_speak();
        res.status = 200;
        res.set_content("{\"ok\":true}", "application/json");
    });

    svr.Post("/v1/speak/resume", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        media::llm::path::resume_active_speak();
        res.status = 200;
        res.set_content("{\"ok\":true}", "application/json");
    });
}
} // namespace node_detail
} // namespace media_cli
