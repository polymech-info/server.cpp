// Desktop node: models, credit, completions, each, decide, path tools.
#include "node_internal.hpp"

namespace media_cli {
namespace node_detail {

bool looks_like_preset(const std::string& model_or_preset)
{
    if (model_or_preset.empty() || looks_like_loopback_script(model_or_preset))
        return false;
    media::runtime_settings::ChatProviderPreset p;
    std::string err;
    return media::runtime_settings::find_chat_provider_preset(model_or_preset, p, err);
}

nlohmann::json models_list_json()
{
    nlohmann::json data = nlohmann::json::array();
    std::vector<media::runtime_settings::ChatProviderPreset> presets;
    std::string err;
    (void)media::runtime_settings::load_chat_provider_presets(presets, err);

    const long created = openai_created_unix();
    if (presets.empty()) {
        data.push_back({
            {"id", "default"},
            {"object", "model"},
            {"created", created},
            {"owned_by", "tanit"},
        });
    } else {
        for (const auto& p : presets) {
            const std::string id = !p.name.empty() ? p.name : (!p.id.empty() ? p.id : "preset");
            data.push_back({
                {"id", id},
                {"object", "model"},
                {"created", created},
                {"owned_by", "tanit"},
                {"tanit_preset_id", p.id},
                {"tanit_is_default", p.is_default},
            });
        }
    }
    return nlohmann::json{{"object", "list"}, {"data", std::move(data)}};
}


std::string resolve_request_cwd(const httplib::Request& req,
                                const nlohmann::json& body,
                                const AgentServerOptions& opt)
{
    const std::string header =
        req.has_header("X-Tanit-Cwd") ? req.get_header_value("X-Tanit-Cwd") : std::string{};
    return media::llm::agent::cliopt::resolve_body_cwd(body, header, opt);
}

std::string resolve_request_session(const httplib::Request& req, const nlohmann::json& body)
{
    const std::string header =
        req.has_header("X-Tanit-Session") ? req.get_header_value("X-Tanit-Session") : std::string{};
    return media::llm::agent::cliopt::resolve_body_session(body, header);
}

void apply_request_provider_overrides(const httplib::Request& req,
                                      const nlohmann::json& body,
                                      std::string& api_key,
                                      std::string& base_url)
{
    const std::string key = req.has_header("X-Tanit-Provider-Key")
        ? req.get_header_value("X-Tanit-Provider-Key") : std::string{};
    const std::string base = req.has_header("X-Tanit-Provider-Base-Url")
        ? req.get_header_value("X-Tanit-Provider-Base-Url") : std::string{};
    media::llm::agent::cliopt::apply_body_provider_overrides(body, key, base, api_key, base_url);
}

void attach_session_to_turn(media::llm::agent::Turn& turn, const std::string& session_id)
{
    if (session_id.empty())
        return;
    nlohmann::json mem_state, recent_evs;
    media::llm::agent::session_load(session_id, mem_state, recent_evs, 20);
    turn.task_id       = session_id;
    turn.memory_state  = std::move(mem_state);
    turn.recent_events = std::move(recent_evs);
}

bool bearer_authorized(const httplib::Request& req, const std::string& expected_key)
{
    return media::llm::agent::cliopt::bearer_token_authorized(
        req.get_header_value("Authorization"),
        req.get_header_value("x-api-key"),
        req.get_header_value("X-Api-Key"),
        req.get_header_value("api-key"),
        expected_key);
}

void apply_capability_flags(media::llm::agent::Turn& turn, const AgentServerOptions& opt)
{
    const auto caps = media::llm::agent::cliopt::server_turn_caps(opt);
    if (caps.clear_mcp) {
        turn.mcp_tools_enabled = false;
        turn.tool_policy_override_set = true;
    }
    if (caps.skills_on) {
        turn.skills_enabled = true;
        turn.skills_roaming_enabled = true;
        turn.skills_workspace_enabled = true;
        turn.skill_policy_override_set = true;
    } else if (caps.skills_off) {
        turn.skills_enabled = false;
        turn.skill_policy_override_set = true;
    }
    if (caps.planner_off) {
        turn.planner_enabled = false;
        turn.planner_strategy = media::llm::agent::PlannerStrategy::Disabled;
    }
    if (caps.fs_jail)
        turn.fs_jail = true;
}

TurnOutcome run_one_completion(const AgentServerOptions& opt,
                               const nlohmann::json&     body,
                               const ParsedChatRequest&  parsed,
                               const std::string&        request_cwd,
                               const std::string&        request_session,
                               const std::string&        request_id,
                               const StreamEmitFn&       stream_emit,
                               const std::string&        req_provider_key = {},
                               const std::string&        req_provider_base = {})
{
    TurnOutcome out;
    out.session_id = request_session;
    logger::info("llm-server turn phase=resolve id=" + request_id
                 + " prompt_chars=" + std::to_string(parsed.user_prompt.size()));

    media::llm::agent::launch::AgentLaunchSpec launch_spec;
    launch_spec.preset         = opt.preset;
    launch_spec.router         = opt.router;
    launch_spec.model          = opt.model;
    // Resolve with process/profile credentials first. Per-request JWT (below) is
    // applied only for router=tanit so OpenAI presets are not fed a Zitadel bearer.
    launch_spec.api_key        = opt.api_key;
    launch_spec.base_url       = opt.base_url;
    launch_spec.timeout_ms     = opt.timeout_ms;
    launch_spec.max_iterations = opt.max_iterations;
    launch_spec.no_tools       = opt.no_tools;
    launch_spec.api_mode       = opt.api_mode;
    launch_spec.streaming      = opt.streaming;
    launch_spec.planner_enabled = opt.planner;
    launch_spec.planner_schema_budget = opt.planner_budget;
    launch_spec.runner         = opt.runner;

    const std::string req_model = body.value("model", "");
    if (!req_model.empty()) {
        if (looks_like_loopback_script(req_model)) {
            // OpenAI `model` carries a loopback script (inline JSON / @file).
            launch_spec.model = req_model;
            if (launch_spec.router.empty())
                launch_spec.router = "loopback";
        } else if (looks_like_preset(req_model)) {
            launch_spec.preset = req_model;
            // The named preset owns its model. A process-level --model from the
            // previous chat (text-fast on an OpenAI preset) must not stick.
            launch_spec.model.clear();
        } else {
            launch_spec.model = req_model;
        }
    }

    media::llm::agent::launch::AgentLaunchResolved resolved;
    std::string launch_err;
    if (!media::llm::agent::launch::resolve_agent_launch(launch_spec, resolved, launch_err)) {
        out.error = launch_err.empty() ? "resolve_agent_launch failed" : launch_err;
        logger::warn("llm-server turn phase=resolve_error id=" + request_id
                     + " err=" + out.error);
        return out;
    }

    // LiteLLM only: caller's Zitadel JWT as provider key (pm-pics X-Tanit-Provider-Key).
    if (resolved.provider.router == "tanit") {
        if (!req_provider_key.empty())
            resolved.provider.api_key = req_provider_key;
        if (!req_provider_base.empty())
            resolved.provider.base_url = req_provider_base;
    }

    out.model = !resolved.provider.model.empty()
                    ? resolved.provider.model
                    : (!req_model.empty() ? req_model
                                          : (!launch_spec.preset.empty() ? launch_spec.preset
                                                                         : "default"));
    // Don't leak giant loopback scripts into the OpenAI response model field.
    if (looks_like_loopback_script(out.model))
        out.model = "loopback";
    logger::info("llm-server turn phase=resolved id=" + request_id
                 + " router=" + resolved.provider.router
                 + " model=" + out.model);

    media::llm::ChatSettingsOverrideGuard tool_settings_guard(resolved.chat_settings);

    std::string folder = !request_cwd.empty() ? request_cwd : opt.cwd;
    if (!folder.empty()) {
        std::error_code ec;
        fs::path fp = media::path::path_from_utf8(folder);
        if (!fp.is_absolute())
            fp = fs::absolute(fp, ec);
        if (ec || !fs::exists(fp)) {
            out.error = std::string("cwd does not exist: ") + folder;
            return out;
        }
        folder = media::path::path_to_utf8(fp);
    }

    media::llm::agent::Turn turn;
    turn.user_prompt        = parsed.user_prompt;
    turn.seed_chat_messages = parsed.seed_chat_messages;
    turn.folder_hint        = folder;
    turn.selection          = resolve_request_selection(body);
    std::vector<std::pair<std::string, std::string>> staged_files;
    {
        std::string stage_err = stage_mobile_attachments(body, folder, turn.selection, &staged_files);
        if (!stage_err.empty()) {
            out.error = std::move(stage_err);
            return out;
        }
    }
    {
        std::string stage_err = stage_message_images(body, folder, turn.selection);
        if (!stage_err.empty()) {
            out.error = std::move(stage_err);
            return out;
        }
    }
    if (turn.user_prompt.empty() && !turn.selection.empty())
        turn.user_prompt = "Use the selected context.";
    {
        nlohmann::json send = nlohmann::json::object();
        if (body.contains("workflow") && body["workflow"].is_object())
            send["workflow"] = body["workflow"];
        else if (body.contains("tanit") && body["tanit"].is_object()
                 && body["tanit"].contains("workflow") && body["tanit"]["workflow"].is_object())
            send["workflow"] = body["tanit"]["workflow"];
        if (send.contains("workflow")) {
            rewrite_staged_paths(send["workflow"], staged_files);
            media::llm::agent::apply_workflow_send_json(send, turn);
        }
    }
    if (body.contains("tanit") && body["tanit"].is_object()
        && body["tanit"].contains("tool_providers")
        && body["tanit"]["tool_providers"].is_array()) {
        for (const auto& v : body["tanit"]["tool_providers"]) {
            if (v.is_string()) {
                const std::string id = v.get<std::string>();
                if (!id.empty())
                    turn.tool_provider_ids.push_back(id);
            }
        }
    }
    media::llm::agent::launch::apply_launch_policy_to_turn(launch_spec, resolved, turn);
    apply_capability_flags(turn, opt);
    attach_session_to_turn(turn, request_session);
    // Same precedence as `llm agent`: settings profile, then
    // PM_LLM_STRUCTURED_MEMORY_FEATURES, then PM_LLM_MEMORY_RECALL_PROFILE.
    // Loopback benches set the feature mask to none so a long client ramp does
    // not reindex every prior session on each request.
    media::llm::agent::apply_agent_memory_settings_to_turn(turn);
    turn.structured_memory_features =
        media::llm::agent::apply_structured_memory_features_env(
            turn.structured_memory_features, "PM_LLM_STRUCTURED_MEMORY_FEATURES");
    if (const char* recall_profile = std::getenv("PM_LLM_MEMORY_RECALL_PROFILE");
        recall_profile && *recall_profile) {
        media::llm::agent::apply_memory_recall_profile(
            turn.structured_memory_features, recall_profile);
    }
    {
        // Request system message wins over CLI --system-prompt when present.
        const std::string sys_raw =
            !parsed.system_prompt.empty() ? parsed.system_prompt : opt.system_prompt;
        std::string sys_err;
        if (!media::llm::agent::options::apply_system_prompt_option(sys_raw, turn, sys_err)) {
            out.error = sys_err;
            return out;
        }
        std::string planner_err;
        if (!media::llm::agent::options::apply_planner_prompt_option(opt.planner_prompt, turn,
                                                                    planner_err)) {
            out.error = planner_err;
            return out;
        }
    }
    media_cli::parse_agent_disable_tools(opt.disable_tools, opt.no_tools, turn.disabled_path_tools,
                                         &turn.disabled_mcp_tools);
    media_cli::parse_agent_enable_tools(opt.enable_tools, opt.no_tools, turn.allowed_path_tools,
                                        turn.planner_path_tool_allowlist_set);
    turn.parallel_tool_dispatch = !opt.no_parallel_tools;

#if !FEATURE_HOME_LLM_TOOLS
    turn.disabled_path_tools.clear();
#endif

    const auto& prov = resolved.provider;
    if (prov.api_key.empty() && prov.router != "llama" && prov.router != "loopback"
        && prov.router != "mock") {
        out.error = "no API key configured for router '" + prov.router
                    + "' (pass --api-key or configure Chat / provider keys)";
        return out;
    }

#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
    const std::string consent_mode = pm::security::resolve_consent_ui_mode(
        opt.consent_ui,
        resolved.has_preset ? resolved.selected_preset.consent_ui : std::string{},
        "auto-deny");
    const pm::security::ConsentSurfaceScope consent_surface(consent_mode, opt.consent_owner);
    // HTTP hosts (pm-pics TanitChat) answer ask_user via SSE + POST /v1/chat/ask.
    if (consent_surface.resolved() == "stream")
        pm::llm::inquire::ensure_stream_ask_ui_backend();
#endif

    media::llm::agent::AgentRunnerOptions runner_opt;
    runner_opt.kind = media::llm::agent::AgentRunnerKind::Native;
    if (!opt.runner.empty() || !resolved.effective_runner.empty()) {
        const std::string r =
            !opt.runner.empty() ? opt.runner : resolved.effective_runner;
        if (auto k = media::llm::agent::parse_agent_runner_kind(r))
            runner_opt.kind = *k;
    }

    std::string streamed;
    const auto t0 = std::chrono::steady_clock::now();
#if defined(_WIN32)
    pm::perf::emit_event("agent.completion.start", "llm-server",
                         std::string("model=") + out.model);
#endif
    const std::string sse_id      = openai_completion_id();
    const long        sse_created = openai_created_unix();
    out.stream_id      = sse_id;
    out.stream_created = sse_created;
    bool              role_sent        = false;
    bool              stream_had_delta = false;
    std::size_t       stream_delta_count = 0;

    auto write_oai_delta = [&](const std::string& content_piece) -> bool {
        if (!stream_emit)
            return true;
        nlohmann::json delta = nlohmann::json::object();
        if (!role_sent) {
            delta["role"] = "assistant";
            role_sent     = true;
        }
        if (!content_piece.empty())
            delta["content"] = content_piece;
        nlohmann::json chunk{
            {"id", sse_id},
            {"object", "chat.completion.chunk"},
            {"created", sse_created},
            {"model", out.model},
            {"choices",
             nlohmann::json::array(
                 {{{"index", 0}, {"delta", std::move(delta)}, {"finish_reason", nullptr}}})},
        };
        const std::string line = sse_data_line(chunk);
        return stream_emit(line);
    };

    auto write_tanit_event = [&](const std::string& type, const nlohmann::json& payload) -> bool {
        if (!stream_emit)
            return true;
        nlohmann::json ev{{"object", "tanit.event"}, {"type", type}, {"model", out.model}};
        for (auto it = payload.begin(); it != payload.end(); ++it)
            ev[it.key()] = it.value();
        const std::string line = "event: tanit." + type + "\ndata: " + ev.dump() + "\n\n";
        return stream_emit(line);
    };

    // Short transcript fields. The model already has the full envelope in-process;
    // streaming it stalls the side panel.
    struct ToolNote {
        std::string text;
        std::string id;
        long long ms = -1;
    };
    auto tool_note = [](const media::llm::agent::Event& ev) -> ToolNote {
        auto clip = [](std::string s, std::size_t n) {
            for (char& c : s) {
                if (c == '\n' || c == '\r' || c == '\t' || c == '"')
                    c = ' ';
            }
            if (s.size() <= n)
                return s;
            // Do not split a UTF-8 sequence: walk back past continuation bytes.
            std::size_t cut = n;
            while (cut > 0
                   && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80)
                --cut;
            s.resize(cut);
            return s;
        };
        auto cryptic = [](const std::string& s) {
            if (s.empty() || s.find(' ') != std::string::npos)
                return false;
            return s.find_first_not_of(
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
                       == std::string::npos
                   && s.size() >= 6;
        };
        auto arg_detail = [&](const nlohmann::json& args, const std::string& tool) -> std::string {
            if (!args.is_object())
                return {};
            const char* keys[] = {
                "command", "cmd", "query", "text", "url", "path", "prompt",
                "pattern", "instruction",
            };
            if (tool == "run") {
                for (const char* key : {"command", "cmd"}) {
                    if (!args.contains(key) || !args[key].is_string())
                        continue;
                    std::string s = args[key].get<std::string>();
                    if (!s.empty())
                        return clip(std::move(s), 80);
                }
            }
            for (const char* key : keys) {
                if (!args.contains(key) || !args[key].is_string())
                    continue;
                std::string s = args[key].get<std::string>();
                if (s.empty() || cryptic(s))
                    continue;
                return clip(std::move(s), 80);
            }
            return {};
        };
        auto friendly = [](const std::string& name) -> std::string {
            if (name == "browser_read") return "Read page";
            if (name == "browser_find") return "Find";
            if (name == "browser_click") return "Click";
            if (name == "browser_type") return "Type";
            if (name == "browser_select") return "Select";
            if (name == "browser_navigate") return "Open page";
            if (name == "browser_scope") return "Scope page";
            if (name == "browser_batch") return "Page actions";
            if (name == "run") return "Run";
            if (name == "info_lookup") return "Look up";
            if (name == "write_file") return "Write file";
            if (name == "download_url") return "Download";
            if (name == "file_read") return "Read file";
            if (name == "file_glob") return "Find files";
            if (name == "app_batch") return "App actions";
            if (name == "app_inspect_dump") return "Inspect app";
            if (name == "app_command") return "App command";
            if (name == "memory_find") return "Search memory";
            if (name == "service_page_get") return "Open service page";
            std::string s = name;
            for (char& c : s)
                if (c == '_')
                    c = ' ';
            return s;
        };
        ToolNote note;
        std::string name = ev.tool_name.empty() ? "tool" : ev.tool_name;
        std::string detail;
        std::string err;
        if (ev.payload.is_object()) {
            if (ev.payload.contains("id") && ev.payload["id"].is_string())
                note.id = ev.payload["id"].get<std::string>();
            if (ev.payload.contains("duration_ms") && ev.payload["duration_ms"].is_number())
                note.ms = ev.payload["duration_ms"].get<long long>();
            if (ev.kind == media::llm::agent::Event::ToolCall
                && ev.payload.contains("arguments") && ev.payload["arguments"].is_object())
                detail = arg_detail(ev.payload["arguments"], ev.tool_name);
            const nlohmann::json* env = nullptr;
            if (ev.payload.contains("envelope") && ev.payload["envelope"].is_object())
                env = &ev.payload["envelope"];
            if (env && env->contains("error")) {
                const auto& e = (*env)["error"];
                if (e.is_string())
                    err = e.get<std::string>();
                else if (e.is_object())
                    err = e.value("message", std::string{});
            }
        }
        note.text = friendly(name);
        if (!detail.empty())
            note.text += " " + detail;
        else if (!err.empty() && !cryptic(err))
            note.text += " " + clip(std::move(err), 80);
        return note;
    };

#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
    std::uint64_t consent_ticket = 0;
    std::uint64_t ask_ticket = 0;
    if (stream_emit) {
        auto emit = [&](const std::string& type, const std::string& payload_json) {
            const auto payload = media::json::try_parse(payload_json);
            if (!payload.is_object())
                return false;
            return write_tanit_event(type, payload);
        };
        consent_ticket = pm::security::bind_stream_consent_emit(emit);
        ask_ticket = pm::llm::inquire::bind_stream_ask_emit(emit);
    }
    struct ConsentEmitRestore {
        std::uint64_t consent_ticket = 0;
        std::uint64_t ask_ticket = 0;
        ~ConsentEmitRestore()
        {
            // Unblock any ask_user still waiting if the SSE client dropped.
            if (ask_ticket)
                pm::llm::inquire::cancel_stream_ask();
            if (consent_ticket)
                pm::security::restore_stream_consent_emit(consent_ticket);
            if (ask_ticket)
                pm::llm::inquire::restore_stream_ask_emit(ask_ticket);
        }
    } consent_restore{consent_ticket, ask_ticket};
#endif

    const int budget_ms = prov.timeout_ms > 0 ? prov.timeout_ms : 180000;
    const auto turn_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);
    auto turn_cancel = std::make_shared<std::atomic<bool>>(false);
    auto turn_cancel_logged = std::make_shared<std::atomic<bool>>(false);
    turn.cancel_signal = turn_cancel;
    turn.cancel_check = [turn_deadline, budget_ms, turn_cancel, turn_cancel_logged, request_id]() {
        if (turn_cancel->load())
            return true;
        if (media::cli::turn_deadline_reached()
            || std::chrono::steady_clock::now() >= turn_deadline) {
            if (!turn_cancel_logged->exchange(true))
                logger::warn("llm-server turn phase=deadline id=" + request_id
                             + " timeout_ms=" + std::to_string(budget_ms));
            turn_cancel->store(true);
            return true;
        }
        if (!media::cli::turn_client_connected()) {
            if (!turn_cancel_logged->exchange(true))
                logger::warn("llm-server turn phase=client_closed id=" + request_id);
            turn_cancel->store(true);
            return true;
        }
        return false;
    };

    logger::info("llm-server turn phase=agent_start id=" + request_id
                 + " timeout_ms=" + std::to_string(budget_ms));
    auto result = media::llm::agent::run_agent_turn(
        turn, prov, runner_opt, [&](const media::llm::agent::Event& ev) {
            if (ev.kind == media::llm::agent::Event::TextDelta) {
                if (!ev.text.empty()) {
                    streamed += ev.text;
                    stream_had_delta = true;
                    stream_delta_count += 1;
                    if (!write_oai_delta(ev.text))
                        return false;
                }
            } else if (ev.kind == media::llm::agent::Event::AssistantText) {
                // Deltas already streamed the reply — AssistantText is the final snapshot only.
                if (!stream_had_delta && !ev.text.empty()) {
                    streamed += ev.text;
                    if (!write_oai_delta(ev.text))
                        return false;
                }
            } else if (ev.kind == media::llm::agent::Event::Thinking) {
                if (!write_tanit_event("thinking", {{"text", ev.text}}))
                    return false;
            } else if (ev.kind == media::llm::agent::Event::ToolCall
                       || ev.kind == media::llm::agent::Event::ToolResult) {
                const bool starting = ev.kind == media::llm::agent::Event::ToolCall;
                const ToolNote note = tool_note(ev);
                logger::info("llm-server turn phase="
                             + std::string(starting ? "tool_start" : "tool_done")
                             + " id=" + request_id + " tool="
                             + (ev.tool_name.empty() ? std::string("?") : ev.tool_name)
                             + (note.ms >= 0 ? " duration_ms=" + std::to_string(note.ms)
                                             : std::string{}));
                nlohmann::json p{{"name", ev.tool_name}, {"text", note.text}};
                if (!note.id.empty())
                    p["id"] = note.id;
                if (note.ms >= 0)
                    p["duration_ms"] = note.ms;
                if (!starting && ev.payload.is_object()
                    && ev.payload.contains("envelope") && ev.payload["envelope"].is_object()) {
                    const auto& env = ev.payload["envelope"];
                    if (env.contains("results") && env["results"].is_array()) {
                        for (const auto& row : env["results"]) {
                            if (!row.is_object() || !row.value("ok", false))
                                continue;
                            std::string produced = row.value("output_path", std::string{});
                            if (produced.empty())
                                continue;
                            p["path"] = std::move(produced);
                            break;
                        }
                    }
                }
                if (!write_tanit_event(starting ? "tool_call" : "tool_result", p))
                    return false;
            } else if (ev.kind == media::llm::agent::Event::ToolFileProgress
                       && (ev.tool_name == "run" || ev.tool_name == "download_url")) {
                nlohmann::json p = ev.payload.is_object() ? ev.payload : nlohmann::json::object();
                p["name"] = ev.tool_name;
                if (!write_tanit_event("tool_file_progress", p))
                    return false;
            }
            return !media::cli::cancel_requested();
        });
    const auto wall_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - t0)
                             .count();
    logger::info("llm-server turn phase=agent_done id=" + request_id
                 + " ok=" + (result.ok ? std::string("1") : std::string("0"))
                 + " wall_ms=" + std::to_string(wall_ms)
                 + " streamed_chars=" + std::to_string(streamed.size()));
#if defined(_WIN32)
    pm::perf::emit_event(
        result.ok ? "agent.completion.done" : "agent.completion.error", "llm-server",
        std::string("wall_ms=") + std::to_string(wall_ms)
            + (result.ok ? "" : (std::string(" err=") + (result.error.empty() ? "?" : result.error))));
    // Do not call sample() here — that would reset CPU deltas to a post-idle
    // window and poison the next /v1/sysprobe (benchmarks sample mid-flight).
#endif
    (void)wall_ms;

    if (!result.ok) {
        out.error = result.error.empty() ? "agent turn failed" : result.error;
        return out;
    }
    out.ok         = true;
    out.final_text = !result.final_text.empty() ? result.final_text : streamed;
    out.streamed_chars = streamed.size();
    out.stream_deltas  = stream_delta_count;
    out.finish_reason  = !result.llm_finish_reason.empty() ? result.llm_finish_reason : "stop";
    if (result.llm_usage_aggregate.is_object())
        out.usage = result.llm_usage_aggregate;

    logger::trace("llm-server completion: streamed_chars=" + std::to_string(out.streamed_chars)
                  + " final_chars=" + std::to_string(out.final_text.size())
                  + " deltas=" + std::to_string(out.stream_deltas)
                  + " finish_reason=" + out.finish_reason
                  + " had_delta=" + (stream_had_delta ? "1" : "0"));
    if (out.finish_reason == "length")
        logger::warn("llm-server completion: provider finish_reason=length (output likely truncated)");

    // Live stream: flush final text if no deltas were emitted. Caller writes stop + [DONE]
    // after filling queue_wait_ms / exec_ms.
    if (stream_emit && !role_sent && !out.final_text.empty())
        (void)write_oai_delta(out.final_text);
    return out;
}



/// Inherit server provider credentials only when the request is not redirecting
/// to a foreign base URL (avoids attaching the daemon key to a caller URL).

int serve_budget_ms(const AgentServerOptions& opt)
{
    return opt.timeout_ms > 0 ? opt.timeout_ms : 180000;
}

void respond_queue_full(httplib::Response& res, bool expired)
{
    res.status = 503;
    res.set_header("Retry-After", "1");
    res.set_content(
        openai_error(expired ? "timed out waiting for a free turn"
                             : "server busy: turn concurrency queue is full",
                     "server_error",
                     expired ? "queue_timeout" : "queue_full")
            .dump(),
        "application/json");
}

struct PathBaseGuard {
    explicit PathBaseGuard(const std::string& cwd, bool fs_jail = false)
    {
        if (!cwd.empty()) {
            media::llm::path::set_agent_path_base(cwd);
            active_ = true;
        }
        if (fs_jail) {
            media::llm::path::set_agent_fs_jail(true);
            jail_ = true;
        }
    }
    ~PathBaseGuard()
    {
        if (jail_)
            media::llm::path::clear_agent_fs_jail();
        if (active_)
            media::llm::path::clear_agent_path_base();
    }
    PathBaseGuard(const PathBaseGuard&)            = delete;
    PathBaseGuard& operator=(const PathBaseGuard&) = delete;

private:
    bool active_ = false;
    bool jail_   = false;
};

struct PathBlocklistGuard {
    explicit PathBlocklistGuard(const std::vector<std::string>& disabled)
    {
        if (!disabled.empty()) {
            media::llm::path::set_agent_tool_blocklist(disabled);
            active_ = true;
        }
    }
    ~PathBlocklistGuard()
    {
        if (active_)
            media::llm::path::clear_agent_tool_blocklist();
    }
    PathBlocklistGuard(const PathBlocklistGuard&)            = delete;
    PathBlocklistGuard& operator=(const PathBlocklistGuard&) = delete;

private:
    bool active_ = false;
};

bool lan_completion_without_tools(const httplib::Request& req, const std::string& serve_api_key)
{
    if (!g_lan)
        return false;
    const auto secrets = request_secrets(req);
    if (!serve_api_key.empty()) {
        for (const auto& secret : secrets) {
            if (lan::constant_time_equal(secret, serve_api_key))
                return false;
        }
    }
    for (const auto& secret : secrets) {
        lan::DeviceAuth dev;
        if (g_lan->authorize(secret, dev))
            return !dev.has("tools");
    }
    return false;
}

void register_llm_routes(httplib::Server& svr, const AgentServerOptions& opt, InflightGate& gate,
                         const AuthFn& require_v1_auth)
{
    svr.Get("/v1/models", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        // Discovery stays open on the direct HTTP port. Phones on the TLS proxy authenticate.
        if (lan_hop_present(req) && !require_v1_auth(req, res))
            return;
        res.status = 200;
        res.set_content(models_list_json().dump(), "application/json");
    });

    svr.Get("/v1/credit", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        // Prefer per-request Zitadel bearer (pm-pics), else process `tanit-cli login`.
        std::string token;
        std::string token_err;
        if (req.has_header("X-Tanit-Provider-Key"))
            token = trim_ascii(req.get_header_value("X-Tanit-Provider-Key"));
        if (token.empty()
            && (!pm_zitadel_oauth_read_access_token(token, token_err) || token.empty())) {
            res.status = 200;
            res.set_content(nlohmann::json{{"ok", false},
                                           {"error", token_err.empty() ? "not signed in" : token_err}}
                                .dump(),
                            "application/json");
            return;
        }
        std::string api_key;
        std::string base_url;
        media::runtime_settings::merge_provider_credentials("tanit", false, api_key, base_url);
        if (req.has_header("X-Tanit-Provider-Base-Url")) {
            const std::string h = trim_ascii(req.get_header_value("X-Tanit-Provider-Base-Url"));
            if (!h.empty())
                base_url = h;
        }
        media::pixlwiz_cli::PixlWizBudgetInfo info;
        std::string err;
        if (!media::pixlwiz_cli::pixlwiz_get_budget_info(token, base_url, info, err)) {
            res.status = 200;
            res.set_content(nlohmann::json{{"ok", false},
                                           {"error", err.empty() ? "budget lookup failed" : err}}
                                .dump(),
                            "application/json");
            return;
        }
        nlohmann::json data{{"spend", info.spend}};
        if (info.max_budget >= 0.0)
            data["max_budget"] = info.max_budget;
        else
            data["max_budget"] = nullptr;
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}, {"data", std::move(data)}}.dump(),
                        "application/json");
    });

    svr.Post("/v1/llm/path-tools/call",
             [&opt, &gate, require_v1_auth](const httplib::Request& req, httplib::Response& res) {
                 if (!require_v1_auth(req, res))
                     return;
                 if (opt.no_tools) {
                     res.status = 403;
                     res.set_content(
                         openai_error("path tools are disabled on this daemon (--no-tools)",
                                      "invalid_request_error", "tools_disabled")
                             .dump(),
                         "application/json");
                     return;
                 }
                 nlohmann::json body;
                 try {
                     body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
                 } catch (const std::exception& e) {
                     res.status = 400;
                     res.set_content(
                         openai_error(std::string("invalid JSON: ") + e.what(),
                                      "invalid_request_error", "invalid_json")
                             .dump(),
                         "application/json");
                     return;
                 }
                 if (!body.contains("name") || !body["name"].is_string()) {
                     res.status = 400;
                     res.set_content(
                         openai_error("'name' (string) is required", "invalid_request_error",
                                      "missing_name")
                             .dump(),
                         "application/json");
                     return;
                 }
                 const std::string          name = body["name"].get<std::string>();
                 const nlohmann::json       args =
                     body.contains("arguments") && body["arguments"].is_object()
                         ? body["arguments"]
                         : nlohmann::json::object();

                 std::vector<std::string> disabled;
                 std::vector<std::string> allowed;
                 bool                     allowlist_set = false;
                 media_cli::parse_agent_disable_tools(opt.disable_tools, opt.no_tools, disabled,
                                                     nullptr);
                 media_cli::parse_agent_enable_tools(opt.enable_tools, opt.no_tools, allowed,
                                                    allowlist_set);
                 if (allowlist_set) {
                     bool ok = false;
                     for (const auto& a : allowed) {
                         if (a == name) {
                             ok = true;
                             break;
                         }
                     }
                     if (!ok) {
                         res.status = 403;
                         res.set_content(
                             openai_error("tool is not in the daemon enable-tools allowlist: " + name,
                                          "invalid_request_error", "tool_not_allowed")
                                 .dump(),
                             "application/json");
                         return;
                     }
                 }

                 InflightGate::Slot slot(gate, serve_budget_ms(opt));
                 if (!slot) {
                     respond_queue_full(res, slot.expired());
                     return;
                 }
                 const std::string req_cwd = resolve_request_cwd(req, body, opt);
                 PathBaseGuard     path_base(req_cwd, opt.fs_jail);
                 PathBlocklistGuard block(disabled);
                 const media::llm::path::ExecuteResult out = media::llm::path::execute(name, args);
                 res.status = 200;
                 res.set_content(out.envelope.dump(), "application/json");
             });

    // jq leaf transform (same engine as `llm agent each`). Inline `document`
    // or server-side `source` path; response includes `output` (+ optional dst write).
    svr.Post("/v1/llm/each",
             [&opt, &gate, require_v1_auth](const httplib::Request& req, httplib::Response& res) {
                 if (!require_v1_auth(req, res))
                     return;
                 nlohmann::json body;
                 try {
                     body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
                 } catch (const std::exception& e) {
                     res.status = 400;
                     res.set_content(
                         openai_error(std::string("invalid JSON: ") + e.what(),
                                      "invalid_request_error", "invalid_json")
                             .dump(),
                         "application/json");
                     return;
                 }
                 media::llm::agent::each::EachOptions each_opt;
                 std::string parse_err;
                 if (!media::llm::agent::each::parse_each_options(body, each_opt, parse_err)) {
                     res.status = 400;
                     res.set_content(
                         openai_error(parse_err, "invalid_request_error", "invalid_each_options")
                             .dump(),
                         "application/json");
                     return;
                 }
                 InflightGate::Slot slot(gate, serve_budget_ms(opt));
                 if (!slot) {
                     respond_queue_full(res, slot.expired());
                     return;
                 }
                 const std::string req_cwd = resolve_request_cwd(req, body, opt);
                 if (each_opt.cwd.empty())
                     each_opt.cwd = req_cwd;
                 if (each_opt.preset.empty())
                     each_opt.preset = opt.preset;
                 if (each_opt.router.empty())
                     each_opt.router = opt.router;
                 if (each_opt.model.empty())
                     each_opt.model = opt.model;
                 apply_request_provider_overrides(req, body, each_opt.api_key, each_opt.base_url);
                 apply_provider_defaults(each_opt.api_key, each_opt.base_url, opt.api_key,
                                         opt.base_url);
                 if (each_opt.timeout_ms <= 0 && opt.timeout_ms > 0)
                     each_opt.timeout_ms = opt.timeout_ms;
                 if (each_opt.api_mode.empty() && !opt.api_mode.empty())
                     each_opt.api_mode = opt.api_mode;
                 if (each_opt.system_prompt.empty() && !opt.system_prompt.empty())
                     each_opt.system_prompt = opt.system_prompt;

                 media::llm::agent::each::EachResult result;
                 (void)media::llm::agent::each::run_each(each_opt, result);
                 if (!result.ok && result.document.is_null()) {
                     const bool bad_req =
                         result.error.find("required") != std::string::npos
                         || result.error.find("must be") != std::string::npos
                         || result.error.find("invalid JSON") != std::string::npos
                         || result.error.find("could not open") != std::string::npos;
                     res.status = bad_req ? 400 : 500;
                     res.set_content(
                         openai_error(result.error.empty() ? "each failed" : result.error,
                                      bad_req ? "invalid_request_error" : "server_error",
                                      "each_error")
                             .dump(),
                         "application/json");
                     return;
                 }
                 res.status = 200;
                 res.set_content(result.to_json().dump(), "application/json");
             });

    // System One decisions (same engine as `llm agent decide`).
    svr.Post("/v1/llm/decide",
             [&opt, &gate, require_v1_auth](const httplib::Request& req, httplib::Response& res) {
                 if (!require_v1_auth(req, res))
                     return;
                 nlohmann::json body;
                 try {
                     body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
                 } catch (const std::exception& e) {
                     res.status = 400;
                     res.set_content(
                         openai_error(std::string("invalid JSON: ") + e.what(),
                                      "invalid_request_error", "invalid_json")
                             .dump(),
                         "application/json");
                     return;
                 }
                 media::llm::agent::decide::DecideOptions decide_opt;
                 std::string parse_err;
                 if (!media::llm::agent::decide::parse_decide_options(body, decide_opt, parse_err)) {
                     res.status = 400;
                     res.set_content(
                         openai_error(parse_err, "invalid_request_error", "invalid_decide_options")
                             .dump(),
                         "application/json");
                     return;
                 }
                 InflightGate::Slot slot(gate, serve_budget_ms(opt));
                 if (!slot) {
                     respond_queue_full(res, slot.expired());
                     return;
                 }
                 const std::string req_cwd = resolve_request_cwd(req, body, opt);
                 if (decide_opt.cwd.empty())
                     decide_opt.cwd = req_cwd;
                 if (decide_opt.model.empty())
                     decide_opt.model = opt.model;
                 apply_request_provider_overrides(req, body, decide_opt.api_key, decide_opt.base_url);
                 apply_provider_defaults(decide_opt.api_key, decide_opt.base_url, opt.api_key,
                                         opt.base_url);
                 if (decide_opt.timeout_ms <= 0 && opt.timeout_ms > 0)
                     decide_opt.timeout_ms = opt.timeout_ms;

                 media::llm::agent::decide::DecideResult result;
                 const bool ok = media::llm::agent::decide::run_decide(decide_opt, result);
                 if (!ok) {
                     const bool bad_req =
                         result.error.find("required") != std::string::npos
                         || result.error.find("must be") != std::string::npos
                         || result.error.find("cannot be combined") != std::string::npos
                         || result.error.find("matched nothing") != std::string::npos
                         || result.error.find("invalid JSON") != std::string::npos;
                     res.status = bad_req ? 400 : 500;
                     res.set_content(
                         openai_error(result.error.empty() ? "decide failed" : result.error,
                                      bad_req ? "invalid_request_error" : "server_error",
                                      "decide_error")
                             .dump(),
                         "application/json");
                     return;
                 }
                 res.status = 200;
                 res.set_content(result.to_json().dump(), "application/json");
             });

    svr.Post("/v1/chat/completions",
             [&opt, &gate, require_v1_auth](const httplib::Request& req, httplib::Response& res) {
                 if (!require_v1_auth(req, res))
                     return;

                 nlohmann::json body;
                 try {
                     body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body);
                 } catch (const std::exception& e) {
                     res.status = 400;
                     res.set_content(openai_error(std::string("invalid JSON: ") + e.what(),
                                                  "invalid_request_error", "invalid_json")
                                         .dump(),
                                     "application/json");
                     return;
                 }

                 ParsedChatRequest parsed;
                 std::string       parse_err;
                 if (!parse_chat_request(body, parsed, parse_err)) {
                     res.status = 400;
                     res.set_content(
                         openai_error(parse_err, "invalid_request_error", "invalid_messages").dump(),
                         "application/json");
                     return;
                 }

                 const std::string req_cwd = resolve_request_cwd(req, body, opt);
                 const std::string req_session =
                     media::llm::agent::session_get_or_create(resolve_request_session(req, body));
                 const bool        stream  = body.value("stream", false);
                 const std::string request_id = openai_completion_id();
                 logger::info("llm-server request phase=received id=" + request_id
                              + " stream=" + (stream ? std::string("1") : std::string("0"))
                              + " prompt_chars=" + std::to_string(parsed.user_prompt.size()));

                 // Stash per-request provider creds; applied in run_one_completion only
                 // when resolved router is tanit (LiteLLM). OpenAI presets keep profile keys.
                 AgentServerOptions turn_opt = opt;
                 if (lan_completion_without_tools(req, opt.serve_api_key))
                     turn_opt.no_tools = true;
                 std::string        req_provider_key;
                 std::string        req_provider_base;
                 apply_request_provider_overrides(req, body, req_provider_key, req_provider_base);

                 if (stream) {
                     // Live SSE: hold the gate slot for the lifetime of the provider.
                     {
                         const auto gs = gate.stats();
                         logger::info("llm-server request phase=gate_wait id=" + request_id
                                      + " inflight=" + std::to_string(gs.inflight)
                                      + " waiting=" + std::to_string(gs.waiting));
                     }
                     auto slot = std::make_shared<InflightGate::Slot>(gate, serve_budget_ms(turn_opt));
                     if (!*slot) {
                         logger::warn("llm-server request phase=gate_rejected id=" + request_id
                                      + (slot->expired() ? " reason=timeout" : " reason=full"));
                         respond_queue_full(res, slot->expired());
                         return;
                     }
                     logger::info("llm-server request phase=gate_acquired id=" + request_id
                                  + " wait_ms=" + std::to_string(slot->queue_wait_ms()));
                     // Browser env after gate so waiters do not stamp process env early.
                     auto browser = std::make_shared<BrowserEnvGuard>(body);
                     res.status = 200;
                     res.set_header("Cache-Control", "no-cache");
                     res.set_header("Connection", "keep-alive");
                     res.set_header("X-Tanit-Session", req_session);
                     res.set_header("X-Tanit-Queue-Wait-Ms", std::to_string(slot->queue_wait_ms()));
                     res.set_chunked_content_provider(
                         "text/event-stream; charset=utf-8",
                         [turn_opt, body, parsed, req_cwd, req_session, request_id, slot, browser,
                          req_provider_key, req_provider_base](
                             size_t /*offset*/, httplib::DataSink& sink) -> bool {
                             (void)browser;
                             const auto t_exec0 = std::chrono::steady_clock::now();
                             bool client_connected = true;
                             media::cli::ScopedTurnClientProbe client_probe([&]() {
                                 if (!client_connected)
                                     return false;
                                 return !sink.is_writable || sink.is_writable();
                             });
                             auto emit = [&sink, &client_connected, &request_id](
                                             std::string_view wire) -> bool {
                                 const bool ok = sink.write(wire.data(), wire.size());
                                 if (!ok && client_connected) {
                                     client_connected = false;
                                     logger::warn("llm-server request phase=client_closed id="
                                                  + request_id);
                                 }
                                 return ok;
                             };
                             TurnOutcome outcome =
                                 run_one_completion(turn_opt, body, parsed, req_cwd, req_session,
                                                    request_id, emit, req_provider_key,
                                                    req_provider_base);
                             outcome.queue_wait_ms = slot->queue_wait_ms();
                             outcome.exec_ms =
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - t_exec0)
                                     .count();
                             if (!outcome.ok) {
                                 const std::string line = sse_data_line(openai_error(outcome.error));
                                 (void)sink.write(line.data(), line.size());
                             } else {
                                 nlohmann::json usage = usage_fields(outcome.usage);
                                 if (outcome.exec_ms > 0)
                                     usage["wall_ms"] = outcome.exec_ms;
                                 nlohmann::json stop{
                                     {"id",
                                      outcome.stream_id.empty() ? openai_completion_id()
                                                                : outcome.stream_id},
                                     {"object", "chat.completion.chunk"},
                                     {"created",
                                      outcome.stream_created != 0 ? outcome.stream_created
                                                                  : openai_created_unix()},
                                     {"model", outcome.model},
                                     {"choices",
                                      nlohmann::json::array(
                                          {{{"index", 0},
                                            {"delta", nlohmann::json::object()},
                                            {"finish_reason",
                                             outcome.finish_reason.empty() ? "stop"
                                                                           : outcome.finish_reason}}})},
                                     {"tanit",
                                      {{"queue_wait_ms", outcome.queue_wait_ms},
                                       {"exec_ms", outcome.exec_ms},
                                       {"session_id", outcome.session_id},
                                       {"streamed_chars", outcome.streamed_chars},
                                       {"stream_deltas", outcome.stream_deltas}}},
                                     {"usage", std::move(usage)},
                                 };
                                 const std::string stop_line = sse_data_line(stop);
                                 (void)sink.write(stop_line.data(), stop_line.size());
                             }
                             static const char done[] = "data: [DONE]\n\n";
                             (void)sink.write(done, sizeof(done) - 1u);
                             sink.done();
                             logger::info("llm-server request phase=finished id=" + request_id
                                          + " ok="
                                          + (outcome.ok ? std::string("1") : std::string("0"))
                                          + " exec_ms=" + std::to_string(outcome.exec_ms));
                             return false;
                         });
                     return;
                 }

                 {
                     const auto gs = gate.stats();
                     logger::info("llm-server request phase=gate_wait id=" + request_id
                                  + " inflight=" + std::to_string(gs.inflight)
                                  + " waiting=" + std::to_string(gs.waiting));
                 }
                 InflightGate::Slot slot(gate, serve_budget_ms(turn_opt));
                 if (!slot) {
                     logger::warn("llm-server request phase=gate_rejected id=" + request_id
                                  + (slot.expired() ? " reason=timeout" : " reason=full"));
                     respond_queue_full(res, slot.expired());
                     return;
                 }
                 logger::info("llm-server request phase=gate_acquired id=" + request_id
                              + " wait_ms=" + std::to_string(slot.queue_wait_ms()));
                 BrowserEnvGuard browser(body);
                 const auto      t_exec0 = std::chrono::steady_clock::now();
                 TurnOutcome     outcome =
                     run_one_completion(turn_opt, body, parsed, req_cwd, req_session, request_id, {},
                                        req_provider_key, req_provider_base);
                 outcome.queue_wait_ms = slot.queue_wait_ms();
                 outcome.exec_ms       = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - t_exec0)
                                     .count();
                 res.set_header("X-Tanit-Session", req_session);
                 res.set_header("X-Tanit-Queue-Wait-Ms", std::to_string(outcome.queue_wait_ms));
                 res.set_header("X-Tanit-Exec-Ms", std::to_string(outcome.exec_ms));

                 if (!outcome.ok) {
                     logger::warn("llm-server request phase=finished id=" + request_id
                                  + " ok=0 exec_ms=" + std::to_string(outcome.exec_ms));
                     res.status = 500;
                     res.set_content(openai_error(outcome.error).dump(), "application/json");
                     return;
                 }
                 logger::info("llm-server request phase=finished id=" + request_id
                              + " ok=1 exec_ms=" + std::to_string(outcome.exec_ms));
                 res.status = 200;
                 res.set_content(completion_success_json(outcome).dump(), "application/json");
             });
}
} // namespace node_detail
} // namespace media_cli
