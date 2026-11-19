// Desktop node: realtime voice session.
#include "node_internal.hpp"

namespace media_cli {
namespace node_detail {

struct RtLive {
    std::uint64_t epoch = 0;
    std::atomic<bool> stop{false};
    std::atomic<int> tool_n{0};
    std::shared_ptr<pm::plugins::chat_host::RealtimeSession> session;
#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
    // Lives as long as the voice session. A spoken run happens after this
    // HTTP handler returns, so the session keeps the same consent surface
    // the process was started with. `stream` posts the card on the realtime
    // event queue. consent_ticket stays bound until the session stops —
    // start() returns as soon as the socket is up, before any tool ask.
    std::unique_ptr<pm::security::ConsentSurfaceScope> consent;
    std::atomic<std::uint64_t> consent_ticket{0};
    std::atomic<std::uint64_t> ask_ticket{0};
#endif
};

struct RtHub {
    std::mutex mu;
    std::condition_variable cv;
    std::vector<nlohmann::json> events;
    std::uint64_t base = 0;
    std::uint64_t epoch = 0;
    std::uint64_t level_gen = 0;
    double level = 0;
    bool closed = false;
    std::shared_ptr<RtLive> live;
};

RtHub g_rt;

void rt_emit_for(std::uint64_t epoch, const char* method, nlohmann::json args)
{
    {
        std::lock_guard lock(g_rt.mu);
        if (epoch != g_rt.epoch)
            return;
        const char* level_method =
            pm::audio::session::audio_method_name(pm::audio::session::AudioMethod::Level);
        if (method && std::strcmp(method, level_method) == 0) {
            double level = 0;
            if (args.is_array() && !args.empty() && args[0].is_number())
                level = args[0].get<double>();
            g_rt.level = std::clamp(level, 0.0, 1.0);
            ++g_rt.level_gen;
            g_rt.cv.notify_all();
            return;
        }
        if (g_rt.events.size() >= 4000) {
            g_rt.events.erase(g_rt.events.begin(), g_rt.events.begin() + 1000);
            g_rt.base += 1000;
        }
        g_rt.events.push_back({{"method", method}, {"args", std::move(args)}});
    }
    g_rt.cv.notify_all();
}

void rt_fail(std::uint64_t epoch, const std::string& err)
{
    rt_emit_for(epoch, pm::audio::session::audio_method_name(pm::audio::session::AudioMethod::Error),
                nlohmann::json::array({err.empty() ? "realtime start failed" : err}));
    rt_emit_for(epoch, pm::audio::session::audio_method_name(pm::audio::session::AudioMethod::Done),
                nlohmann::json::array());
    {
        std::lock_guard lock(g_rt.mu);
        if (epoch == g_rt.epoch)
            g_rt.closed = true;
    }
    g_rt.cv.notify_all();
}

#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
void release_rt_consent_emit(RtLive* live)
{
    if (!live)
        return;
    const std::uint64_t ticket = live->consent_ticket.exchange(0);
    if (ticket)
        pm::security::restore_stream_consent_emit(ticket);
    const std::uint64_t ask = live->ask_ticket.exchange(0);
    if (ask)
        pm::llm::inquire::restore_stream_ask_emit(ask);
}
#endif

std::string rt_text(const char* s)
{
    return s ? s : "";
}

PmChatRtCallbacks rt_callbacks(RtLive* live)
{
    using pm::audio::session::AudioMethod;
    using pm::audio::session::audio_method_name;
    PmChatRtCallbacks cb{};
    cb.userdata = live;
    cb.on_ready = [](void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (live)
            rt_emit_for(live->epoch, audio_method_name(AudioMethod::Ready), nlohmann::json::array());
    };
    cb.on_level = [](double level, void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (live)
            rt_emit_for(live->epoch, audio_method_name(AudioMethod::Level),
                        nlohmann::json::array({std::clamp(level, 0.0, 1.0)}));
    };
    cb.on_text = [](const char* text, void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (live)
            rt_emit_for(live->epoch, audio_method_name(AudioMethod::TextDelta), nlohmann::json::array({rt_text(text)}));
    };
    cb.on_transcript = [](const char* text, void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (live)
            rt_emit_for(live->epoch, audio_method_name(AudioMethod::TranscriptDelta), nlohmann::json::array({rt_text(text)}));
    };
    cb.on_user_transcript = [](const char* text, int is_final, void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (!live)
            return;
        if (is_final) {
            const char* spoken = text ? text : "";
            logger::info(std::string("realtime user transcript chars=")
                         + std::to_string(std::char_traits<char>::length(spoken)));
        }
        rt_emit_for(live->epoch, audio_method_name(AudioMethod::UserTranscript),
                    nlohmann::json::array({rt_text(text), is_final != 0}));
    };
    cb.on_response_done = [](void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (live)
            rt_emit_for(live->epoch, audio_method_name(AudioMethod::ResponseDone), nlohmann::json::array());
    };
    cb.on_error = [](const char* text, void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (live)
            rt_emit_for(live->epoch, audio_method_name(AudioMethod::Error), nlohmann::json::array({rt_text(text)}));
    };
    cb.on_auth_error = [](const char* text, void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (live)
            rt_emit_for(live->epoch, audio_method_name(AudioMethod::AuthError), nlohmann::json::array({rt_text(text)}));
    };
    cb.on_network_error = [](const char* text, void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (live)
            rt_emit_for(live->epoch, audio_method_name(AudioMethod::NetworkError), nlohmann::json::array({rt_text(text)}));
    };
    // Spoken run_pm_agent tools never ride the chat-completion SSE. The phone
    // transcript needs the same tool calls and result paths a typed turn draws.
    cb.on_event_json = [](const char* event_json, void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (!live || !event_json || !event_json[0])
            return;
        const auto parsed = media::json::try_parse(event_json);
        if (!parsed.is_object())
            return;
        const std::string kind = parsed.value("kind", std::string{});
        if (kind != "tool_call" && kind != "tool_result"
            && kind != "tool_file_progress" && kind != "thinking")
            return;
        std::string name = parsed.value("tool_name", std::string{});
        if (kind == "thinking")
            name = parsed.value("text", std::string{});
        if (name.empty())
            name = "tool";
        std::string id;
        if (kind == "tool_call")
            id = std::to_string(live->tool_n.fetch_add(1) + 1);
        else if (kind == "tool_result") {
            const int n = live->tool_n.load();
            id = std::to_string(n > 0 ? n : 1);
        } else {
            id = std::to_string(live->tool_n.load()) + "-" + kind;
        }
        nlohmann::json row{
            {"role", "tool"},
            {"kind", kind},
            {"text", std::move(name)},
            {"toolCallId", "rt-" + id},
        };
        if (kind == "tool_call")
            row["toolRunning"] = true;
        if (parsed.contains("payload")) {
            row["payload"] = media::llm::agent::surface_value(parsed["payload"], 0);
            const auto paths = media::llm::agent::surface_output_paths(parsed["payload"]);
            if (!paths.empty())
                row["paths"] = paths;
        }
        rt_emit_for(live->epoch, audio_method_name(AudioMethod::AppendText),
                    nlohmann::json::array({std::move(row)}));
    };
    cb.on_closed = [](void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (!live)
            return;
        rt_emit_for(live->epoch, audio_method_name(AudioMethod::Done), nlohmann::json::array());
        {
            std::lock_guard lock(g_rt.mu);
            if (live->epoch == g_rt.epoch)
                g_rt.closed = true;
        }
        g_rt.cv.notify_all();
    };
    cb.on_agent_started = [](const char* call_id, const char* goal, void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (!live)
            return;
        const std::string name = rt_text(goal);
        nlohmann::json agent{{"id", rt_text(call_id)}, {"name", name}, {"display_name", name}};
        rt_emit_for(live->epoch, audio_method_name(AudioMethod::AgentStarted), nlohmann::json::array({std::move(agent)}));
    };
    cb.on_agent_result = [](const char* call_id, const char* output_json, void* ud) {
        auto* live = static_cast<RtLive*>(ud);
        if (!live)
            return;
        bool ok = false;
        std::string err;
        const auto parsed = media::json::try_parse(output_json ? output_json : "{}");
        if (parsed.is_object()) {
            const std::string status = parsed.value("status", std::string{});
            ok = status == "completed";
            if (!ok)
                err = parsed.value("error", parsed.value("note", status));
        }
        rt_emit_for(live->epoch, audio_method_name(AudioMethod::AgentDone), nlohmann::json::array({rt_text(call_id), ok, err}));
    };
    return cb;
}

void register_realtime_routes(httplib::Server& svr, const AgentServerOptions& opt,
                              const AuthFn& require_v1_auth)
{
    svr.Post("/v1/realtime/start", [require_v1_auth, &opt](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        nlohmann::json body = media::json::parse_object_or(req.body);
        std::shared_ptr<RtLive> prev;
        std::shared_ptr<RtLive> live;
        {
            std::lock_guard lock(g_rt.mu);
            prev = g_rt.live;
            if (prev)
                prev->stop.store(true);
            ++g_rt.epoch;
            g_rt.events.clear();
            g_rt.base = 0;
            g_rt.level_gen = 0;
            g_rt.level = 0;
            g_rt.closed = false;
            live = std::make_shared<RtLive>();
            live->epoch = g_rt.epoch;
            live->session = std::make_shared<pm::plugins::chat_host::RealtimeSession>();
            g_rt.live = live;
        }
        g_rt.cv.notify_all();
        if (prev) {
            prev->stop.store(true);
#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
            release_rt_consent_emit(prev.get());
#endif
        }
        if (prev && prev->session)
            prev->session->stop();
        prev.reset();
#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
        live->consent = std::make_unique<pm::security::ConsentSurfaceScope>(
            opt.consent_ui.empty() ? std::string("auto-deny") : opt.consent_ui,
            opt.consent_owner);
#endif

        nlohmann::json opts{
            {"preset", body.value("preset", opt.preset)},
            {"chat_session_id", body.value("chat_session_id", std::string{})},
            {"mic_send", body.value("mic_send", true)},
            {"acquire_timeout_ms", body.value("acquire_timeout_ms", 1500)},
            {"router", opt.router},
            {"model", opt.model},
            {"api_key", opt.api_key},
            {"base_url", opt.base_url},
            {"streaming", opt.streaming},
            {"timeout_ms", opt.timeout_ms},
            {"max_iterations", opt.max_iterations},
            {"no_tools", opt.no_tools},
            {"runner", opt.runner},
        };
        if (body.contains("instructions") && body["instructions"].is_string())
            opts["instructions"] = body["instructions"];
        if (body.contains("voice") && body["voice"].is_string())
            opts["voice"] = body["voice"];

#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
        const bool stream_consent = live->consent && live->consent->resolved() == "stream";
#else
        const bool stream_consent = false;
#endif
        std::thread([live, opts = std::move(opts), stream_consent] {
            if (!live || !live->session)
                return;
            if (live->stop.load()) {
                rt_fail(live->epoch, "realtime stopped");
                return;
            }
            if (stream_consent) {
#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
                pm::llm::inquire::ensure_stream_ask_ui_backend();
                auto emit = [epoch = live->epoch](const std::string& type,
                                                  const std::string& payload_json) {
                    auto payload = media::json::try_parse(payload_json);
                    if (!payload.is_object())
                        return false;
                    const char* method =
                        type == "consent" ? pm::audio::session::audio_method_name(pm::audio::session::AudioMethod::ConsentRequest)
                        : type == "ask"   ? pm::audio::session::audio_method_name(pm::audio::session::AudioMethod::AskUser)
                                          : pm::audio::session::audio_method_name(pm::audio::session::AudioMethod::ConsentDismiss);
                    rt_emit_for(epoch, method, nlohmann::json::array({std::move(payload)}));
                    return true;
                };
                const std::uint64_t ticket = pm::security::bind_stream_consent_emit(emit);
                const std::uint64_t ask = pm::llm::inquire::bind_stream_ask_emit(emit);
                live->consent_ticket.store(ticket);
                live->ask_ticket.store(ask);
                if (live->stop.load()) {
                    release_rt_consent_emit(live.get());
                    rt_fail(live->epoch, "realtime stopped");
                    return;
                }
#endif
            }
            const PmChatRtCallbacks cb = rt_callbacks(live.get());
            std::string err;
            if (!live->session->open(opts, cb, err)) {
#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
                release_rt_consent_emit(live.get());
#endif
                rt_fail(live->epoch, err);
                return;
            }
            if (live->stop.load()) {
#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
                release_rt_consent_emit(live.get());
#endif
                live->session->stop();
                return;
            }
            std::string serr;
            if (!live->session->start(serr)) {
#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
                release_rt_consent_emit(live.get());
#endif
                rt_emit_for(live->epoch, pm::audio::session::audio_method_name(pm::audio::session::AudioMethod::Error),
                            nlohmann::json::array(
                                {serr.empty() ? std::string("realtime start failed") : serr}));
                live->session->stop();
                return;
            }
            if (live->stop.load()) {
#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
                release_rt_consent_emit(live.get());
#endif
                live->session->stop();
            }
        }).detach();

        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    });

    svr.Post("/v1/realtime/stop", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        std::shared_ptr<RtLive> live;
        {
            std::lock_guard lock(g_rt.mu);
            live = g_rt.live;
        }
        if (live) {
            live->stop.store(true);
#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
            release_rt_consent_emit(live.get());
#endif
        }
        if (live && live->session)
            live->session->stop();
        else if (live)
            rt_fail(live->epoch, "realtime stopped");
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    });

    svr.Post("/v1/realtime/ptt", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        nlohmann::json body = media::json::parse_object_or(req.body);
        std::shared_ptr<RtLive> live;
        {
            std::lock_guard lock(g_rt.mu);
            live = g_rt.live;
        }
        if (live && live->session) {
            const bool held = body.value("held", true);
            live->session->set_mic_send(held);
            if (!held && body.value("finishInputTurn", false))
                live->session->finish_input();
        }
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    });

    svr.Post("/v1/realtime/speaker", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        nlohmann::json body = media::json::parse_object_or(req.body);
        std::shared_ptr<RtLive> live;
        {
            std::lock_guard lock(g_rt.mu);
            live = g_rt.live;
        }
        if (live && live->session)
            live->session->set_speaker_send(body.value("enabled", true));
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    });

    svr.Post("/v1/realtime/cancel-agent",
             [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        std::shared_ptr<RtLive> live;
        {
            std::lock_guard lock(g_rt.mu);
            live = g_rt.live;
        }
        const bool cancelled = live && live->session && live->session->cancel_agent({});
        res.status = cancelled ? 200 : 409;
        res.set_content(
            nlohmann::json{
                {"ok", cancelled},
                {"error", cancelled ? std::string{} : "no delegated agent is running"},
            }.dump(),
            "application/json");
    });

    svr.Get("/v1/realtime/events", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        const std::uint64_t epoch = [&] {
            std::lock_guard lock(g_rt.mu);
            return g_rt.epoch;
        }();
        logger::info(std::string("realtime events client epoch=") + std::to_string(epoch));
        res.set_chunked_content_provider(
            "text/event-stream; charset=utf-8",
            [epoch](size_t /*offset*/, httplib::DataSink& sink) -> bool {
                std::uint64_t pos = 0;
                std::uint64_t seen_level = 0;
                for (;;) {
                    std::vector<nlohmann::json> batch;
                    nlohmann::json level_event;
                    bool done = false;
                    bool superseded = false;
                    {
                        std::unique_lock lock(g_rt.mu);
                        g_rt.cv.wait_for(lock, std::chrono::seconds(15), [&] {
                            return g_rt.epoch != epoch || g_rt.closed || g_rt.level_gen != seen_level
                                || (g_rt.base + g_rt.events.size()) > pos;
                        });
                        if (g_rt.epoch != epoch)
                            superseded = true;
                        else {
                            if (g_rt.level_gen != seen_level) {
                                seen_level = g_rt.level_gen;
                                level_event = {
                                    {"method", pm::audio::session::audio_method_name(
                                                   pm::audio::session::AudioMethod::Level)},
                                    {"args", nlohmann::json::array({g_rt.level})},
                                };
                            }
                            if (pos < g_rt.base)
                                pos = g_rt.base;
                            const std::uint64_t end = g_rt.base + g_rt.events.size();
                            while (pos < end) {
                                batch.push_back(g_rt.events[static_cast<size_t>(pos - g_rt.base)]);
                                ++pos;
                            }
                            done = g_rt.closed && pos >= end && g_rt.level_gen == seen_level;
                        }
                    }
                    if (superseded)
                        return false;
                    if (!level_event.is_null()) {
                        const std::string line = "data: " + level_event.dump() + "\n\n";
                        if (!sink.write(line.data(), line.size()))
                            return false;
                    }
                    for (const auto& ev : batch) {
                        const std::string line = "data: " + ev.dump() + "\n\n";
                        if (!sink.write(line.data(), line.size()))
                            return false;
                    }
                    if (done) {
                        sink.done();
                        return false;
                    }
                    if (batch.empty() && level_event.is_null()) {
                        static const char ping[] = ": keepalive\n\n";
                        if (!sink.write(ping, sizeof(ping) - 1u))
                            return false;
                    }
                }
            });
    });
}
} // namespace node_detail
} // namespace media_cli
