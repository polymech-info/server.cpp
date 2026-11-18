// Desktop node: microphone, loopback, and playback routes.
#include "node_internal.hpp"

namespace media_cli {
namespace node_detail {

#if defined(FEATURE_AUDIO_SOURCES) && FEATURE_AUDIO_SOURCES
std::shared_ptr<pm::audio::SourceHost> g_llm_audio_host;
std::shared_ptr<pm::audio::SinkHost> g_llm_audio_sink;
#endif

void stop_llm_audio_host()
{
#if defined(FEATURE_AUDIO_SOURCES) && FEATURE_AUDIO_SOURCES
    if (g_llm_audio_host)
        g_llm_audio_host->stop();
    if (g_llm_audio_sink)
        g_llm_audio_sink->stop();
#endif
}

void register_audio_routes(httplib::Server& svr, const AuthFn& require_v1_auth)
{
#if defined(FEATURE_AUDIO_SOURCES) && FEATURE_AUDIO_SOURCES
    g_llm_audio_host = std::make_shared<pm::audio::SourceHost>();
    {
        const auto host = g_llm_audio_host;
        auto write_audio = [](httplib::Response& res, const pm::audio::SourceReply& reply) {
            res.status = reply.status;
            res.set_content(reply.body.dump(2) + "\n", "application/json; charset=utf-8");
        };
        auto read_body = [](const httplib::Request& req, httplib::Response& res, nlohmann::json& body) -> bool {
            try {
                body = req.body.empty() ? nlohmann::json::object() : nlohmann::json::parse(req.body);
            } catch (const std::exception& ex) {
                res.status = 400;
                res.set_content(nlohmann::json{{"ok", false},
                                               {"error", std::string("invalid JSON: ") + ex.what()}}
                                    .dump(2) + "\n",
                                "application/json; charset=utf-8");
                return false;
            }
            return true;
        };
        svr.Get("/v1/audio/status", [host, require_v1_auth, write_audio](const httplib::Request& req,
                                                                         httplib::Response& res) {
            if (!require_v1_auth(req, res))
                return;
            write_audio(res, host->status());
        });
        svr.Get("/v1/audio/sources", [host, require_v1_auth, write_audio](const httplib::Request& req,
                                                                          httplib::Response& res) {
            if (!require_v1_auth(req, res))
                return;
            write_audio(res, host->sources());
        });
        svr.Post("/v1/audio/start", [host, require_v1_auth, write_audio, read_body](const httplib::Request& req,
                                                                                    httplib::Response& res) {
            if (!require_v1_auth(req, res))
                return;
            nlohmann::json body;
            if (!read_body(req, res, body))
                return;
            write_audio(res, host->start(body));
        });
        svr.Post("/v1/audio/stop", [host, require_v1_auth, write_audio](const httplib::Request& req,
                                                                        httplib::Response& res) {
            if (!require_v1_auth(req, res))
                return;
            host->stop();
            auto reply = host->status();
            reply.body["accepted"] = true;
            reply.body["stopped"] = true;
            write_audio(res, reply);
        });
        svr.Post("/v1/audio/source", [host, require_v1_auth, write_audio, read_body](const httplib::Request& req,
                                                                                     httplib::Response& res) {
            if (!require_v1_auth(req, res))
                return;
            nlohmann::json body;
            if (!read_body(req, res, body))
                return;
            write_audio(res, host->select(body));
        });
        svr.Get("/v1/audio/stream", [host, require_v1_auth](const httplib::Request& req, httplib::Response& res) {
            if (!require_v1_auth(req, res))
                return;
            const auto idle = host->status();
            if (!idle.body.value("running", false)) {
                res.status = 409;
                res.set_content(nlohmann::json{{"ok", false},
                                               {"error", "audio capture is idle"},
                                               {"phase", "idle"}}
                                    .dump(2) + "\n",
                                "application/json; charset=utf-8");
                return;
            }
            res.set_header("Cache-Control", "no-cache");
            res.set_header("X-Audio-Sample-Rate", std::to_string(idle.body.value("sampleRate", 48000)));
            res.set_header("X-Audio-Channels", std::to_string(idle.body.value("channels", 2)));
            res.set_chunked_content_provider(
                "application/octet-stream",
                [host](size_t /*offset*/, httplib::DataSink& sink) -> bool {
                    std::int16_t buf[960];
                    const int frames = host->pull(buf, 480, 200);
                    if (frames < 0) {
                        sink.done();
                        return false;
                    }
                    if (frames == 0)
                        return true;
                    const size_t bytes = static_cast<size_t>(frames) * 2 * sizeof(std::int16_t);
                    if (!sink.write(reinterpret_cast<const char*>(buf), bytes))
                        return false;
                    return true;
                });
        });
    }
    g_llm_audio_sink = std::make_shared<pm::audio::SinkHost>();
    {
        const auto sink = g_llm_audio_sink;
        auto write_sink = [](httplib::Response& res, const pm::audio::SinkReply& reply) {
            res.status = reply.status;
            res.set_content(reply.body.dump(2) + "\n", "application/json; charset=utf-8");
        };
        auto read_body = [](const httplib::Request& req, httplib::Response& res, nlohmann::json& body) -> bool {
            try {
                body = req.body.empty() ? nlohmann::json::object() : nlohmann::json::parse(req.body);
            } catch (const std::exception& ex) {
                res.status = 400;
                res.set_content(nlohmann::json{{"ok", false},
                                               {"error", std::string("invalid JSON: ") + ex.what()}}
                                    .dump(2) + "\n",
                                "application/json; charset=utf-8");
                return false;
            }
            return true;
        };
        svr.Get("/v1/audio/outputs", [sink, require_v1_auth, write_sink](const httplib::Request& req,
                                                                         httplib::Response& res) {
            if (!require_v1_auth(req, res))
                return;
            write_sink(res, sink->outputs());
        });
        svr.Post("/v1/audio/output", [sink, require_v1_auth, write_sink, read_body](const httplib::Request& req,
                                                                                    httplib::Response& res) {
            if (!require_v1_auth(req, res))
                return;
            nlohmann::json body;
            if (!read_body(req, res, body))
                return;
            write_sink(res, sink->select(body));
        });
        svr.Post("/v1/audio/play/start", [sink, require_v1_auth, write_sink, read_body](const httplib::Request& req,
                                                                                        httplib::Response& res) {
            if (!require_v1_auth(req, res))
                return;
            nlohmann::json body;
            if (!read_body(req, res, body))
                return;
            write_sink(res, sink->start(body));
        });
        svr.Post("/v1/audio/play/stop", [sink, require_v1_auth, write_sink](const httplib::Request& req,
                                                                            httplib::Response& res) {
            if (!require_v1_auth(req, res))
                return;
            sink->stop();
            auto reply = sink->status();
            reply.body["accepted"] = true;
            reply.body["stopped"] = true;
            write_sink(res, reply);
        });
        svr.Post("/v1/audio/play", [sink, require_v1_auth, write_sink](const httplib::Request& req,
                                                                       httplib::Response& res) {
            if (!require_v1_auth(req, res))
                return;
            if (req.body.size() > 256u * 1024u) {
                res.status = 413;
                res.set_content(nlohmann::json{{"ok", false}, {"error", "audio chunk is too large"}}.dump(2) + "\n",
                                "application/json; charset=utf-8");
                return;
            }
            auto header_u32 = [&](const char* key, std::uint32_t fallback) {
                if (!req.has_header(key))
                    return fallback;
                try {
                    const unsigned long parsed = std::stoul(req.get_header_value(key));
                    if (parsed == 0 || parsed > 96000)
                        return fallback;
                    return static_cast<std::uint32_t>(parsed);
                } catch (...) {
                    return fallback;
                }
            };
            const std::uint32_t rate = header_u32("X-Audio-Sample-Rate", 48000);
            const std::uint32_t channels = header_u32("X-Audio-Channels", 2);
            const std::uint32_t width = std::max<std::uint32_t>(1, std::min<std::uint32_t>(channels, 8));
            if (req.body.size() < static_cast<size_t>(width) * sizeof(std::int16_t)) {
                res.status = 400;
                res.set_content(nlohmann::json{{"ok", false}, {"error", "audio chunk is empty"}}.dump(2) + "\n",
                                "application/json; charset=utf-8");
                return;
            }
            const size_t samples = req.body.size() / sizeof(std::int16_t);
            const int frames = static_cast<int>(samples / width);
            std::vector<std::int16_t> pcm(static_cast<size_t>(frames) * width);
            std::memcpy(pcm.data(), req.body.data(), pcm.size() * sizeof(std::int16_t));
            write_sink(res, sink->push(pcm.data(), frames, rate, width));
        });
    }
#else
    auto audio_unavailable = [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        res.status = 501;
        res.set_content(openai_error("audio sources are not built into this binary", "server_error",
                                     "audio_unavailable")
                            .dump(),
                        "application/json");
    };
    for (const char* path : {"/v1/audio/status", "/v1/audio/sources", "/v1/audio/stream", "/v1/audio/outputs"})
        svr.Get(path, audio_unavailable);
    for (const char* path : {"/v1/audio/start", "/v1/audio/stop", "/v1/audio/source", "/v1/audio/output",
                             "/v1/audio/play", "/v1/audio/play/start", "/v1/audio/play/stop"})
        svr.Post(path, audio_unavailable);
#endif
}
} // namespace node_detail
} // namespace media_cli
