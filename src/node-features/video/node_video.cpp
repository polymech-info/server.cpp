// Desktop node: camera and screen routes.
// Capture stays in video_stream_host. JSON parsing is json_utils. Errors use route_error.
#include "pm/node/lan_routes.hpp"

#include "json/json_utils.hpp"
#include "video_stream_host.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace media_cli {
namespace node_detail {

#if defined(FEATURE_VIDEO) && FEATURE_VIDEO && defined(FEATURE_VIDEO_STREAM) && FEATURE_VIDEO_STREAM
std::shared_ptr<VideoStreamHost> g_llm_video_host;
#endif

void stop_llm_video_host()
{
#if defined(FEATURE_VIDEO) && FEATURE_VIDEO && defined(FEATURE_VIDEO_STREAM) && FEATURE_VIDEO_STREAM
    if (g_llm_video_host)
        g_llm_video_host->stop();
#endif
}

#if defined(FEATURE_VIDEO) && FEATURE_VIDEO && defined(FEATURE_VIDEO_STREAM) && FEATURE_VIDEO_STREAM
bool fill_video_update(const nlohmann::json& body, VideoStreamCaptureUpdate& upd, std::string& err)
{
    auto fail = [&](std::string msg) {
        err = std::move(msg);
        return false;
    };
    if (body.contains("input")) {
        if (!body["input"].is_string())
            return fail("input must be a string");
        upd.input = body["input"].get<std::string>();
    }
    auto take_int = [&](const char* primary, const char* alias, std::optional<int>& slot) -> bool {
        const char* key = nullptr;
        const nlohmann::json* value = nullptr;
        if (body.contains(primary)) {
            key = primary;
            value = &body.at(primary);
        } else if (alias && body.contains(alias)) {
            key = alias;
            value = &body.at(alias);
        }
        if (!value)
            return true;
        if (!value->is_number())
            return fail(std::string(key) + " must be a number");
        const double n = value->get<double>();
        if (!std::isfinite(n) || n < -1000000.0 || n > 1000000.0)
            return fail(std::string(key) + " is out of range");
        slot = static_cast<int>(n);
        return true;
    };
    if (!take_int("fps", nullptr, upd.fps))
        return false;
    if (!take_int("mjpegQuality", "mjpeg_quality", upd.mjpeg_quality))
        return false;
    if (!take_int("bitrateKbps", "bitrate_kbps", upd.bitrate_kbps))
        return false;
    auto take_bool = [&](const char* primary, const char* alias, std::optional<bool>& slot) -> bool {
        const char* key = nullptr;
        const nlohmann::json* value = nullptr;
        if (body.contains(primary)) {
            key = primary;
            value = &body.at(primary);
        } else if (alias && body.contains(alias)) {
            key = alias;
            value = &body.at(alias);
        }
        if (!value)
            return true;
        if (!value->is_boolean())
            return fail(std::string(key) + " must be a boolean");
        slot = value->get<bool>();
        return true;
    };
    if (!take_bool("includeCursor", "include_cursor", upd.include_cursor))
        return false;
    if (body.contains("encoder")) {
        if (!body["encoder"].is_string())
            return fail("encoder must be a string");
        upd.encoder = body["encoder"].get<std::string>();
    }
    return true;
}

void write_video_json(httplib::Response& res, const nlohmann::json& body, int status = 200)
{
    res.status = status;
    res.set_content(body.dump(2) + "\n", "application/json; charset=utf-8");
}
#endif

void register_video_routes(httplib::Server& svr, const AuthFn& require_v1_auth)
{
#if defined(FEATURE_VIDEO) && FEATURE_VIDEO && defined(FEATURE_VIDEO_STREAM) && FEATURE_VIDEO_STREAM
    {
        VideoStreamHostConfig cfg;
        cfg.path_prefix = "/v1/video";
        cfg.require_stream_token = false;
        cfg.input = "screen:0";
        cfg.stream_id = "llm";
        cfg.stop_when_last_viewer = true;
        g_llm_video_host = std::make_shared<VideoStreamHost>(std::move(cfg));
        g_llm_video_host->mount(svr, require_v1_auth);
    }
    svr.Post("/v1/video/start", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        const auto host = g_llm_video_host;
        if (!host) {
            res.status = 501;
            res.set_content(route_error("video streaming is not built into this binary",
                                         "server_error", "video_unavailable")
                                .dump(),
                            "application/json");
            return;
        }
        nlohmann::json body = nlohmann::json::object();
        if (!req.body.empty()) {
            body = media::json::try_parse(req.body);
            if (!body.is_object()) {
                write_video_json(res, {{"ok", false}, {"error", "invalid JSON body"}}, 400);
                return;
            }
        }
        VideoStreamCaptureUpdate update;
        std::string err;
        if (!fill_video_update(body, update, err)) {
            write_video_json(res, {{"ok", false}, {"error", err}}, 400);
            return;
        }
        const VideoStreamStartResult started = host->start(update);
        if (!started.ok) {
            write_video_json(res, {{"ok", false}, {"error", started.error}}, 400);
            return;
        }
        nlohmann::json status = host->status();
        status["accepted"] = true;
        status["already"] = started.already;
        status["switched"] = started.switched;
        write_video_json(res, status);
    });
    svr.Post("/v1/video/stop", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        const auto host = g_llm_video_host;
        if (!host) {
            res.status = 501;
            res.set_content(route_error("video streaming is not built into this binary",
                                         "server_error", "video_unavailable")
                                .dump(),
                            "application/json");
            return;
        }
        host->stop();
        nlohmann::json status = host->status();
        status["accepted"] = true;
        status["stopped"] = true;
        write_video_json(res, status);
    });
#else
    auto video_unavailable = [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        res.status = 501;
        res.set_content(route_error("video streaming is not built into this binary", "server_error",
                                     "video_unavailable")
                            .dump(),
                        "application/json");
    };
    for (const char* path : {"/v1/video/status", "/v1/video/sources", "/v1/video/snapshot.jpg",
                             "/v1/video/mjpeg", "/v1/video/signal"})
        svr.Get(path, video_unavailable);
    for (const char* path : {"/v1/video/start", "/v1/video/stop", "/v1/video/source",
                             "/v1/video/control", "/v1/video/signal", "/v1/video/transcribe",
                             "/v1/video/speak"})
        svr.Post(path, video_unavailable);
#endif
}
} // namespace node_detail
} // namespace media_cli
