// Phone log ingest. This stays with the agent: it forwards to VictoriaLogs
// through the agent helper. A plain node does not mount it.
#include "node_internal.hpp"

namespace media_cli {
namespace node_detail {

namespace {

bool forward_victoria_ndjson(const std::string& ndjson)
{
    const VictoriaTarget target = victoria_target();
    if (!target.enabled || ndjson.empty())
        return false;
    httplib::Client cli(target.host, target.port);
    cli.set_connection_timeout(0, 400000);
    cli.set_read_timeout(0, 800000);
    cli.set_write_timeout(0, 800000);
    const auto res = cli.Post(
        "/insert/jsonline?_stream_fields=source,device,build,session_id"
        "&_msg_field=message&_time_field=_time",
        ndjson, "application/stream+json");
    return res && res->status >= 200 && res->status < 300;
}

} // namespace

void register_log_routes(httplib::Server& svr, const AuthFn& require_v1_auth)
{
    svr.Post("/v1/logs", [require_v1_auth](const httplib::Request& req, httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        if (req.body.size() > 512 * 1024) {
            res.status = 413;
            res.set_content(openai_error("log batch is too large").dump(), "application/json");
            return;
        }
        const nlohmann::json body = media::json::try_parse(req.body.empty() ? "{}" : req.body);
        if (!body.is_object() || !body.contains("lines") || !body["lines"].is_array()) {
            res.status = 400;
            res.set_content(openai_error("body must be {\"lines\":[...]}").dump(), "application/json");
            return;
        }
        std::string device = "lan";
        std::string device_name;
        if (g_lan) {
            for (const auto& secret : request_secrets(req)) {
                lan::DeviceAuth dev;
                if (!g_lan->authorize(secret, dev))
                    continue;
                if (!dev.id.empty())
                    device = clip_text(dev.id, 64);
                device_name = clip_text(dev.name, 80);
                break;
            }
        }
        auto text_field = [](const nlohmann::json& obj, const char* key) -> std::string {
            if (!obj.contains(key) || !obj[key].is_string())
                return {};
            return obj[key].get<std::string>();
        };
        std::string session = text_field(body, "session_id");
        if (session.empty())
            session = "lan";
        session = clip_text(std::move(session), 80);
        const std::string model = clip_text(text_field(body, "device_model"), 80);
        const std::string now = utc_now_iso();
        std::string ndjson;
        int accepted = 0;
        for (const auto& line : body["lines"]) {
            if (accepted >= 200)
                break;
            if (!line.is_object())
                continue;
            std::string message = text_field(line, "message");
            if (message.empty())
                continue;
            message = clip_text(std::move(message), 8192);
            std::string when = text_field(line, "_time");
            if (when.empty())
                when = text_field(line, "time");
            if (when.size() < 19 || when.size() > 40 || when.find('T') == std::string::npos)
                when = now;
            std::string level = text_field(line, "level");
            if (level.empty())
                level = "info";
            std::string component = text_field(line, "component");
            if (component.empty())
                component = "logcat";
            nlohmann::json event{
                {"_time", when},
                {"source", "tanit-android"},
                {"device", device},
                {"device_kind", "phone"},
                {"device_model", model},
                {"device_name", device_name},
                {"build", "android"},
                {"session_id", session},
                {"level", log_level_name(std::move(level))},
                {"component", clip_text(std::move(component), 64)},
                {"message", message},
                {"via", "pair"},
            };
            ndjson += event.dump();
            ndjson.push_back('\n');
            ++accepted;
        }
        const bool stored = accepted > 0 && forward_victoria_ndjson(ndjson);
        if (accepted > 0 && !stored) {
            res.status = 503;
            res.set_content(nlohmann::json{{"ok", false},
                                           {"accepted", accepted},
                                           {"stored", false},
                                           {"error", "log store unavailable"}}
                                .dump(),
                            "application/json");
            return;
        }
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}, {"accepted", accepted}, {"stored", stored}}.dump(),
                        "application/json");
    });
}

} // namespace node_detail
} // namespace media_cli
