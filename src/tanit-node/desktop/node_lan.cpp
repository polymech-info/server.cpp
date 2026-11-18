// Desktop node: LAN pairing and phone log ingest.
#include "node_internal.hpp"

#include "pm/server/secret.hpp"
#include "vfs/phone_peers.hpp"

#include <filesystem>
#include <fstream>

namespace media_cli {
namespace node_detail {

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

void register_lan_routes(httplib::Server& svr, const AuthFn& require_v1_auth)
{
    auto lan_off = [](httplib::Response& res) {
        res.status = 404;
        res.set_content(openai_error("LAN discovery is off; restart with --lan").dump(),
                        "application/json");
    };

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

    svr.Get("/v1/lan/info", [](const httplib::Request&, httplib::Response& res) {
        if (!g_lan) {
            res.status = 200;
            res.set_content(nlohmann::json{{"ok", true}, {"enabled", false}}.dump(),
                            "application/json");
            return;
        }
        const lan::PublicInfo info = g_lan->info();
        res.status = 200;
        res.set_content(nlohmann::json{
                            {"ok", true},
                            {"enabled", true},
                            {"protocol", lan::k_protocol_version},
                            {"name", info.name},
                            {"fingerprint", info.fingerprint},
                            {"tls_port", info.tls_port},
                            {"pairing", info.pairing_open},
                            {"mdns", info.mdns},
                            {"addresses", info.addresses},
                        }
                            .dump(),
                        "application/json");
    });

    svr.Post("/v1/lan/pair/begin", [require_v1_auth, lan_off](const httplib::Request& req,
                                                             httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        if (!g_lan) {
            lan_off(res);
            return;
        }
        nlohmann::json body = nlohmann::json::object();
        if (!req.body.empty()) {
            body = media::json::try_parse(req.body);
            if (!body.is_object()) {
                res.status = 400;
                res.set_content(openai_error("invalid JSON body").dump(), "application/json");
                return;
            }
        }
        std::vector<std::string> scopes;
        std::string scope_err;
        std::string csv;
        if (body.contains("scopes")) {
            if (!body["scopes"].is_array() || body["scopes"].empty()) {
                res.status = 400;
                res.set_content(openai_error("scopes must list chat, files, tools, video, or audio").dump(),
                                "application/json");
                return;
            }
            for (const auto& s : body["scopes"]) {
                if (s.is_string()) {
                    if (!csv.empty())
                        csv += ",";
                    csv += s.get<std::string>();
                }
            }
        }
        if (!lan::parse_scopes(csv, scopes, scope_err)) {
            res.status = 400;
            res.set_content(openai_error(scope_err).dump(), "application/json");
            return;
        }
        int ttl = body.value("ttl_sec", 300);
        lan::PairingTicket ticket;
        std::string err;
        if (!g_lan->open_pairing(scopes, ttl, ticket, err)) {
            res.status = 500;
            res.set_content(openai_error(err.empty() ? "could not open pairing" : err).dump(),
                            "application/json");
            return;
        }
        ticket.image_path = g_lan->reveal_qr(ticket);
        res.status = 200;
        res.set_content(nlohmann::json{
                            {"ok", true},
                            {"uri", ticket.uri},
                            {"secret", ticket.secret},
                            {"expires_at", ticket.expires_at},
                            {"host", ticket.host},
                            {"port", ticket.port},
                            {"fingerprint", ticket.fingerprint},
                            {"scopes", ticket.scopes},
                            {"qr", ticket.qr_ascii},
                            {"image", ticket.image_path},
                            {"qr_error", ticket.qr_error},
                        }
                            .dump(),
                        "application/json");
    });

    svr.Post("/v1/lan/pair", [lan_off](const httplib::Request& req, httplib::Response& res) {
        if (lan_hop_present(req) && !lan_hop_ok(req)) {
            res.status = 400;
            res.set_content(openai_error("invalid LAN hop").dump(), "application/json");
            return;
        }
        const bool via_tls = lan_hop_ok(req);
        if (!via_tls && !machine_local_request(req)) {
            res.status = 403;
            res.set_content(
                openai_error("send the pairing secret over TLS after checking the fingerprint")
                    .dump(),
                "application/json");
            return;
        }
        if (!g_lan) {
            lan_off(res);
            return;
        }
        const nlohmann::json body = media::json::try_parse(req.body.empty() ? "{}" : req.body);
        if (!body.is_object()) {
            res.status = 400;
            res.set_content(openai_error("invalid JSON body").dump(), "application/json");
            return;
        }
        std::vector<std::string> scopes;
        if (body.contains("scopes") && body["scopes"].is_array()) {
            for (const auto& s : body["scopes"]) {
                if (!s.is_string())
                    continue;
                std::string name = s.get<std::string>();
                name = media::strutil::lower_ascii(std::move(name));
                scopes.push_back(std::move(name));
            }
        }
        lan::PairGrant grant;
        std::string err;
        const lan::PairError st = g_lan->complete_pairing(
            body.value("secret", std::string{}), body.value("device_id", std::string{}),
            body.value("device_name", std::string{}), scopes, grant, err);
        if (st != lan::PairError::Ok) {
            res.status = st == lan::PairError::BadSecret ? 401
                         : st == lan::PairError::Expired ? 410
                         : st == lan::PairError::Locked  ? 429
                         : st == lan::PairError::NoSession ? 404
                                                           : 403;
            if (st == lan::PairError::Locked)
                res.set_header("Retry-After", "30");
            res.set_content(openai_error(err.empty() ? "pairing refused" : err).dump(),
                            "application/json");
            return;
        }
        res.status = 200;
        res.set_content(nlohmann::json{
                            {"ok", true},
                            {"token", grant.token},
                            {"device_id", grant.device_id},
                            {"fingerprint", grant.fingerprint},
                            {"scopes", grant.scopes},
                            {"protocol", lan::k_protocol_version},
                        }
                            .dump(),
                        "application/json");
    });

    svr.Get("/v1/lan/devices", [require_v1_auth, lan_off](const httplib::Request& req,
                                                         httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        if (!g_lan) {
            lan_off(res);
            return;
        }
        nlohmann::json rows = nlohmann::json::array();
        for (const auto& d : g_lan->devices()) {
            rows.push_back({
                {"id", d.id},
                {"name", d.name},
                {"scopes", d.scopes},
                {"created", d.created},
                {"last_seen", d.last_seen},
                {"revoked", d.revoked},
            });
        }
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}, {"devices", std::move(rows)}}.dump(),
                        "application/json");
    });

    svr.Post("/v1/lan/devices/revoke", [require_v1_auth, lan_off](const httplib::Request& req,
                                                                  httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        if (!g_lan) {
            lan_off(res);
            return;
        }
        const nlohmann::json body = media::json::try_parse(req.body.empty() ? "{}" : req.body);
        if (!body.is_object()) {
            res.status = 400;
            res.set_content(openai_error("invalid JSON body").dump(), "application/json");
            return;
        }
        std::string err;
        if (!g_lan->revoke(body.value("id", std::string{}), err)) {
            res.status = 404;
            res.set_content(openai_error(err.empty() ? "device not found" : err).dump(),
                            "application/json");
            return;
        }
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    });

    // A paired phone announces its folder listener: its name, the addresses on
    // the networks it granted this computer, and (once) the token it issued
    // for this computer. The row lands in `lan/peers.json`. The serve key and
    // the caller's own bearer are never stored as the phone's token.
    //
    // The reply says whether this computer holds a token for that phone. On
    // `missing` the phone issues a new one and announces again.
    svr.Post("/v1/lan/phone-vfs", [require_v1_auth, lan_off](const httplib::Request& req,
                                                            httplib::Response& res) {
        if (!require_v1_auth(req, res))
            return;
        if (!g_lan) {
            lan_off(res);
            return;
        }
        auto refuse = [&res](int status, const std::string& text) {
            res.status = status;
            res.set_content(openai_error(text).dump(), "application/json");
        };
        if (req.body.size() > 16 * 1024) {
            refuse(413, "phone announce is too large");
            return;
        }
        const nlohmann::json body = media::json::try_parse(req.body.empty() ? "{}" : req.body);
        if (!body.is_object()) {
            refuse(400, "invalid JSON body");
            return;
        }
        const std::string authority = body.value("authority", std::string{});
        if (!pm::vfs::phone::is_device_mount(authority)) {
            refuse(400, "the phone name is not valid");
            return;
        }
        std::vector<std::string> urls;
        if (body.contains("urls") && body["urls"].is_array()) {
            for (const auto& url : body["urls"]) {
                if (!url.is_string() || urls.size() >= pm::vfs::phone::k_max_urls) {
                    refuse(400, "a phone address is not usable");
                    return;
                }
                urls.push_back(url.get<std::string>());
            }
        }
        const std::string token = body.contains("token") && body["token"].is_string()
            ? body["token"].get<std::string>()
            : std::string{};
        const std::string name = body.contains("name") && body["name"].is_string()
            ? body["name"].get<std::string>()
            : std::string{};

        // Who is announcing. A paired device is known by its desktop pair id.
        // A caller that used the serve key itself is the owner of this computer.
        // @todo: server key as optional
        std::string owner = "serve-key";
        for (const auto& secret : request_secrets(req)) {
            lan::DeviceAuth dev;
            if (g_lan->authorize(secret, dev) && !dev.id.empty()) {
                owner = clip_text(dev.id, 64);
                break;
            }
        }
        // One paired device cannot take over the row of another phone. The row
        // is free again when the device that announced it is no longer paired.
        if (const auto known = pm::vfs::phone::find_peer(authority);
            known && !known->pair.empty() && known->pair != owner && owner != "serve-key") {
            bool still_paired = known->pair == "serve-key";
            for (const auto& d : g_lan->devices()) {
                if (d.id == known->pair && !d.revoked)
                    still_paired = true;
            }
            if (still_paired) {
                logger::warn(std::string("[phone-vfs] announce refused ") + authority + " from=" + owner);
                refuse(409, "this phone is already stored for another paired device");
                return;
            }
        }
        bool holds_token = false;
        std::string err;
        if (!pm::vfs::phone::store_peer(authority, name, urls, token, owner, holds_token, err)) {
            const bool bad_input = err.find("not valid") != std::string::npos
                                   || err.find("not usable") != std::string::npos;
            refuse(bad_input ? 400 : 500, err.empty() ? "could not store the phone" : err);
            return;
        }
        // Builds before the dial book kept one phone and the caller's bearer in
        // this file, in clear. Nothing reads it now.
        std::error_code stale_ec;
        std::filesystem::remove(media::settings::get_config_dir() / "lan" / "phone-vfs.json", stale_ec);
        logger::info(std::string("[phone-vfs] stored ") + authority + " urls=" + std::to_string(urls.size())
                     + " token=" + (holds_token ? "held" : "missing") + " from=" + owner);
        res.status = 200;
        res.set_content(nlohmann::json{{"ok", true},
                                       {"authority", authority},
                                       {"token", holds_token ? "held" : "missing"}}
                            .dump(),
                        "application/json");
    });
}
} // namespace node_detail
} // namespace media_cli
