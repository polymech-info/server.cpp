#pragma once

// One desktop dials another peer. The pair row holds the address, the
// certificate pin, and the wrapped token. The pin is checked before the
// token is sent. This is the same check a desktop already uses for a phone.
// `lan/peers.json` stays the phone folder book.

#include "core/settings_store.hpp"
#include "lan/pair_store.hpp"
#include "logging/logger.h"
#include "pm/node/peer_book.hpp"
#include "pm/node/peer_book_defaults.hpp"
#include <pm/commons/net/http_client.hpp>

#include <nlohmann/json.hpp>

#include <string>

namespace pm::vfs::peer {

namespace {

[[nodiscard]] inline std::string join_origin_path(std::string_view base, std::string_view path)
{
    std::string out(base);
    if (path.empty())
        return out;
    while (!out.empty() && out.back() == '/')
        out.pop_back();
    std::string p(path);
    if (!p.empty() && p.front() != '/')
        p.insert(p.begin(), '/');
    out += p;
    return out;
}

} // namespace

inline std::filesystem::path pair_file()
{
    return media::settings::get_config_dir() / "lan" / "devices.json";
}

inline std::string lower_hex(std::string text)
{
    for (char& c : text) {
        if (c >= 'A' && c <= 'F')
            c = static_cast<char>(c - 'A' + 'a');
    }
    return text;
}

/// Pair with the listener at @p base (`https://host:port`). @p pin is the pin
/// that was shown with the ticket. The listener's `host_id` becomes the row.
inline bool pair_with(const std::string& base, const std::string& pin, const std::string& self_id,
                      const std::string& self_name, const std::string& self_pin,
                      const std::string& secret, std::string& peer_id, long& http, std::string& err,
                      const std::string& peer_name = {})
{
    pm::node::install_desktop_peer_book_defaults();

    peer_id.clear();
    http = 0;
    const nlohmann::json body{{"secret", secret},
                              {"device_id", self_id},
                              {"device_name", self_name},
                              {"tls_fp", self_pin},
                              {"scopes", nlohmann::json::array({"files", "audio", "video"})}};
    std::string response;
    pm::commons::net::Request req;
    req.method = "POST";
    req.url = join_origin_path(base, "/v1/lan/pair");
    req.body = body.dump();
    req.spki_sha256_hex = pin;
    req.timeout_ms = 120'000;
    req.connect_timeout_ms = 30'000;
    req.headers.push_back({"Content-Type", "application/json"});
    const auto resp = pm::commons::net::request(req);
    http = resp.status;
    response = resp.body;
    err = resp.error;
    if (!resp.ok) {
        if (err.empty())
            err = "pairing request failed";
        return false;
    }
    const nlohmann::json json = nlohmann::json::parse(response, nullptr, false);
    if (http != 200 || !json.is_object()) {
        if (json.is_object() && json.contains("error") && json["error"].is_object())
            err = json["error"].value("message", std::string{"pairing refused"});
        else
            err = "pairing refused";
        return false;
    }
    if (lower_hex(json.value("fingerprint", std::string{})) != lower_hex(pin)) {
        err = "the listener pin does not match";
        return false;
    }
    peer_id = json.value("host_id", std::string{});
    const std::string token = json.value("token", std::string{});
    if (!pm::lan::peer_id_valid(peer_id)) {
        err = "the listener has no device id";
        peer_id.clear();
        return false;
    }
    std::string sealed;
    if (!pm::node::seal_dial_token(token, sealed, err))
        return false;
    const std::string label = peer_name.empty() ? std::string{"peer"} : peer_name;
    pm::lan::Peer row;
    pm::lan::PairStore store(pair_file(), 64);
    if (!store.set_dial(peer_id, label, {base}, pin, sealed, row, err))
        return false;
    logger::info(std::string("[peer] paired ") + peer_id);
    return true;
}

/// GET @p path on the stored listener. @p pin_override replaces the stored pin
/// for this call and is not written. A pin that does not match sends nothing.
inline bool read_path(const std::string& id, const std::string& path, const std::string& pin_override,
                      long& http, std::string& body, std::string& err)
{
    pm::node::install_desktop_peer_book_defaults();

    http = 0;
    body.clear();
    pm::lan::Peer row;
    pm::lan::PairStore store(pair_file(), 64);
    if (!store.find(id, row, err))
        return false;
    const std::string token = pm::node::open_dial_token(row.dial_token);
    if (token.empty()) {
        err = "this peer has no token";
        return false;
    }
    const std::string pin = pin_override.empty() ? row.tls_fp : pin_override;
    if (row.urls.empty()) {
        err = "this peer has no address";
        return false;
    }
    const std::string base = row.urls.front();
    pm::commons::net::Request req;
    req.method = "GET";
    req.url = join_origin_path(base, path);
    req.bearer = token;
    req.spki_sha256_hex = pin;
    req.timeout_ms = 20'000;
    req.connect_timeout_ms = 8'000;
    const auto resp = pm::commons::net::request(req);
    http = resp.status;
    body = resp.body;
    err = resp.error;
    const bool got = resp.ok;
    logger::info(std::string("[peer] GET ") + base + path + " http=" + std::to_string(http)
                 + (err.empty() ? std::string{} : " err=" + err));
    return got;
}

} // namespace pm::vfs::peer