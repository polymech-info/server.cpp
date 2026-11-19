#include "pm/node/lan_gate.hpp"

#include "pm/server/options.hpp"

#include "string/string_utils.hpp"

#include <cctype>

namespace media_cli {
namespace node_detail {

lan::Service* g_lan = nullptr;

bool is_loopback_addr(std::string_view addr)
{
    return pm::server::loopback_host(addr);
}

bool lan_hop_present(const httplib::Request& req)
{
    return req.has_header(lan::k_hop_header);
}

bool lan_hop_ok(const httplib::Request& req)
{
    if (!g_lan || !lan_hop_present(req))
        return false;
    return g_lan->hop_matches(req.get_header_value(lan::k_hop_header));
}

bool machine_local_request(const httplib::Request& req)
{
    if (lan_hop_present(req))
        return false;
    return is_loopback_addr(req.remote_addr);
}

std::vector<std::string> request_secrets(const httplib::Request& req)
{
    std::vector<std::string> out;
    auto add = [&](std::string s) {
        s = media::strutil::trim(std::move(s));
        if (!s.empty())
            out.push_back(std::move(s));
    };
    const std::string auth = media::strutil::trim(req.get_header_value("Authorization"));
    if (auth.size() >= 7) {
        bool bearer = true;
        const char pfx[] = "bearer ";
        for (int i = 0; i < 7; ++i) {
            const auto c = static_cast<unsigned char>(auth[static_cast<size_t>(i)]);
            if (std::tolower(c) != static_cast<unsigned char>(pfx[i])) {
                bearer = false;
                break;
            }
        }
        if (bearer)
            add(auth.substr(7));
    }
    for (const char* h : {"x-api-key", "api-key"})
        add(req.get_header_value(h));
    return out;
}

} // namespace node_detail
} // namespace media_cli
