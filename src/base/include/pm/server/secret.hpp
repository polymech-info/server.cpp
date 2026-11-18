#pragma once

// Bearer parse and compare shared by the desktop LAN routes and the phone
// vfs listener. Not a second auth policy.

#include <cctype>
#include <string>
#include <string_view>

namespace pm::server {

[[nodiscard]] inline bool constant_time_equal(std::string_view a, std::string_view b) noexcept
{
    unsigned diff = static_cast<unsigned>(a.size() ^ b.size());
    const std::size_t n = a.size() < b.size() ? a.size() : b.size();
    for (std::size_t i = 0; i < n; ++i) {
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
}

/// Value after `Bearer `, or empty. The prefix match is case-insensitive.
[[nodiscard]] inline std::string bearer_token(std::string_view authorization)
{
    constexpr std::string_view prefix = "bearer ";
    if (authorization.size() <= prefix.size())
        return {};
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        const auto c = static_cast<unsigned char>(authorization[i]);
        if (std::tolower(c) != static_cast<unsigned char>(prefix[i]))
            return {};
    }
    return std::string(authorization.substr(prefix.size()));
}

/// Authorization Bearer, then `x-api-key`, then `api-key`.
template <typename Request>
[[nodiscard]] inline std::string request_bearer(const Request& req)
{
    const std::string token = bearer_token(req.get_header_value("Authorization"));
    if (!token.empty())
        return token;
    const std::string key = req.get_header_value("x-api-key");
    return key.empty() ? req.get_header_value("api-key") : key;
}

} // namespace pm::server
