#pragma once

// The phone listener's certificate. The key file sits next to the pair file
// and is reused across restarts. The pin is the SHA-256 of the SPKI, hex.

#include <filesystem>
#include <string>
#include <vector>

namespace pm::node {

struct PhoneTls;

/// Load or create the listener certificate. @p pin is 64 lowercase hex digits.
[[nodiscard]] bool phone_tls_ensure(const std::filesystem::path& pair_file, std::string& pin,
                                    std::string& err);

/// Load the certificate and remember @p port and the loopback backend. Nothing
/// is bound until `phone_tls_set_addresses`.
[[nodiscard]] PhoneTls* phone_tls_open(const std::filesystem::path& pair_file, int port, int backend,
                                       std::string& pin, std::string& err);

/// One socket per address, all on the port from `phone_tls_open`. An address
/// that is no longer listed stops accepting. Empty means no public socket.
/// The backend sees `X-Tanit-Arrived` set to the address that socket was bound on.
[[nodiscard]] bool phone_tls_set_addresses(PhoneTls* tls, const std::vector<std::string>& addresses,
                                           std::string& err);

/// The port the next bind uses. Only change it while no public socket is open.
void phone_tls_use_port(PhoneTls* tls, int port);

void phone_tls_close(PhoneTls* tls);

/// GET @p path on `https://ipv4:port`. The certificate pin is checked before
/// the bearer is written. A mismatch leaves @p http at 0 and sends nothing.
[[nodiscard]] bool phone_tls_get(const std::string& base, const std::string& path, const std::string& pin,
                                 const std::string& bearer, long& http, std::string& body, std::string& err);

/// POST @p payload as `application/json`. The pin is checked before the body
/// or the bearer is written.
[[nodiscard]] bool phone_tls_post(const std::string& base, const std::string& path, const std::string& pin,
                                  const std::string& bearer, const std::string& payload, long& http,
                                  std::string& body, std::string& err);

} // namespace pm::node
