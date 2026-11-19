#pragma once

// Desktop LAN hop and bearer parsing. No agent include: a phone on the TLS
// proxy is loopback at the TCP layer and is not a local caller.

#include "lan/tanit_lan.hpp"

#include <httplib.h>

#include <string>
#include <string_view>
#include <vector>

namespace media_cli {
namespace node_detail {

/// Set while the desktop LAN proxy is running.
extern lan::Service* g_lan;

bool is_loopback_addr(std::string_view addr);
bool lan_hop_present(const httplib::Request& req);
bool lan_hop_ok(const httplib::Request& req);
bool machine_local_request(const httplib::Request& req);
std::vector<std::string> request_secrets(const httplib::Request& req);

} // namespace node_detail
} // namespace media_cli
