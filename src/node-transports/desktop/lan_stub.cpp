#include "lan/tanit_lan.hpp"

namespace media_cli::lan {

namespace {
const char* k_unsupported = "LAN discovery and pairing are implemented on Windows only";
} // namespace

struct LanServiceImpl {};

Service::Service() : impl_(new LanServiceImpl) {}
Service::~Service() { delete impl_; }

bool Service::prepare(const std::string&, std::string& err)
{
    err = k_unsupported;
    return false;
}
bool Service::listen(const std::string&, int, int, std::string& err)
{
    err = k_unsupported;
    return false;
}
void Service::stop() {}

PublicInfo Service::info() const { return {}; }
bool Service::hop_matches(const std::string&) const { return false; }
bool Service::proxy_peer(const std::string&) const { return false; }

bool Service::open_pairing(const std::vector<std::string>&, int, PairingTicket&, std::string& err)
{
    err = k_unsupported;
    return false;
}
std::string Service::reveal_qr(const PairingTicket&, bool) { return {}; }

PairError Service::complete_pairing(const std::string&, const std::string&, const std::string&,
                                    const std::vector<std::string>&, const std::string&, PairGrant&,
                                    std::string& err)
{
    err = k_unsupported;
    return PairError::Rejected;
}

bool Service::authorize(const std::string&, DeviceAuth&) { return false; }
std::vector<DeviceInfo> Service::devices() { return {}; }
bool Service::revoke(const std::string&, std::string& err)
{
    err = k_unsupported;
    return false;
}

bool list_paired_devices(std::string&, std::string& err)
{
    err = k_unsupported;
    return false;
}
bool list_paired_device_infos(std::vector<DeviceInfo>&, std::string& err)
{
    err = k_unsupported;
    return false;
}
bool revoke_paired_device(const std::string&, std::string& err)
{
    err = k_unsupported;
    return false;
}

} // namespace media_cli::lan
