#include "lan/tanit_mdns.hpp"

namespace media_cli::mdns {

struct Publisher::Impl {};

Publisher::Publisher() : impl_(new Impl) {}
Publisher::~Publisher()
{
    delete impl_;
    impl_ = nullptr;
}

bool Publisher::start(const Publication&, std::string& err)
{
    err = "mDNS advertising is implemented on Windows only";
    return false;
}

void Publisher::stop() {}

bool bind_is_loopback(const std::string& host)
{
    return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]";
}

bool browse(const std::string&, int, std::vector<Sight>& out, std::string& err)
{
    out.clear();
    err = "mDNS browsing is implemented on Windows only";
    return false;
}

} // namespace media_cli::mdns
