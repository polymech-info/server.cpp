#include "pm/node/sessions.hpp"

#include <mutex>
#include <unordered_map>

namespace pm::node {
namespace {

struct Row {
    std::string peer;
    std::string capability;
    int revision = 0;
    std::shared_ptr<std::atomic<bool>> cancel;
};

std::mutex& mu()
{
    static std::mutex gate;
    return gate;
}

std::unordered_map<std::uint64_t, Row>& rows()
{
    static std::unordered_map<std::uint64_t, Row> table;
    return table;
}

std::uint64_t& next_id()
{
    static std::uint64_t id = 1;
    return id;
}

} // namespace

LiveSession::LiveSession(std::string peer_id, std::string capability, int revision)
    : cancel_(std::make_shared<std::atomic<bool>>(false))
{
    std::lock_guard<std::mutex> lock(mu());
    id_ = next_id()++;
    rows().emplace(id_, Row{std::move(peer_id), std::move(capability), revision, cancel_});
}

LiveSession::~LiveSession()
{
    std::lock_guard<std::mutex> lock(mu());
    rows().erase(id_);
}

bool LiveSession::cancelled() const noexcept
{
    return cancel_ && cancel_->load();
}

void sessions_cancel(std::string_view peer_id, std::string_view capability)
{
    std::lock_guard<std::mutex> lock(mu());
    for (auto& [id, row] : rows()) {
        (void)id;
        if (row.peer != peer_id)
            continue;
        if (!capability.empty() && row.capability != capability)
            continue;
        row.cancel->store(true);
    }
}

} // namespace pm::node
