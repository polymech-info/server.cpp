#pragma once

// Live calls accepted under one grant revision. A later revoke or a narrower
// grant cancels the matching ones. The caller drops the object when the call ends.

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace pm::node {

class LiveSession {
public:
    LiveSession(std::string peer_id, std::string capability, int revision);
    ~LiveSession();

    LiveSession(const LiveSession&) = delete;
    LiveSession& operator=(const LiveSession&) = delete;

    [[nodiscard]] bool cancelled() const noexcept;

private:
    std::uint64_t id_ = 0;
    std::shared_ptr<std::atomic<bool>> cancel_;
};

/// `capability` empty cancels every live call for the peer. Otherwise only that
/// capability (`files`, `audio`, `video`, `chat`, `tools`).
void sessions_cancel(std::string_view peer_id, std::string_view capability);

} // namespace pm::node
