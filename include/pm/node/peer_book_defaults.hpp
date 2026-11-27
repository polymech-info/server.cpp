#pragma once

// Desktop / Tanit host wiring for @ref pm::node::PeerBook hooks (config dir +
// platform secret wrap). Call once before dial-book use when no custom hooks
// are installed.

#include "pm/node/peer_book.hpp"

#include "commands/batch_queue.hpp"
#include "core/settings_store.hpp"
#include "storage/secure_storage.hpp"
#include "string/string_utils.hpp"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace pm::node {

inline void install_desktop_peer_book_defaults()
{
    static std::once_flag once;
    std::call_once(once, [] {
        PeerBookHooks hooks;
        hooks.config_dir = [] { return media::settings::get_config_dir(); };
        hooks.seal_token = [](const std::string& token, std::string& stored, std::string& err) -> bool {
            const std::vector<std::uint8_t> plain(token.begin(), token.end());
            std::vector<std::uint8_t> wrapped;
            if (!pm::storage::wrap_local_secret(plain, wrapped, err))
                return false;
            stored = "w1:" + media::strutil::to_hex(wrapped.data(), wrapped.size());
            return true;
        };
        hooks.open_token = [](const std::string& stored) -> std::string {
            if (stored.rfind("w1:", 0) != 0)
                return {};
            const std::vector<std::uint8_t> wrapped =
                media::strutil::from_hex(std::string_view(stored).substr(3));
            if (wrapped.empty())
                return {};
            std::vector<std::uint8_t> plain;
            std::string err;
            if (!pm::storage::unwrap_local_secret(wrapped, plain, err))
                return {};
            return std::string(plain.begin(), plain.end());
        };
        hooks.clip_name = [](std::string_view text, std::size_t max) {
            return media::strutil::clip_text(text, max);
        };
        hooks.utc_now = [] { return media::utc_now_iso8601(); };
        set_peer_book_hooks(std::move(hooks));
    });
}

} // namespace pm::node