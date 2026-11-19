#pragma once

// Shared by the desktop node translation units. Route bodies live in
// node_<feature>.cpp. This header is not a public API.

#include "pm_image_cmd_llm_agent_server.hpp"
#include "json/json_utils.hpp"
#include "pm/node/node.hpp"
#include "pm/node/lan_gate.hpp"
// httplib (winsock2) comes in here, ahead of any header that pulls windows.h.
#include "pm/server/vfs.hpp"
#include "pm/node/lan_routes.hpp"
#include "pm/node/vfs_bookmarks.hpp"
#include "lan/tanit_lan.hpp"

#include "pm_image_cli_helpers.hpp"

#include "core/cli_cancel.hpp"
#include "core/cmd_ipc.hpp"
#include "core/command_runner.hpp"
#include "core/launcher_commands.hpp"
#include "llm/chat_host_events.hpp"
#include "core/settings_runtime.hpp"
#include "llm/agent_skills.hpp"
#if defined(_WIN32)
#include "win/settings_store.hpp"
#endif
#include "llm/agent.hpp"
#include "llm/agent_event_surface.hpp"
#include "llm/agent_workflow.hpp"
#include "llm/agent_launch.hpp"
#include "llm/agent_tool_provider.hpp"
#include "llm/agent_memory.hpp"
#include "llm/agent_memory_artifacts.hpp"
#include "llm/agent_memory_recall.hpp"
#include "llm/agent_runner.hpp"
#include "llm/agent_runner_session.hpp"
#include "llm/agent_turn_options.hpp"
#include "llm/agent_each.hpp"
#include "llm/agent_decide.hpp"
#include "llm/llm_image_tool_defaults.hpp"
#include "llm/path_tool_executor.hpp"
#include "llm/tools/browser_use/browser_use_page_model.hpp"
#include "logging/logger.h"
#if defined(_WIN32)
#include "win/ui_next/ChatWebPanel_TypeaheadPresets.hpp"
#endif
#include "security/consent_surface.hpp"
#include "llm/tools/inquire/InquireTools.hpp"
#include "llm/chat_session_store.hpp"
#include "lib/pm_zitadel_oauth.hpp"
#include "core/pixlwiz_user_budget.hpp"
#include "plugins/chat/host_chat.hpp"
#include "audio/session/audio_events.hpp"
#if defined(FEATURE_VIDEO) && FEATURE_VIDEO && defined(FEATURE_VIDEO_STREAM) && FEATURE_VIDEO_STREAM
#include "video_stream_host.hpp"
#endif
#if defined(FEATURE_AUDIO_SOURCES) && FEATURE_AUDIO_SOURCES
#include "pm/audio/source_host.hpp"
#include "pm/audio/sink_host.hpp"
#endif

#if defined(_WIN32)
#include "performance/counters.hpp"
#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>
#endif

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cctype>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include "fs/path_sanitizer.hpp"
#include "string/string_utils.hpp"

namespace fs = std::filesystem;

namespace media_cli {
namespace node_detail {

class InflightGate {
public:
    struct Stats {
        int concurrency = 1;
        int inflight    = 0;
        int waiting     = 0;
        int max_waiting = 0; ///< 0 = unbounded waiters
        int peak_inflight = 0;
        int peak_waiting  = 0;
        std::uint64_t accepted = 0;
        std::uint64_t waited   = 0; // accepted turns that blocked on the gate
        std::uint64_t rejected = 0; // turned away because the waiter cap was full
    };

    /// @param max_n max concurrent turns.
    /// @param max_waiting cap on parkable HTTP workers waiting for a slot.
    ///        0 = unbounded (legacy). Prefer http_workers - concurrency - reserve
    ///        so consent / control routes keep free workers.
    explicit InflightGate(int max_n, int max_waiting = 0)
        : max_n_(max_n < 1 ? 1 : max_n)
        , max_waiting_(max_waiting < 0 ? 0 : max_waiting)
    {
    }

    Stats stats() const
    {
        std::lock_guard lock(mu_);
        Stats s;
        s.concurrency   = max_n_;
        s.inflight      = inflight_;
        s.waiting       = waiting_;
        s.max_waiting   = max_waiting_;
        s.peak_inflight = peak_inflight_;
        s.peak_waiting  = peak_waiting_;
        s.accepted      = accepted_;
        s.waited        = waited_;
        s.rejected      = rejected_;
        return s;
    }

    class Slot {
    public:
        /// Acquire a turn slot. When the concurrency limit is hit, park until a
        /// slot frees or @p wait_ms elapses. A full waiter cap or a timed-out
        /// park leaves @ref ok false (HTTP 503).
        explicit Slot(InflightGate& g, int wait_ms) : g_(&g)
        {
            const auto t0 = std::chrono::steady_clock::now();
            const int budget = wait_ms > 0 ? wait_ms : 180000;
            const auto deadline = t0 + std::chrono::milliseconds(budget);
            std::unique_lock lock(g_->mu_);
            if (g_->inflight_ >= g_->max_n_) {
                if (g_->max_waiting_ > 0 && g_->waiting_ >= g_->max_waiting_) {
                    ++g_->rejected_;
                    g_ = nullptr;
                    return;
                }
                ++g_->waiting_;
                if (g_->waiting_ > g_->peak_waiting_)
                    g_->peak_waiting_ = g_->waiting_;
                ++g_->waited_;
                const bool got = g_->cv_.wait_until(lock, deadline, [&] {
                    return g_->inflight_ < g_->max_n_;
                });
                --g_->waiting_;
                if (!got) {
                    ++g_->rejected_;
                    expired_ = true;
                    g_ = nullptr;
                    queue_wait_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                                         std::chrono::steady_clock::now() - t0)
                                         .count();
                    return;
                }
            }
            queue_wait_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - t0)
                                 .count();
            ++g_->inflight_;
            ++g_->accepted_;
            if (g_->inflight_ > g_->peak_inflight_)
                g_->peak_inflight_ = g_->inflight_;
            media::cli::push_turn_deadline(t0 + std::chrono::milliseconds(budget));
            deadline_armed_ = true;
        }
        ~Slot()
        {
            if (deadline_armed_)
                media::cli::pop_turn_deadline();
            if (!g_)
                return;
            {
                std::lock_guard lock(g_->mu_);
                --g_->inflight_;
            }
            g_->cv_.notify_one();
        }
        Slot(const Slot&)            = delete;
        Slot& operator=(const Slot&) = delete;

        bool ok() const { return g_ != nullptr; }
        explicit operator bool() const { return ok(); }
        /// The wait budget elapsed before a slot freed.
        bool expired() const { return expired_; }
        long long queue_wait_ms() const { return queue_wait_ms_; }

    private:
        InflightGate* g_             = nullptr;
        long long     queue_wait_ms_ = 0;
        bool          expired_       = false;
        bool          deadline_armed_ = false;
    };

private:
    int                     max_n_         = 1;
    int                     max_waiting_   = 0;
    int                     inflight_      = 0;
    int                     waiting_       = 0;
    int                     peak_inflight_ = 0;
    int                     peak_waiting_  = 0;
    std::uint64_t           accepted_      = 0;
    std::uint64_t           waited_        = 0;
    std::uint64_t           rejected_      = 0;
    mutable std::mutex      mu_;
    std::condition_variable cv_;
};

using media::llm::agent::cliopt::BrowserEnvGuard;
using media::llm::agent::cliopt::ParsedChatRequest;
using media::llm::agent::cliopt::StreamEmitFn;
using media::llm::agent::cliopt::TurnOutcome;
using media::llm::agent::cliopt::VictoriaTarget;
using media::llm::agent::cliopt::apply_provider_defaults;
using media::llm::agent::cliopt::clip_text;
using media::llm::agent::cliopt::completion_success_json;
using media::llm::agent::cliopt::is_video_route;
using media::llm::agent::cliopt::log_level_name;
using media::llm::agent::cliopt::looks_like_loopback_script;
using media::llm::agent::cliopt::openai_completion_id;
using media::llm::agent::cliopt::openai_created_unix;
using media::llm::agent::cliopt::openai_error;
using media::llm::agent::cliopt::parse_chat_request;
using media::llm::agent::cliopt::parse_host_tool_provider_spec;
using media::llm::agent::cliopt::resolve_request_selection;
using media::llm::agent::cliopt::sse_data_line;
using media::llm::agent::cliopt::stage_message_images;
using media::llm::agent::cliopt::rewrite_staged_paths;
using media::llm::agent::cliopt::stage_mobile_attachments;
using media::llm::agent::cliopt::trim_ascii;
using media::llm::agent::cliopt::usage_fields;
using media::llm::agent::cliopt::utc_now_iso;
using media::llm::agent::cliopt::victoria_target;

void stop_llm_video_host();
void stop_llm_audio_host();
void install_chat_event_sources();
void register_cli_host_tool_providers(const AgentServerOptions& opt);

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
void attach_chat_host_ipc(media::cmd_ipc::InstanceServer& ipc);
#endif

#if defined(_WIN32)
std::wstring wide_from_utf8(const std::string& text);
#endif

void register_host_routes(httplib::Server& svr, const AuthFn& require_v1_auth);
void register_llm_routes(httplib::Server& svr, const AgentServerOptions& opt, InflightGate& gate,
                         const AuthFn& require_v1_auth);
void register_chat_routes(httplib::Server& svr, const AuthFn& require_v1_auth);
void register_realtime_routes(httplib::Server& svr, const AgentServerOptions& opt,
                              const AuthFn& require_v1_auth);
void register_video_routes(httplib::Server& svr, const AuthFn& require_v1_auth);
void register_audio_routes(httplib::Server& svr, const AuthFn& require_v1_auth);
void register_log_routes(httplib::Server& svr, const AuthFn& require_v1_auth);

} // namespace node_detail
} // namespace media_cli
