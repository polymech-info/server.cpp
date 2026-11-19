#pragma once

// Audio and video route registration. The translation units do not include
// the agent header. Capture types stay in pm/audio and video_stream_host.

#include <httplib.h>

#include <functional>
#include <string>

namespace media_cli {
namespace node_detail {

using MediaAuthFn = std::function<bool(const httplib::Request&, httplib::Response&)>;

void stop_llm_video_host();
void stop_llm_audio_host();
void register_video_routes(httplib::Server& svr, const MediaAuthFn& require_v1_auth);
void register_audio_routes(httplib::Server& svr, const MediaAuthFn& require_v1_auth);

} // namespace node_detail
} // namespace media_cli
