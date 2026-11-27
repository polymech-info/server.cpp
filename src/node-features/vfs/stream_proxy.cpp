#include "pm/node/phone_stream_proxy.hpp"

#include "logging/logger.h"
#include "pm/node/phone_vfs_client.hpp"
#include <pm/commons/net/http_client.hpp>

#include <httplib.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <unordered_map>

namespace pm::vfs::phone {
namespace {

struct Ticket {
    std::string device;
    std::string mount;
    std::string rel;
    std::string base;
    std::string bearer;
    std::string pin;
    std::string mime;
    std::string leaf;
    std::uint64_t expected_size = 0;
};

struct ProxyState {
    std::mutex mu;
    std::unordered_map<std::string, Ticket> tickets;
    std::unique_ptr<httplib::Server> server;
    std::thread thread;
    int port = 0;
    std::atomic<bool> ready{false};
};

ProxyState& state()
{
    static ProxyState s;
    return s;
}

std::string make_ticket_id()
{
    static thread_local std::mt19937_64 rng{
        static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count())};
    std::uniform_int_distribution<std::uint64_t> dist;
    char buf[33];
    const auto a = dist(rng);
    const auto b = dist(rng);
    std::snprintf(
        buf,
        sizeof(buf),
        "%016llx%016llx",
        static_cast<unsigned long long>(a),
        static_cast<unsigned long long>(b));
    return buf;
}

bool parse_bytes_range(
    const std::string& header,
    std::uint64_t size,
    std::uint64_t& start,
    std::uint64_t& end)
{
    if (header.empty() || size == 0)
        return false;
    std::string_view text(header);
    if (text.rfind("bytes=", 0) == 0)
        text.remove_prefix(6);
    const auto dash = text.find('-');
    if (dash == std::string_view::npos)
        return false;
    try {
        if (dash == 0) {
            const auto suffix = std::stoull(std::string(text.substr(1)));
            if (suffix == 0 || suffix > size)
                return false;
            start = size - suffix;
            end = size - 1;
            return true;
        }
        start = std::stoull(std::string(text.substr(0, dash)));
        if (dash + 1 >= text.size())
            end = size - 1;
        else
            end = std::stoull(std::string(text.substr(dash + 1)));
        if (start >= size)
            return false;
        if (end >= size)
            end = size - 1;
        if (end < start)
            return false;
        return true;
    } catch (...) {
        return false;
    }
}

[[nodiscard]] bool path_char_unreserved(unsigned char c) noexcept
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
           || c == '_' || c == '.' || c == '~';
}

[[nodiscard]] std::string percent_encode_path_segment(std::string_view s)
{
    static constexpr char k_hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (path_char_unreserved(c))
            out.push_back(static_cast<char>(c));
        else {
            out.push_back('%');
            out.push_back(k_hex[(c >> 4) & 0x0F]);
            out.push_back(k_hex[c & 0x0F]);
        }
    }
    return out;
}

std::string read_path_for(const Ticket& ticket)
{
    std::string path = "/v1/vfs/read";
    path = detail::append_query_param(path, "mount", ticket.mount);
    path = detail::append_query_param(path, "path", ticket.rel);
    return path;
}

std::string curl_range_value(std::string_view range)
{
    if (range.empty())
        return {};
    if (range.rfind("bytes=", 0) == 0)
        return std::string(range);
    return std::string("bytes=") + std::string(range);
}

bool phone_get_stream(const Ticket& ticket, std::string range_value, httplib::DataSink& sink)
{
    pm::commons::net::Request req;
    req.method = "GET";
    req.url = detail::join_origin_path(ticket.base, read_path_for(ticket));
    req.bearer = ticket.bearer;
    req.spki_sha256_hex = ticket.pin;
    req.timeout_ms = 0;

    pm::commons::net::StreamOptions opts;
    opts.range = std::move(range_value);
    opts.on_body = [&sink](const char* data, std::size_t n) { return sink.write(data, n); };

    logger::info(std::string("[phone-vfs] GET-STREAM ") + req.url
                 + (opts.range.empty() ? std::string{} : " range=" + opts.range));
    const auto resp = pm::commons::net::request_stream(req, std::move(opts));
    return resp.ok;
}

bool stream_slice(
    const Ticket& ticket,
    std::uint64_t from,
    std::uint64_t to,
    httplib::DataSink& sink)
{
    const std::string range =
        "bytes=" + std::to_string(from) + "-" + std::to_string(to);
    return phone_get_stream(ticket, range, sink);
}

bool ensure_proxy(std::string& err)
{
    auto& st = state();
    if (st.ready.load(std::memory_order_acquire) && st.port > 0)
        return true;
    std::lock_guard lock(st.mu);
    if (st.ready.load(std::memory_order_relaxed) && st.port > 0)
        return true;
    if (st.server) {
        err = "Phone stream proxy is starting.";
        return false;
    }
    st.server = std::make_unique<httplib::Server>();
    auto* svr = st.server.get();

    auto resolve = [](const httplib::Request& req, Ticket& ticket) -> bool {
        const std::string id = req.matches.size() > 1 ? req.matches[1].str() : std::string{};
        std::lock_guard lock(state().mu);
        const auto it = state().tickets.find(id);
        if (it == state().tickets.end())
            return false;
        ticket = it->second;
        return true;
    };

    svr->Get(R"(/s/([^/]+)/(.*))", [resolve](const httplib::Request& req, httplib::Response& res) {
        Ticket ticket;
        if (!resolve(req, ticket)) {
            res.status = 404;
            res.set_content("unknown stream", "text/plain");
            return;
        }
        const std::string mime =
            ticket.mime.empty() ? "application/octet-stream" : ticket.mime;
        res.set_header("Accept-Ranges", "bytes");
        res.set_header("Cache-Control", "no-store");

        const std::string range = req.get_header_value("Range");
        std::uint64_t start = 0;
        std::uint64_t end =
            ticket.expected_size > 0 ? ticket.expected_size - 1 : 0;
        const bool ranged =
            ticket.expected_size > 0
            && parse_bytes_range(range, ticket.expected_size, start, end);

        if (ticket.expected_size == 0) {
            // Size unknown: one chunked full GET (or phone Range if client sent one).
            auto once = std::make_shared<bool>(false);
            res.set_chunked_content_provider(
                mime,
                [ticket, range, once](size_t, httplib::DataSink& sink) {
                    if (*once)
                        return false;
                    *once = true;
                    (void)phone_get_stream(ticket, curl_range_value(range), sink);
                    sink.done();
                    return false;
                });
            res.status = range.empty() ? 200 : 206;
            return;
        }

        if (ranged) {
            res.status = 206;
            res.set_header(
                "Content-Range",
                "bytes " + std::to_string(start) + "-" + std::to_string(end) + "/"
                    + std::to_string(ticket.expected_size));
        } else {
            res.status = 200;
            start = 0;
            end = ticket.expected_size - 1;
        }
        const std::uint64_t total = end - start + 1;
        res.set_content_provider(
            total,
            mime,
            [ticket, start](size_t offset, size_t length, httplib::DataSink& sink) {
                if (length == 0)
                    return true;
                const std::uint64_t from = start + offset;
                const std::uint64_t to = from + length - 1;
                return stream_slice(ticket, from, to, sink);
            });
    });

    // cpp-httplib answers HEAD for Get routes without a body.

    int bound = 0;
    for (int port = 17890; port < 17990; ++port) {
        if (svr->bind_to_port("127.0.0.1", port)) {
            bound = port;
            break;
        }
    }
    if (bound == 0) {
        st.server.reset();
        err = "Could not bind the phone stream proxy.";
        return false;
    }
    st.port = bound;
    st.thread = std::thread([svr]() {
        logger::info(
            std::string("[phone-vfs] stream proxy listen 127.0.0.1:")
            + std::to_string(state().port));
        svr->listen_after_bind();
    });
    st.thread.detach();
    st.ready.store(true, std::memory_order_release);
    return true;
}

} // namespace

StreamOpen open_stream(
    std::string_view device,
    std::string_view browse_path,
    std::uint64_t expected_size,
    std::string_view mime)
{
    StreamOpen out;
    std::string mount;
    std::string rel;
    if (!split(device, browse_path, mount, rel) || rel.empty()) {
        out.err = "Phone stream needs a file inside a shared folder.";
        return out;
    }
    const auto peer = detail::find_peer(device);
    if (!peer) {
        out.err = "This phone is not sharing its folders with this computer.";
        return out;
    }
    if (peer->token.empty()) {
        out.err = "This phone has not sent this computer a key yet. Open Tanit on the phone.";
        return out;
    }
    std::string base;
    if (!detail::route_for(*peer, base, out.err))
        return out;
    if (!ensure_proxy(out.err))
        return out;

    std::string leaf = rel;
    const auto slash = leaf.find_last_of('/');
    if (slash != std::string::npos)
        leaf = leaf.substr(slash + 1);
    if (leaf.empty())
        leaf = "media.bin";

    Ticket ticket;
    ticket.device = std::string(device);
    ticket.mount = std::move(mount);
    ticket.rel = std::move(rel);
    ticket.base = std::move(base);
    ticket.bearer = peer->token;
    ticket.pin = peer->tls_fp;
    ticket.mime = std::string(mime);
    ticket.leaf = leaf;
    ticket.expected_size = expected_size;

    const std::string id = make_ticket_id();
    {
        std::lock_guard lock(state().mu);
        state().tickets[id] = std::move(ticket);
    }
    out.ok = true;
    out.url = "http://127.0.0.1:" + std::to_string(state().port) + "/s/" + id + "/"
        + percent_encode_path_segment(leaf);
    logger::info(std::string("[phone-vfs] stream open ") + out.url);
    return out;
}

} // namespace pm::vfs::phone