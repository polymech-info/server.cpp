#include "pm/node/vfs_backend.hpp"

#include <pm/node/phone_vfs_client.hpp>

#include <pm/vfs/store.hpp>

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace {

struct TempNodeRead final : pm::vfs::OpenedRead {
    std::filesystem::path staging;

    ~TempNodeRead()
    {
        file.close();
        std::error_code ec;
        std::filesystem::remove(staging, ec);
    }
};

[[nodiscard]] std::string basename_of(std::string_view path)
{
    if (path.empty())
        return {};
    while (!path.empty() && (path.back() == '/' || path.back() == '\\'))
        path.remove_suffix(1);
    const auto slash = path.find_last_of("/\\");
    return slash == std::string_view::npos ? std::string(path) : std::string(path.substr(slash + 1));
}

[[nodiscard]] std::string join_child_path(std::string_view browse, std::string_view name)
{
    if (browse.empty())
        return std::string(name);
    std::string out(browse);
    out.push_back('/');
    out.append(name);
    return out;
}

[[nodiscard]] pm::vfs::OpResult from_phone_op(const pm::vfs::phone::OpResult& op)
{
    pm::vfs::OpResult out;
    if (!op.ok)
        out.error = pm::vfs::Error::make("EIO", op.err.empty() ? "phone operation failed" : op.err);
    return out;
}

class NodeVfsBackend final : public pm::vfs::Backend {
public:
    [[nodiscard]] std::string_view name() const noexcept override { return "node"; }

    [[nodiscard]] bool accepts(const pm::vfs::Location& loc) const override
    {
        return loc.scheme == "vfs" && pm::node::is_device_mount(loc.authority);
    }

    [[nodiscard]] pm::vfs::Capabilities capabilities(const pm::vfs::Location&) override
    {
        pm::vfs::Capabilities caps;
        caps.list = true;
        caps.stat = true;
        caps.read = true;
        caps.write = true;
        caps.mkdir = true;
        caps.touch = true;
        caps.remove = true;
        caps.relocate = true;
        return caps;
    }

    [[nodiscard]] pm::vfs::ListResult list(const pm::vfs::Location& loc,
                                           const pm::vfs::OperationContext&) override
    {
        pm::vfs::ListResult out;
        const std::string& device = loc.authority;
        const std::string& browse_path = loc.path;

        if (browse_path.empty()) {
            const auto mounts = pm::vfs::phone::mounts(device);
            if (!mounts.ok) {
                out.error = pm::vfs::Error::make(
                    "EIO", mounts.err.empty() ? "Unable to list this phone." : mounts.err);
                return out;
            }
            // Device root is browse-only; mounts are listed, not written.
            out.can = {"list", "stat"};
            for (const auto& mount : mounts.mounts) {
                pm::vfs::Node node;
                node.name = mount.name;
                node.type = "dir";
                out.entries.push_back(std::move(node));
            }
            return out;
        }

        const auto listed = pm::vfs::phone::list(device, browse_path);
        if (!listed.ok) {
            out.error = pm::vfs::Error::make(
                "EIO", listed.err.empty() ? "Unable to list this phone folder." : listed.err);
            return out;
        }
        out.can = listed.can;
        for (const auto& entry : listed.entries) {
            pm::vfs::Node node;
            node.name = entry.name;
            node.path = join_child_path(browse_path, entry.name);
            node.type = entry.is_dir ? "dir" : "file";
            node.size = entry.size;
            node.mtime = entry.mtime_ms;
            node.mime = entry.mime;
            out.entries.push_back(std::move(node));
        }
        return out;
    }

    [[nodiscard]] pm::vfs::NodeResult stat(const pm::vfs::Location& loc,
                                           const pm::vfs::OperationContext&) override
    {
        pm::vfs::NodeResult out;
        if (loc.path.empty()) {
            out.node.type = "dir";
            return out;
        }

        const auto st = pm::vfs::phone::stat(loc.authority, loc.path);
        if (!st.ok) {
            out.error = pm::vfs::Error::make(
                "EIO", st.err.empty() ? "Unable to stat this phone path." : st.err);
            return out;
        }
        if (!st.exists)
            return out;

        out.node.type = st.is_dir ? "dir" : "file";
        out.node.name = loc.path;
        out.node.path = loc.path;
        out.node.size = st.size;
        return out;
    }

    [[nodiscard]] pm::vfs::OpenReadResult open_read(const pm::vfs::Location& loc,
                                                    const pm::vfs::OperationContext& ctx) override
    {
        pm::vfs::OpenReadResult out;
        if (loc.path.empty()) {
            out.error = pm::vfs::Error::make("EISDIR", "cannot open a phone folder root for read");
            return out;
        }

        const auto st = pm::vfs::phone::stat(loc.authority, loc.path);
        if (!st.ok) {
            out.error = pm::vfs::Error::make(
                "EIO", st.err.empty() ? "Unable to stat this phone path." : st.err);
            return out;
        }
        if (!st.exists) {
            out.error = pm::vfs::Error::make("ENOENT", "phone path does not exist");
            return out;
        }
        if (st.is_dir) {
            out.error = pm::vfs::Error::make("EISDIR", "cannot open a phone directory for read");
            return out;
        }

        const auto staging = pm::vfs::make_cache_temp(std::filesystem::temp_directory_path());
        pm::vfs::phone::ReadOptions read_opts;
        read_opts.expected_size = st.size;
        if (ctx.cancelled)
            read_opts.cancel = ctx.cancelled;
        const auto dl = pm::vfs::phone::read_to_file(loc.authority, loc.path, staging, std::move(read_opts));
        if (!dl.ok) {
            std::error_code ec;
            std::filesystem::remove(staging, ec);
            out.error =
                pm::vfs::Error::make("EIO", dl.err.empty() ? "Unable to read this phone file." : dl.err);
            return out;
        }

        pm::vfs::Error nerr;
        const auto parent = staging.parent_path();
        const auto leaf = staging.filename().string();
        auto native = pm::vfs::NativeFile::open_read(parent, leaf, nerr);
        if (!native) {
            std::error_code ec;
            std::filesystem::remove(staging, ec);
            out.error = nerr;
            return out;
        }

        auto opened = std::make_shared<TempNodeRead>();
        opened->staging = staging;
        opened->file = std::move(native);
        opened->size = st.size != 0 ? st.size : dl.bytes;
        opened->node.type = "file";
        opened->node.name = basename_of(loc.path);
        opened->node.path = loc.path;
        opened->node.size = opened->size;
        out.file = std::move(opened);
        return out;
    }

    [[nodiscard]] pm::vfs::OpResult open_write(const pm::vfs::Location& loc,
                                               const pm::vfs::WriteOptions&,
                                               std::string_view bytes,
                                               const pm::vfs::OperationContext&) override
    {
        if (bytes.size() > pm::vfs::phone::k_max_write) {
            pm::vfs::OpResult out;
            out.error = pm::vfs::Error::make("EFBIG", "Phone write is larger than 8 MiB.");
            return out;
        }
        return from_phone_op(
            pm::vfs::phone::write_bytes(loc.authority, loc.path, bytes.data(), bytes.size()));
    }

    [[nodiscard]] pm::vfs::OpResult mkdir(const pm::vfs::Location& loc,
                                          const pm::vfs::OperationContext&) override
    {
        return from_phone_op(pm::vfs::phone::mkdir(loc.authority, loc.path));
    }

    [[nodiscard]] pm::vfs::OpResult touch(const pm::vfs::Location& loc,
                                          const pm::vfs::OperationContext&) override
    {
        return from_phone_op(pm::vfs::phone::touch(loc.authority, loc.path));
    }

    [[nodiscard]] pm::vfs::OpResult remove(const pm::vfs::Location& loc, bool recursive,
                                           const pm::vfs::OperationContext&) override
    {
        return from_phone_op(pm::vfs::phone::remove(loc.authority, loc.path, recursive));
    }

    [[nodiscard]] pm::vfs::OpResult relocate(const pm::vfs::Location& from,
                                             const pm::vfs::Location& to,
                                             const pm::vfs::OperationContext&) override
    {
        if (from.authority != to.authority) {
            pm::vfs::OpResult out;
            out.error = pm::vfs::Error::make("EXDEV", "cross-device relocate not supported");
            return out;
        }
        return from_phone_op(pm::vfs::phone::move(from.authority, from.path, to.path));
    }
};

} // namespace

void pm::node::register_vfs_backend(pm::vfs::Runtime& runtime)
{
    static std::mutex mu;
    std::lock_guard lock(mu);
    for (const auto& backend : runtime.backends().all()) {
        if (backend && backend->name() == "node")
            return;
    }
    runtime.backends().add(std::make_shared<NodeVfsBackend>());
}