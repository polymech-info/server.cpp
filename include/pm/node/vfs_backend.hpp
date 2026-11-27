#pragma once
#include "pm/vfs/runtime.hpp"
namespace pm::node {
/// Register the paired-node (phone) VFS backend on @p runtime (idempotent).
/// Implementation lives in the desktop host (Tanit) for now — dial HTTP still
/// uses the Tanit phone client.
void register_vfs_backend(pm::vfs::Runtime& runtime);
}