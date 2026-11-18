// Feature set for the phone listener. vfs_listener.cpp mounts health and vfs
// only when this says vfs is on. It does not link the desktop node.

#include "pm/node/node.hpp"

namespace pm::node {

pm::server::ServerFeatures android_listener_features()
{
    return phone_features();
}

} // namespace pm::node
