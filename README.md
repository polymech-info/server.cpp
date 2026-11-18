# pm-server

Tanit node. `pm-server-lib` is the `/v1/vfs` routes and the paired-peer listener. Desktop routes, mDNS, and the LAN proxy stay in this tree and are compiled by the host. The phone compiles the same two portable files plus `android/`.

Siblings: [commons.cpp](../commons.cpp/README.md) (pair file, paths, logging), [vfs.cpp](../vfs.cpp/README.md) (the jail), [llm.cpp](../llm.cpp/README.md) (agent routes on the desktop listener). [encryption.cpp](../encryption.cpp/README.md) is not linked. Its `pm::host::Device` and `pm-encryption server` are a test host, not this process.

## Modules

| Module | Where | Who compiles it |
| --- | --- | --- |
| VFS routes | [vfs.cpp](src/base/src/vfs.cpp), [vfs.hpp](src/base/include/pm/server/vfs.hpp) | `pm-server-lib`, and the phone image |
| Route flags | [features.hpp](src/base/include/pm/server/features.hpp) | header only. Phone turns llm, tools, and host off |
| Bearer parse | [secret.hpp](src/base/include/pm/server/secret.hpp) | header only |
| Paired-peer listener | [listener.cpp](src/tanit-node/peer/listener.cpp), [peer_listener.hpp](src/tanit-node/include/pm/node/peer_listener.hpp) | `pm-server-lib`, and the phone image |
| Desktop listener | [node.cpp](src/tanit-node/desktop/node.cpp) and [node_llm](src/tanit-node/desktop/node_llm.cpp), [node_chat](src/tanit-node/desktop/node_chat.cpp), [node_realtime](src/tanit-node/desktop/node_realtime.cpp), [node_audio](src/tanit-node/desktop/node_audio.cpp), [node_video](src/tanit-node/desktop/node_video.cpp), [node_host](src/tanit-node/desktop/node_host.cpp), [node_lan](src/tanit-node/desktop/node_lan.cpp) | host, via `pm_llm_sources(cli)`. Includes the agent and settings |
| LAN proxy | [lan_win.cpp](src/tanit-node/desktop/lan_win.cpp) / [lan_stub.cpp](src/tanit-node/desktop/lan_stub.cpp), [lan_qr.cpp](src/tanit-node/desktop/lan_qr.cpp) | `pm_server_add_lan` |
| mDNS | [mdns_win.cpp](src/tanit-node/desktop/mdns_win.cpp) / [mdns_stub.cpp](src/tanit-node/desktop/mdns_stub.cpp) | `pm_server_add_mdns` |
| Phone glue | [android/node.cpp](src/tanit-node/android/node.cpp), [vfs_listener.cpp](src/tanit-node/android/vfs_listener.cpp), [phone_vfs.hpp](src/tanit-node/include/pm/node/phone_vfs.hpp) | Android `tanit_node_phone` only |
| Host wiring | [host.cmake](cmake/host.cmake) | included by the repo root |
| Version CLI | [cli/main.cpp](cli/main.cpp) | top-level `pm-server` only. The host does not build it |

Shared bookmarks are [vfs_bookmarks.hpp](src/tanit-node/include/pm/node/vfs_bookmarks.hpp). The listener entry for both hosts is [node.hpp](src/tanit-node/include/pm/node/node.hpp).

## Integration

```cmake
if(NOT TARGET pm-server-lib)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/packages/server.cpp
                   ${CMAKE_CURRENT_BINARY_DIR}/pm-server-lib EXCLUDE_FROM_ALL)
endif()
target_link_libraries(${HOST_TARGET} PRIVATE pm-server-lib)
```

`pm_server_add_lan` and `pm_server_add_mdns` add the platform files. The phone image compiles the list from `pm_server_phone_sources` itself, so those two `.cpp` files are not also inside `pm-server-lib` on Android.

## Next

- Refactor the cut with [commons.cpp](../commons.cpp/README.md). The pair file, LAN checks, and string helpers landed there so the phone could link them. Node policy still reaches back across that line, and the desktop listener still includes the agent and the settings store.
- Treat [encryption.cpp](../encryption.cpp/README.md) as the protocol library. `pm::host::Device`, `media-host`, and `pm-encryption server` exist to exercise frames on a loopback. They are not the product host.
- New features on this node, not a second server: encryption on the paired channel, p2p, and chat. An LLM may join that chat. Each one is a route group beside vfs, the same way audio and video already are.
