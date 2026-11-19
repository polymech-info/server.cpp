# pm-server

Tanit node. `pm-server-lib` is the `/v1/vfs` routes and the paired-peer listener. Desktop routes, mDNS, and the LAN proxy stay in this tree and are compiled by the host. The phone compiles the portable files plus its lifecycle and transport glue.

Siblings: [commons.cpp](../commons.cpp/README.md) (paths, strings, logging), [vfs.cpp](../vfs.cpp/README.md) (the jail), [llm.cpp](../llm.cpp/README.md) (agent routes on the desktop listener). [encryption.cpp](../encryption.cpp/README.md) is not linked. Its `pm::host::Device` and `pm-encryption server` are a test host, not this process.

## Modules

The target source groups are [node-core](src/node-core/README.md),
[node-transports](src/node-transports/README.md),
[node-features](src/node-features/README.md), and
[node-e2ee](src/node-e2ee/README.md). Translation units live there. Public headers stay `pm/server` and `pm/node`.

| Module | Where | Who compiles it |
| --- | --- | --- |
| VFS routes | [vfs.cpp](src/node-features/vfs/vfs.cpp), [vfs.hpp](src/base/include/pm/server/vfs.hpp) | `pm-server-lib`, and the phone image |
| Route flags | [features.hpp](src/base/include/pm/server/features.hpp) | header only. Phone turns llm, tools, and host off |
| Node options | [options.hpp](src/base/include/pm/server/options.hpp) | header only. Listener limits, features, LAN, serve-key capabilities |
| Desktop seams | [desktop.hpp](src/tanit-node/include/pm/node/desktop.hpp) | header only. Principals, route policies, router registration, optional agent layer |
| Bearer parse | [secret.hpp](src/base/include/pm/server/secret.hpp) | header only |
| Pair file | [pair_store.cpp](src/node-core/pair/pair_store.cpp), [pair_store.hpp](src/tanit-node/include/lan/pair_store.hpp) | `pm-server-lib`, and the phone image. Grant, trust, and the token hash |
| Paired-peer listener | [listener.cpp](src/node-core/lifecycle/listener.cpp), [peer_listener.hpp](src/tanit-node/include/pm/node/peer_listener.hpp) | `pm-server-lib`, and the phone image |
| Shared folders | [vfs_bookmarks.cpp](src/node-features/vfs/vfs_bookmarks.cpp) | host and the phone image. Reads the settings store; the library does not |
| Desktop listener | [node.cpp](src/node-features/agent/node.cpp) and [node_llm](src/node-features/agent/node_llm.cpp), [node_chat](src/node-features/agent/node_chat.cpp), [node_realtime](src/node-features/agent/node_realtime.cpp), [node_audio](src/node-features/audio/node_audio.cpp), [node_video](src/node-features/video/node_video.cpp), [node_host](src/node-features/agent/node_host.cpp), [node_lan](src/node-features/agent/node_lan.cpp) | host, via `pm_llm_sources(cli)`. Includes the agent and settings |
| LAN proxy | [lan_win.cpp](src/node-transports/desktop/lan_win.cpp) / [lan_stub.cpp](src/node-transports/desktop/lan_stub.cpp), [lan_qr.cpp](src/node-transports/desktop/lan_qr.cpp) | `pm_server_add_lan` |
| mDNS | [mdns_win.cpp](src/node-transports/desktop/mdns_win.cpp) / [mdns_stub.cpp](src/node-transports/desktop/mdns_stub.cpp) | `pm_server_add_mdns` |
| Phone glue | [node.cpp](src/node-core/lifecycle/node.cpp), [vfs_listener.cpp](src/node-transports/phone/vfs_listener.cpp), [phone_vfs.hpp](src/tanit-node/include/pm/node/phone_vfs.hpp) | Android `tanit_node_phone` only |
| Host wiring | [host.cmake](cmake/host.cmake) | included by the repo root |
| Source ownership | [sources.cmake](cmake/sources.cmake) | canonical portable, transport, agent, bookmark, and phone groups while files move |
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

## Diagrams

Class, flow, and sequence diagrams, in Mermaid.

| File | Shows |
| --- | --- |
| [docs/node-today.md](docs/node-today.md) | Both listeners as they compile now: build targets, types, the two gates, pairing, and a phone folder read |
| [docs/node-refactor.md](docs/node-refactor.md) | Target folders: `node-core`, `node-transports`, `node-features`, `node-e2ee`. The router and the gate. Tanit-mesh sections 10 and 11 are the exits |
| [docs/node-impl.md](docs/node-impl.md) | The commits. One commit leaves `tanit`, `tanit-cli`, and `test:vfs-phone` green |
| [docs/encryption-seams.md](docs/encryption-seams.md) | Snapshot of a proposed link. Tanit-mesh section 7 and phase 5 supersede it: the library stays unlinked |

## Next

Design and the todo list are in [docs/tanit-mesh.md](../../docs/tanit-mesh.md), sections 10 and 11. The commits are in [docs/node-impl.md](docs/node-impl.md). First the three link fixes already due, then TLS on the phone listener, with the pin checked before the token. Then a `node serve` verb that listens without the agent, so a build with `FEATURE_COMMAND_LLM` off can receive a phone folder.

- Desktop route files still include the agent. Those routes are the agent. The pair file and the grant check now live in this package. Paths, strings, and logging stay in [commons.cpp](../commons.cpp/README.md). The settings store is read only from [vfs_bookmarks.cpp](src/node-features/vfs/vfs_bookmarks.cpp), which the host compiles.
- Treat [encryption.cpp](../encryption.cpp/README.md) as the protocol library. `pm::host::Device`, `media-host`, and `pm-encryption server` exist to exercise frames on a loopback. They are not the product host.
- New features on this node, not a second server. Audio and video are route groups beside vfs, including when the agent is off. `encryption.cpp` stays unlinked until a feature has to hide bytes from a store the peer is not serving. An in-process LLM is a local principal, not a paired device.
