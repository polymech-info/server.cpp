# Node implementation plan

**Date:** 2026-11-19  
**Status:** the commits. None of this is code.  
**Exits:** [tanit-mesh.md](../../../docs/tanit-mesh.md) section 11.  
**Folders, types, and the gate:** [node-refactor.md](node-refactor.md).  
**What compiles today:** [node-today.md](node-today.md).

A commit ends with every target that owns a touched source linking: `tanit`, `tanit-cli`, `pm-llm`, the viewer, standalone `pm-server`, and `tanit_node_phone` when their feature sets include that source. `npm run test:vfs-phone` passes. The next commit starts from that. A commit that moves a file updates every source list in the same commit. `pm-server-lib` and `node serve` link no `pm-encryption-lib`.

## 0. Already due

The pair store and the bookmark file moved after the last link. No behavior change.

| Commit | Does | Check |
|---|---|---|
| 0.1 | Relink `tanit` and `tanit-cli` | Both link |
| 0.2 | Build `tanit_node_phone` with the NDK. Its list is `vfs.cpp`, `listener.cpp`, `pair_store.cpp`, `sessions.cpp`, `node.cpp`, `vfs_listener.cpp`. Bookmark rows are passed in | The phone image builds |
| 0.3 | `CMakePresets.json` for the standalone `pm-server` CLI | `npm run test:pm-server` |
| 0.4 | Harden `PairStore` before it becomes the desktop owner. Read `audio` and `video` as well as writing them. Replace an existing file atomically on Windows. Make the row limit a host policy: 16 on the phone, 64 on the desktop | Grant round-trip, second write to the same file, interrupted-write fixture, 16-row phone and 64-row desktop tests |

## 1. Secure transport

Exit: vfs bytes move only after each side has checked the other's certificate pin, and a `/health` body that names the right authority receives no token.

The phone listener terminates TLS in `listener_tls.cpp`. httplib binds 127.0.0.1. mbedtls serves the public port with an app-private P-256 certificate beside the pair file. `GET /health` returns `role` and does not return `authority`. Announce URLs are `https://` and the body carries `tls_fp`. The desktop dialer pins that SPKI and does not follow redirects. A missing or wrong pin sends no token. The desktop's own listener is still Schannel in `lan_win.cpp`, key container `TanitLanIdentity.rsa.v1`. The QR exchange does not yet carry both pins. The public listener is one socket per granted address, and a hop header is accepted only from the proxy on loopback.

### TLS decision gate

Do not choose OpenSSL merely because cpp-httplib exposes `SSLServer`. The Android image links neither OpenSSL nor TLS-enabled httplib today. An Android Keystore private key is not a PEM key cpp-httplib can consume. Commit 1.1 proves one of these complete paths before the product route changes:

- cpp-httplib plus OpenSSL, with an app-private exportable TLS key. The threat model and the APK ABI packaging must accept that the key is not a Keystore handle.
- Java or OkHttp TLS termination in front of the C++ listener, with a Keystore key.
- A documented Keystore/OpenSSL provider integration.

The proof includes certificate creation, restart persistence, app upgrade, reinstall, and all Android ABIs the image ships. This TLS identity is not the optional long-term device signing key. `peer_fp` stays empty.

The Windows phone client is not the proxy. It uses the existing curl HTTP helper, whose Windows backend is Schannel. Add a dedicated HTTPS-only client interface that supplies an SPKI pin, disables redirects, and refuses cleartext downgrade. The bearer header is constructed only after the TLS connection and pin check succeed.

### Pin bootstrap

The phone TLS identity exists before pairing and independently of whether a folder is shared. The existing authenticated QR/TLS pairing transaction carries both listener SPKI pins:

1. The QR ticket supplies the desktop listener pin the phone must check.
2. The phone pairing request supplies the phone listener pin.
3. Each side writes the peer pin to its authoritative pairing row before pairing succeeds. The phone uses `PairStore`; the desktop extends its legacy row with `tls_fp` until phase 3 migrates it.
4. The desktop announce row in `lan/peers.json` also stores the phone `tls_fp`. Announce may repeat it, but may not change it. A pin change needs a new pairing transaction.
5. No first connection uses trust on first use. A missing pin is a refusal.

The phone announce contains only `https://` URLs after cutover. `/health` is liveness only and contains no authority. The desktop routes to the authenticated announce row, but does not send its token until the URL is HTTPS and its certificate matches that row's pin.

`encryption.cpp` is not this TLS. A mismatch, missing pin, redirect, or downgrade sends no bearer header and no vfs byte.

| Commit | Does | Leaves alone | Check |
|---|---|---|---|
| 1.1 | TLS spike and decision record. Prove one Android termination path and the dedicated pinned Windows client. No credential route changes | The cleartext product listener | Restart and upgrade keep the same phone pin. Reinstall creates a new identity. Wrong pin, redirect, and downgrade send no test bearer header |
| 1.2 | Create the phone TLS identity before pairing. Extend the existing pairing request and response with both pins. Add `tls_fp` to the legacy desktop paired-device row and copy it into `lan/peers.json`; persist the desktop pin in the phone `PairStore`. Pairing fails if either pin cannot be stored | The product listener is still cleartext and the old dialer still uses it. The new pin is not yet authority to send a token | Pair before sharing a folder. Restart both processes. Both authoritative rows still hold the expected peer pin |
| 1.3 | A hop header is accepted only from the proxy's own loopback socket and only when the secret matches. Any other socket with `X-Tanit-Lan-Hop` is 400. The proxy strips a client-supplied copy before it writes its own. The hop grants nothing | The open-loopback pass. Phase 2 removes it | A forged hop is 400. A real proxied request still reaches the handler |
| 1.4 | Atomic transport cutover. `node-transports/phone` terminates the chosen TLS stack in front of `peer/listener.cpp`. Announces become HTTPS-only. The desktop pinned client replaces `route_for`'s anonymous authority probe. `/health` drops `authority`. HTTP, a missing pin, wrong pin, redirect, or changed announce pin is refused before the token is attached | The directory move of `peer/`. The listener file stays where it is until phase 2 | Spoofed `/health`, wrong pin, missing pin, redirect, and cleartext downgrade receive no token. Right pin reads a file. Android image links |
| 1.5 | Replace the single wildcard listener with a listener set: one socket per granted local address, all sharing one selected port and one immutable handler state. No granted address means no listener. Interface and grant changes atomically replace the set. Loopback exists only in an explicit test profile | `any_peer_on` remains defense in depth | Add and remove an interface while listening. Narrow a network grant. Removed addresses stop accepting TCP. Overlapping peer grants keep one socket. Port stays stable |

## 2. Node core split

Exit: `tanit-cli node serve` runs with `FEATURE_COMMAND_LLM` off, and a viewer can be told about a phone folder.

Introduce the seams before moving files. The mechanical move therefore has no type invention and no behavior change. The later gate commit drops the open-loopback pass in `desktop/node.cpp` (`!via_tls && serve_api_key.empty()` is a pass today). That pass is not copied into the router.

Audio, video, and control stay in `desktop/` through this phase. `node_audio.cpp` and `node_video.cpp` include the agent header. `/v1/logs` moves with the agent. `lan_win.cpp` keeps its ticket-scope `devices.json`. Phone TLS stays the wrapper from 1.4.

| Commit | Does | Check |
|---|---|---|
| 2.1 | Add `pm/server/options.hpp` (`ListenOptions`, `validate`, `node_features()`), `pm/node/desktop.hpp` (`RoutePolicy`, `RequestContext`, `Router`, `DesktopLayer::mount`), and principal kinds `RemotePair`, `ServeKey`, `LocalAdmin`, and `LocalAgent`. Implement them as behavior-preserving adapters in the current paths. `LocalAgent` is injected only by a direct in-process call and carries explicit capabilities plus consent; it is never inferred from loopback and has no pair row | Existing routes and statuses stay byte-compatible, including today's open-loopback pass |
| 2.2 | Add `pm_server_add_desktop_node` and explicit source groups for core, desktop transport, vfs, and agent while files remain at their current paths. Make every owning target consume those groups. Do not add `FEATURE_COMMAND_NODE` yet | `tanit`, `tanit-cli`, `pm-llm`, viewer, standalone `pm-server`, and `tanit_node_phone` link |
| 2.3 | Mechanically move files onto the directories in [node-refactor.md](node-refactor.md) section 1. Public includes stay `pm/server` and `pm/node`. Update `packages/server.cpp/CMakeLists.txt`, `packages/llm.cpp/cmake/host-sources.cmake`, `cmake/host.cmake`, and Android source ownership in the same commit. Split `node.cpp`, `node_lan.cpp`, and `node_internal.hpp`; `node-core` includes nothing from `llm/` | All owners from 2.2 link. `llm agent --serve` still serves today's routes. `test:vfs-phone` |
| 2.4 | Switch the desktop to the router gate. Unknown `/v1/` is 404. Loopback with no credential is refused. `POST /v1/lan/phone-vfs` accepts a paired device whose grant has `files`. Tickets offer only scopes whose feature is on. The phone listener keeps its three checks until phase 3 | The phase 2 cases in `tests/orchestrator/test-node-serve.mjs` against `llm agent --serve`. Separate checks for `LocalAgent`, authenticated IPC `LocalAdmin`, unauthenticated loopback, serve key, and remote pair |
| 2.5 | Add `FEATURE_COMMAND_NODE`, CLI `node serve`, `node devices`, `node revoke`, `Cmd::Node`, and `ProcessKind::Node`. Move the three root link blocks out of `if(FEATURE_COMMAND_LLM)`. `test core phone-listener` loses its LLM guard. Reconfigure with `node scripts/cmake.mjs --preset release-debug` | `test-node-serve` with the LLM feature off: `/health` names `tanit-node`, vfs is 200, agent routes are 404, a `files` token announces, and a second pair id is 409. Then `test:vfs-phone`, `test:vfs-copy`, `test:service` |
| 2.6 | Viewer preset turns `FEATURE_COMMAND_NODE` on. README module table. Pointer in `packages/llm.cpp/docs/llm-server.md`. `npm run android:server -- --node` | `test-node-serve` against the viewer |
| 2.7 | Tray `node` service row, and a pair entry in the file panel | A viewer user reaches a phone folder without a terminal |

## 3. One trust model, one route policy

Exit: both listeners enforce the same grants, and a route nobody registered is 404 on both.

| Commit | Does | Check |
|---|---|---|
| 3.1 | Version 2 is the only schema `PairStore` writes. One owner. A ticket-scope desktop file is imported once and is not read again: identity, device id, name, token hash, timestamps, revocation, and scopes are kept. Legacy `files` maps to vfs write; `audio`, `video`, `chat`, and `tools` are explicit capabilities. Unknown scopes and invalid ids abort and leave the file untouched. Desktop limit 64, phone limit 16. No compatibility reader | A new pair writes only version 2. A bad ticket file is unchanged. Audio, video, chat, and tools round-trip |
| 3.2 | The import backs up `devices.json`, flushes the new file, and replaces it. After that, `PairStore` is the only writer. The device id stays the `vfs://` label; `tls_fp` stays empty until phase 1; `peer_fp` stays empty; there is no `pm::room` step | A failed conversion leaves the original file. The next read of a converted file does not import again |
| 3.3 | Done for the grant table. Desktop and phone both use `route_grant`. The phone still admits by token and network, then applies that grant. Unknown `/v1/` is 404. The agent serve key is `files`, `audio`, `video`, `chat`, `tools`. `node serve` adds `audio` and `video` only when those features are on. Local admin on HTTP is that key without a proxy hop. IPC action `pair` is local admin | A files token reads vfs, is 403 on audio, and is 404 on chat. A phone token with vfs off is 403. Loopback with no key is 401 |
| 3.4 | Done for the registry. A live call is keyed by peer, capability, and revision. Revoke cancels that peer. Narrowing vfs cancels `files`. An upload re-reads the grant between chunks and deletes the partial. Audio stops on cancel and re-checks the token. Old-schema migration is not a test | `lan-grant` covers the cancel. A files key is still 404 on chat. A revoked token is 401 |

The ticket-scope parser is the one-shot import. It is not a writer, and it does not stay as a reader of version 2.

## 4. Features that are not the agent

Exit: vfs, audio, and video answer on a node with `llm` off, when the binary contains them.

| Commit | Does | Check |
|---|---|---|
| 4.1 | Done for the include cut and the mount. `node_audio.cpp` and `node_video.cpp` include the capture headers and the node gate, not the agent header. `node serve` mounts them when capture is compiled, and `video_control` stays off. `POST /v1/video/control` still lives in the video host; it is not a separate feature file, and the handlers are not on the unused router type | `test:node-serve`: a files token is 403 on audio, the serve key reaches audio, and video control is 404 |
| 4.2 | Done as host defaults. `ListenOptions.payload_max` is 9 MiB and `http_workers` is 8. The phone listener hardcodes 9 MiB and 4 workers. The agent sets 500 MiB and keeps `InflightGate` on LLM routes only. vfs refuses a write over 8 MiB. `RoutePolicy.max_body` is unused. A stream is not a request body | `test:llm-server` refuses a body over 500 MiB. `node serve` keeps the 9 MiB default |
| 4.3 | When a WebRTC path exists, its signaling is a route on the router and the negotiated fingerprint is checked against the pair. `node-transports/webrtc` is empty until that route exists. Media keeps SRTP | No files, and no work, until a media path needs signaling |

## 5. One E2EE use

Exit: bytes stored where the peer is not serving them are ciphertext there. `node serve` still links no `encryption.cpp`.

| Commit | Does | Check |
|---|---|---|
| 5.1 | `node-e2ee` is a separate target. It links the node and `pm-encryption-lib`. `pm-server-lib` does not. The first call is `FileOffer` / `FileInbox` for one file a relay will hold. Direct vfs stays on TLS and the pair row | The relay's copy is not plaintext. `node serve` with the LLM feature off links without `pm-encryption-lib` |

The in-process agent was made a `LocalAgent` principal in phase 2. It has explicit capabilities and consent, no pair row, no room membership, and no `tn1_` token. `Handshake`, `TextSession`, `SecureFlow`, `SignalEndpoint`, `Broker`, and `pm::host::Device` stay in the encryption tests until a feature has a requirement TLS, the file envelope, or WebRTC cannot meet.

## 6. Remove the duplicates

| Commit | Does | Check |
|---|---|---|
| 6.1 | Delete the ticket-scope reader in `lan_win.cpp`. Delete any remaining open-loopback pass | A desktop with an old ticket file migrates or refuses with a clear error. `test:vfs-phone` |
| 6.2 | Desktop-to-desktop is on the pair row: `urls`, `tls_fp`, and a wrapped `dial_token`. `test:node-peer`. Two phone listeners dial the same way. An announce writes that row, and the desktop also keeps `lan/peers.json` for Places. `test:phone-peer` | One peer reads the other's `/v1/vfs` only after the pin matches |
| 6.3 | Drop any `encryption.cpp` entry point `node-e2ee` gained and does not call. The library's tests keep the entry point | `node-e2ee` builds. The encryption test suite passes |

## Standing checks

These run at the end of the phase that makes them real, with `llm` compiled in and compiled out, on the desktop and on Android.

| Check | First green at |
|---|---|
| Phone identity survives restart and upgrade; reinstall changes it | 1.1 |
| Pairing before any folder is published stores both pins | 1.2 |
| Spoofed `/health`, wrong or missing pin, redirect, and downgrade receive no token | 1.4 |
| Interface or grant removal closes the listener on that address | 1.5 |
| Forged hop is 400 | 1.3 |
| `node serve` with the LLM feature off | 2.5 |
| Old pair schema migrates without loss or a second writer | 3.2 |
| Unknown `/v1/` is 404 on the phone | 3.3 |
| Replayed token, revoked live stream, grant on the wrong route, path outside the mount | 3.4 |
| Audio and video with the LLM feature off | 4.1 |
| Relay holds ciphertext | 5.1 |
