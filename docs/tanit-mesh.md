# Tanit mesh

**Date:** 2026-11-22  
**Status:** the node, the pair row, and the dials are in. `tanit-cli node serve` is the listener with `llm` unmounted. `llm agent --serve` mounts the agent on the same gate. Desktop-to-desktop, phone-to-desktop, and phone-to-phone use one `PairStore` version 3 row (`allow_peer`). The phone listener terminates TLS. The desktop dials it with the certificate pin. What is still open is in section 11: E2EE for a file that a relay will hold, and the node when the tray or the built-in GUI starts it. That process still answers 401 and `invalid LAN hop`. The orchestrator suites do not start it. Live gaps and Places/capability work: `tanit-mesh-overview.md` §6.  
**Reads with:** `packages/server.cpp/docs/tanit-mesh-overview.md` (what each platform actually serves and calls today), `packages/server.cpp/README.md` (module index), `packages/server.cpp/docs/node-today.md` (what compiles now), `android/vfs-next.md` (the phone-folder slice log and manual tests), `packages/llm.cpp/docs/llm-server.md` (the agent routes), `docs/phone-mesh.md` (the longer product sketch), `packages/encryption.cpp/docs/design.md`.

A mesh peer is a node. It speaks the same routes, with a `vfs://` name for every shared folder and every live source. Either phone or a desktop can be the listener. Phone-to-phone uses the same pair record as phone-to-desktop. The LLM is one feature of that node. A build that leaves it out is still a node.

`packages/encryption.cpp` stays a separate library. The root build does not link it, and `pm-server-lib` does not link it either. Paired vfs, audio, and video ride authenticated TLS. The library is for a feature that must hide bytes from a relay or from storage the peer is not serving. It is not the node transport, and it is not a second pairing system.

## 1. Two different fingerprints

The desktop LAN listener treats the TLS key as the device.

| Object | Where it lives today | What a change means |
|---|---|---|
| TLS key | Legacy RSA CSP container `TanitLanIdentity.rsa.v1`. Schannel rejects a CNG self-signed cert here. SPKI SHA-256 in `%APPDATA%\PolyMech\tanit\lan\identity.json` | Every row in `lan\devices.json` is revoked |
| Pair token | SHA-256 only, in that same `devices.json`. Plaintext `tn1_` is returned once | Re-pair of the same device id rotates the hash. Scopes are whatever the ticket offered |
| Ticket | Memory. `tp1_` secret, default 300s | Lost on process exit. Eight wrong secrets lock the listener for 30s |

That fusion is the wrong long-term identity. A TLS certificate rotates when a listener is reinstalled or the key container is lost. The person did not get a new phone.

The device id and the key stay apart. `phone-<id>` in a `vfs://` URI is a label. Rotating a key does not rename it. Trust follows the key that authenticated the peer, not the label and not the address.

There is one pairing transaction, the one that already exists. The listener shows a QR with its TLS fingerprint and a short-lived secret. The dialer checks that fingerprint before it sends the secret. The listener issues a token. The same exchange records the peer's TLS pin, so the desktop checks the phone the way the phone already checks the desktop. `pm::room` offer, accept, and `confirm_pairing` are not a second pairing step, and the node does not run them.

A long-term device key is optional, and it waits until both platforms can hold one. Android Keystore documents hardware-backed EC signing. A portable non-exportable Ed25519 key is not something this tree can assume on Windows and on Android. Until that is shown, the verified TLS pin and the token are the pair. `encryption.cpp` `Identity` is a candidate adapter for a later key. Shipping the node does not depend on it.

Tailscale authenticates a tailnet node. It does not authenticate the pin or the token. A saved `100.x` or `*.ts.net` address is one more unicast candidate after the pair exists.

## 2. The pair record

Each device stores its own file. The desktop file stays `%APPDATA%\PolyMech\tanit\lan\devices.json`. A phone file is `files/tanit-profile/lan/devices.json`, with `identity.json` beside it. The desktop TLS private key stays in the RSA container. The phone listener key is `listener.key` beside the pair file. The id in the URI is not that key. The ticket stays in memory. Writes keep the temp-file rename the desktop already uses.

A row is one peer:

```json
{
  "id": "a1b2c3d4e5f60718",
  "name": "Pixel",
  "peer_fp": "<long-term public key, empty until a platform key exists>",
  "tls_fp": "<spki sha256 hex of the listener we dial>",
  "urls": ["https://192.168.1.20:8091"],
  "dial_token": "<wrapped tn1_ this device sends when it dials that listener>",
  "token_sha256": "<sha256 of the tn1_ token this peer presents when it dials us>",
  "trust": "paired",
  "allow_peer": {
    "vfs": { "revision": 4, "level": "read", "conditions": { "networks": ["192.168.1.0/24"] } },
    "audio.capture": { "revision": 1, "level": "off" },
    "video.capture": { "revision": 1, "level": "off" },
    "chat.turn": { "revision": 1, "level": "off" },
    "tools.call": { "revision": 1, "level": "off" }
  },
  "allow_peer_revision": 4,
  "created": "2026-11-17T12:00:00Z",
  "last_seen": "2026-11-17T12:04:11Z"
}
```

The file on disk is `{"version": 3, "identity", "devices"}`. `allow_peer` is what this device allows that peer to do. `vfs.level` is `off`, `read`, `write`, or `ask`. Capture / turn / call caps use `use`, `off`, or `ask`. Version 1 and 2 files, and rows that still use `outbound`, are rejected. This file is the authority for those resources. `inbound` in older sketches is not written. A request is allowed only when the serving device's own `allow_peer` says so. `urls` and `dial_token` are how this device dials that peer. `dial_token` is wrapped. It is not `token_sha256`. Desktop-to-desktop stores both directions on this row. A phone announce stores the same fields on the caller's row. Places prefers dialable rows from `devices.json`; `lan/peers.json` is fallback.

The token authenticates the peer. It does not carry the grant. `GET /v1/lan/grant` returns the caller's `allow_peer` (and flat `grant.*` for older clients). The user edits grants on the device that owns the resource. That edit is local. There is no route a peer can call to raise what they are allowed to do.

Trust is `verifying`, `paired`, or `revoked`. An empty grant on a `paired` row means the peer is still paired and can refresh `GET /v1/lan/grant`. `revoked` rejects the token. Those are different states: a stolen token still follows later grant edits, and only revoke drops the hash.

Same device id with a new TLS pin is an endpoint change: update `tls_fp` after the peer proves it still holds the token, and do not revoke the row. A new installation is a new device id: revoke the old row. Key rotation, once a long-term key exists, updates `peer_fp` and keeps the id. The id is not derived from the key.

Caps stay small. The desktop listener already refuses the 65th device. A phone caps at 16 peers.

## 3. Permissions

Three grants, each directed, each editable after pairing. Pairing itself grants none of them. The first successful confirm stores `vfs=off`, `audio=off`, `video=off` at revision 1. This matches desktop bookmarks, where `share` defaults off, and the desktop ticket, where `audio` and `video` are opt-in.

| Grant | Values | What the peer may do |
|---|---|---|
| `vfs` | `off`, `read`, `write` | `write` includes read, mkdir, and delete inside a published mount. The jail is that mount |
| `audio` | `off`, `on` | Open this device's microphone sources. The stream is stereo s16le. `sampleRate` is 16000, 24000, or 48000. `bits` is 16. A start that omits them uses the node default (`--audio-rate`, `--audio-bits`) |
| `video` | `off`, `on` | Open this device's camera or screen as a source. MJPEG stays the desktop `/v1/video/mjpeg` contract. Pointer and key injection stay off |

`write` implies `read`. Narrowing `write` to `read` fails an in-flight `PUT` and discards the temp file, so `list` never shows a partial object.

A pair is two of these rows, one on each device. Phone A can give the desktop `vfs=read` while the desktop gives phone A `audio=listen` and `vfs=off`. Phone-to-phone is the same shape. Neither direction implies the other.

Chat is not one of these three, and it is not a reason to link `encryption.cpp`. A node that never mounts chat is complete. If a later build adds an E2EE chat feature, turning off vfs does not close it, and revoking the pair does. Decrypting a message does not grant vfs, audio, video, or tools.

### What a grant does not cover

- `tools`, completions, consent, and `POST /v1/llm/path-tools/call` stay on the desktop chat server. A vfs grant is not a tool grant.
- `POST /v1/video/control` stays off on every phone listener, including when `video=watch`.
- The voice-agent microphone stays on the phone that is running the agent. Mesh `audio=listen` is a recording source the peer asked for. It is a different capture than the agent session, and the publisher does not play that capture back to itself.
- A grant is peer-wide for everything this device has published. Publishing a folder is a second action. The publish sheet names the peers whose `vfs` is `read` or `write`, so a new folder is not a surprise to a second phone.
- One device's grant does not extend through another device. Desktop B having `vfs=read` on phone A does not let phone C read A by asking B. The client dials the device named in the URI.

### Revision

Each capability keeps its own revision (`vfs_revision`, …). The row also keeps `allow_peer_revision` as the whole-document generation. A wall-clock timestamp is not the order: a peer with a wrong clock must not restore an older `write` by replaying an announcement. Folder clients cache the vfs revision (`vfs_revision`), not the generation. The serving device does not consult that cache when it allows a request.

`Room.grants` in `pm::room` is a different mechanism and a known stand-in. `join` ORs invite bits into one room field, in memory, and nothing re-signs the room. `Broker::post` ignores the bits. `invite` rejects `k_grant_files`. A mesh host must not use that field as the pair grant. The pair row is per peer, it can narrow, and the device that owns the microphone enforces it.

## 4. Names

```text
vfs://desktop/<mount>/<path>
vfs://phone-<device-id>/<mount>/<path>
vfs://phone-<device-id>/recordings/<file>
vfs://phone-<device-id>/audio/<spec>
vfs://phone-<device-id>/video/<spec>
```

`desktop` stays the authority it already is, so existing links keep working. `phone-<device-id>` is the stable device id, lowercase hex, not the display name and not a key fingerprint. Renaming the phone does not change a URI. Rotating a key does not either.

Mount ids are stable and unique on that device. Labels may collide, including across peers (`Camera` on two phones). The desktop shows the label and resolves the id.

| Mount kind | `list` returns | Open with |
|---|---|---|
| `folder` | Files and directories | `GET /v1/vfs/read` |
| `audio` | Source rows (`mic:built-in`) | `POST /v1/audio/start`, then `GET /v1/audio/stream` |
| `video` | Source rows (`camera:0`, `screen:0`) | `POST /v1/video/start`, then `GET /v1/video/mjpeg` |

`GET /v1/vfs/read` on a live source is a 400 whose body names the start route. A live source has no length and no content hash. A client that saved the stream has created a new file. That file can be published later under `recordings`. It is not a resume of the live URI.

`GET /v1/vfs/mounts` keeps the desktop envelope and adds the fields a peer needs to tell those cases apart:

```json
{
  "name": "dcim",
  "label": "Camera",
  "uri": "vfs://phone-a1b2c3d4e5f60718/dcim",
  "host": "phone-a1b2c3d4e5f60718",
  "kind": "folder",
  "can": ["list", "read"],
  "online": true
}
```

`can` is the intersection of the mount and the caller's grant. A Storage Access Framework tree that cannot delete advertises `can` without `delete`. `online: false` means the tree permission disappeared while the pair grant remains. An empty `entries` array means the folder is really empty.

`resolve` answers the same `{ path, shared, uri, mount, rel }` object the desktop already returns. The `uri` authority is this device. A path outside every published mount is `shared: false`.

## 5. One server, features as options

Desktop `llm agent --serve` and a phone listener are the same process shape. `run_llm_agent_openai_server` already takes `AgentServerOptions` and `register_routes` mounts every route that was compiled in. Pair scope (`device_scope_ok`) is a second switch: it allows a peer onto a route that already exists. A phone that linked this binary would still expose `/v1/chat/completions` to the serve key and to open loopback. The feature flag closes that. A route that is off is not registered.

Compile-time `FEATURE_*` stays only where the code cannot exist on the platform: Windows UI spawn, command IPC, Schannel, the browser page model. `FEATURE_VIDEO` and `FEATURE_AUDIO_SOURCES` stay as "this binary contains capture." The new switch is runtime, on `AgentServerOptions`, and the desktop defaults match today's serve.

| Feature | Routes | Desktop default | Phone listener |
|---|---|---|---|
| `lan` | `/health`, `/ready`, `/v1/lan/*`, `/v1/logs` | `--lan` | on while a mount or a capture is published |
| `vfs` | `/v1/vfs/*` | on | on |
| `audio` | `/v1/audio/*` | on when the binary has capture | on when this device publishes a mic |
| `video` | `/v1/video/*` except `/control` | on when the binary has capture | on when this device publishes a camera |
| `video_control` | `POST /v1/video/control` | on | off |
| `llm` | completions, sessions, models, credit, speak, realtime, consent, ask | on | off |
| `tools` | path-tools, each, decide, commands, `ui/open` | on | off |
| `host` | host-tool providers, page-model rank, sysprobe, Win32 file open | on | not compiled |

`llm` is one feature. Turning it off skips the turn loop, the completion inflight slots, and provider setup. Health, the payload cap, and the auth gate stay. They are the server, not the chat feature.

Registration is one function per feature. The feature names its routes, the capability each route requires, and its body limit. The router checks that before the handler runs. There is no plugin list and no second HTTP stack. An unregistered route is 404, including a `/v1/` path no feature claimed. Today `route_enabled` treats every other `/v1/` path as `llm`. That fallback goes away: a new feature must not inherit the agent, and the agent must not inherit a route it did not register. A registered route the peer's grant does not cover is 403. The handler still checks the object, such as this mount or this stream. The serve key does not see a feature this process turned off, and it does not receive a feature just because the process turned that feature on.

A desktop that passes no feature override keeps today's routes. Android fills the struct with `llm`, `tools`, `video_control`, and `host` off.

### Layout

The code is `packages/server.cpp`. Its README is the module index. `base` is route tables that take a host struct. `tanit-node` is the process that fills that struct and listens. Generic work stays in the package that already owns it. `base` mounts routes. It does not grow a second store, a second capture stack, or a second turn loop.

```text
packages/server.cpp/src/
  base/include/pm/server/     features.hpp, options.hpp, vfs.hpp
  node-core/
    auth/                     desktop_gate.cpp, lan_gate.cpp
    lifecycle/                desktop.cpp, listener.cpp, listener_tls.cpp, sessions.cpp, node.cpp
    pair/                     pair_store.cpp
    routes/                   node_serve.cpp
  node-features/
    vfs/                      vfs.cpp
    audio/                    node_audio.cpp
    video/                    node_video.cpp
    agent/                    node.cpp, node_lan.cpp, node_chat.cpp, node_llm.cpp, node_host.cpp, node_logs.cpp, node_realtime.cpp
  node-transports/
    desktop/                  lan_win.cpp, lan_qr.cpp, mdns_win.cpp
    phone/                    vfs_listener.cpp
  tanit-node/include/         pm/node, pm/server, lan/pair_store.hpp
```

`node-e2ee` is not a directory yet. `packages/encryption.cpp` stays unlinked from `node serve`. The file list for the pair path and the open tray fault is in section 11.

| Package | Keeps | The node calls |
|---|---|---|
| `packages/server.cpp` | Route tables, the pair file (`devices.json` hash, grant, revision), both listeners | — |
| `packages/llm.cpp` | Turn loop, sessions, tools, speak, realtime, chat fields on `AgentServerOptions` | `run_one_completion` and the session store, from the agent layer only |
| `packages/vfs.cpp` | `Store`, jail, path policy. Its own `/api/vfs` server stays. It is not the mesh route | `list`, `stat`, `read`, `write`, `mkdir`, `delete` |
| `packages/audio.cpp` | `SourceHost`, `SinkHost`, the 48 kHz contract | status, sources, start, stream, play |
| `packages/video.cpp` | Capture, MJPEG, the streaming session | status, sources, start, mjpeg, snapshot |
| `packages/commons.cpp` | Config dir, paths, strings, logging, the local secret wrap | those helpers |
| `packages/encryption.cpp` | Independent library, its own tests and vectors. It does not include `server.cpp` | nothing yet. Only `node-e2ee` links it, and `node serve` does not |

A feature that is off answers 404 before the handler. An unknown `/v1/` path is 404. It is not treated as `llm`. The desktop listener is `pm::node::run_node_serve`. The agent is a second mount on the same gate.

Android UI stays in `android/tanit`. Kotlin does not register routes. The phone image compiles `peer/`, `base/src/vfs.cpp`, and `tanit-node/android` with `llm` off. JNI stays the boundary it already is.

## 6. Listener

The phone process is that server with the phone column above. Discovery stays `_tanit._tcp`. TXT gains `role=phone` or `role=desktop` and `id=<device-id>`. No secret and no token in TXT.

| Method | Path | Who |
|---|---|---|
| GET | `/health`, `/v1/lan/info` | Anyone on the LAN. Name, both fingerprints, TLS port, addresses, `role` |
| POST | `/v1/lan/pair/begin` | This device, locally. A peer gets 403 |
| POST | `/v1/lan/pair` | TLS hop, after the SPKI check. Same ticket rules as the desktop: 200, 401, 410, 429 with `Retry-After: 30`, 404, 403 |
| GET | `/v1/lan/grant` | The authenticated peer. Returns the outbound grant for that peer |
| GET/POST | `/v1/vfs/*` | Peer whose `vfs` is high enough. Same verbs and the 8 MiB write cap |
| GET/POST | `/v1/audio/*` | Peer whose `audio` is `listen`. One capture on this device |
| GET/POST | `/v1/video/*` | Peer whose `video` is `watch`. One capture on this device. No `/control` |

`/health` is not an identity. A dialer does not choose a peer because that body names an authority, and it does not send a token on a socket whose certificate pin is not the one in the pair row. The desktop dialer does that for a phone folder. A custom channel from `encryption.cpp` is not what carries vfs.

`tanit://pair?v=1&host=&port=&fp=&secret=&name=` stays valid. A phone listener adds `id` and `role`. A desktop that does not know those query keys still completes a v=1 pair against a desktop. A mesh client refuses to store a phone pair when `id` is missing, because it would have no `vfs://` authority.

Either side may open the ticket. The side that shows the QR is the listener for the handshake. After confirm, both may listen, and each holds a token hash for the peer. Dialing uses the token that listener issued. Grants do not depend on which socket direction is up.

The phone listener is up while a published mount exists or a transfer or capture is live. A sleeping phone is an offline peer with a saved address, not a queued capture.

## 7. Where encryption sits

Four jobs stay independent. Sharing a struct does not merge them.

| Job | Owner | Rule |
|---|---|---|
| Transport | The listener and the dialer | No token, and no vfs, audio, or video bytes, until the certificate pin matches the pair row |
| Who | `PairStore` | The token identifies the peer. The address does not |
| What they may do | The route policy and the outbound grant | Being able to decrypt a byte does not allow `vfs` write, a microphone, or a tool |
| Past the two endpoints | `encryption.cpp`, optional | Only a feature that must hide bytes from a relay or from storage the peer is not serving |

`pm-server-lib` does not link `pm-encryption-lib`. `node serve` does not either. A feature that needs the library is its own target and links both.

| Bytes | Between two paired peers | When someone else stores or forwards them |
|---|---|---|
| Pairing, grants, vfs, audio, video | Authenticated TLS. The pin is checked first, then the token | Do not relay these. The client dials the owner |
| A file that will sit where the peer is not serving it | TLS, when the owner is the one sending it | `FileOffer` / `FileInbox`. One content key, sealed per recipient. A missing chunk resumes. A copy already opened stays readable after a later revoke |
| Live mic or camera past a forwarder | `/v1/audio/stream` and `/v1/video/mjpeg` while the grant is held | WebRTC SRTP. Signaling rides the authenticated session, and the negotiated fingerprint has to be this pair. This tree does not add a second media cipher |

`PMEH` / `PME2`, `TextSession`, `SecureFlow`, `SignalEndpoint`, `Broker`, and `pm::host::Device` stay in `encryption.cpp` and its tests. They are not the node transport. Paired vfs does not pass through them. `SecureChannel::initiator` without an identity stays a library footgun (`PM_ENCRYPTION_UNAUTHENTICATED_KX`) and no node calls it.

An agent that runs inside the node is a local principal. It gets capabilities and the same consent checks as any other local caller. It does not pair, it does not hold a `tn1_` token, and it does not open a cipher to itself. An agent in another process uses the local IPC. An agent on another device is an ordinary peer.

| Gap | Rule while it stays open |
|---|---|
| The QR exchange still does not carry both pins | Direct vfs from a desktop to a phone is pinned HTTPS, on one socket per granted address. A missing or wrong pin sends no token |
| Nothing in the library is durable | The pair row is the host's store. Do not restore a session from a backup |
| `Room.grants` is one in-memory bit field, and `invite` rejects `k_grant_files` | The pair row is the grant. `FileOffer` is for bytes that will sit somewhere the peer is not |
| A signal address is a string, not a device key | No signal session in the node until a feature can show the binding. Not before phase 5 |

## 8. Edge cases

### Grant changes under a live call

The listener checks the outbound grant when a stream is accepted and whenever the local revision changes. Narrowing `audio` or `video` stops that capture and the next read sees the socket close. A second peer with `listen` does not preempt the peer who already holds the capture: `POST /v1/audio/start` answers 409 and names the holding device id. The owner's own stop is the preemption.

Narrowing `vfs` from `write` to `read` or `off` aborts an in-flight `PUT` before the temp file is renamed. A `GET` that has started finishes the response it already committed to, and the next range or the next file is 403. Bytes already written to the caller's disk stay there. Revoke does not remote-wipe a copy the peer has finished reading. That is the same rule as a dropped `FileOffer` recipient: an older ciphertext they already hold remains readable.

A grant edit while the peer is offline is only a local revision bump. There is no queued grant message to reorder. The peer learns on `GET /v1/lan/grant` or on the next 403.

### Who can narrow, who can widen

The owner widens and narrows. The peer can ask in the UI. The ask is chat text or a local prompt, and it does not change `outbound`. Two peers editing at once cannot conflict: each writes only their own file.

A cached `inbound` of `vfs=write` plus a server that has since stored `read` is a 403 on `PUT`. The client replaces its cache from the error body's `revision` when the body's revision is newer, and it does not retry the write.

### Empty, missing, and revoked mounts

`vfs=read` with no published mount is an empty `mounts` array and `ok: true`. The UI says this peer has shared nothing.

A Storage Access Framework permission the user removed in system settings leaves the mount in the list with `online: false`. The client must not treat that as a deleted folder and offer to recreate it.

Android microphone or camera permission denied, with the pair grant on, lists the source with `available: false` and a reason. It is not a 403. A 403 means the pair grant is off. A 409 means a capture is already held, or the session is idle and a stream was opened early.

### Identity, reinstall, backup

Uninstall, or a cleared platform key, is a new TLS identity. Peers drop the old pin when they next see the mismatch. The device id in the URI changes only when the installation is new, and that revokes the old row. Restoring `devices.json` without the key that matches `identity.json` revokes every local row on load, the same way the desktop revokes rows when `identity.json` no longer matches the RSA container.

The token plaintext on the phone lives in the platform store, wrapped the way the LAN `api_key` already is. A backup that contains only the hash cannot dial. A backup that contains an exportable token is a second device.

### Reachability

Same Wi-Fi, one side listening on the LAN, is the first phone-to-phone path. mDNS is a hint. Guest isolation, a VLAN, or a VPN that drops multicast leaves the saved unicast URL. The client probes saved URLs the way the phone already probes saved desktops, at most eight, newest first.

Both phones on cellular, or otherwise unable to accept a connection, have a pair and no listener the other can dial. The pair record stays. Live vfs, audio, and video wait until one side is reachable. A finished file can move later, and if it will sit where the peer is not serving it, that copy is a `FileOffer`. The listener protocol does not grow a public inbound port to paper over that.

A desktop may introduce two phones by handing each the other's addresses, `role`, TLS pin, and device id. It does not forward the ticket secret and it does not copy a `tn1_` token. The two phones still check the pin themselves before either sends a token.

Address changes update the saved URL and `last_seen`. They do not change `outbound`.

### URI and body mixups

A relative path, a path with `..`, a backslash, or a mount id the caller invented is 400 or 404 from the jail, same as the desktop vfs layer. The client never sends a `content://` URI or a raw filesystem path.

`vfs://phone-<id>/audio/mic:built-in` and `vfs://phone-<id>/recordings/take.wav` share an authority and differ in `kind`. A recorder that wants a file picks the `recordings` mount. A recorder that wants the live mic picks the `audio` mount and the stream route.

The desktop chat server still emits absolute desktop paths. Those become links only through the desktop's own `resolve`. A phone path becomes a link only through the phone's `resolve`. A client that rewrites every absolute path against whichever server it last dialed will attach the wrong authority.

### Capture and playback loops

One audio capture and one video capture per device. Grants do not multiply the hardware. The desktop rule (a failed switch leaves the current capture running) stays.

The subscriber renders. The publisher does not echo the same capture back across the pair. The phone already keeps its own agent microphone local when it subscribes to a desktop mix. The reverse direction follows that: a desktop recording from `vfs://phone-<id>/audio/...` does not feed that stream back into the phone's playback.

### Hostile LAN

The ticket lockout (eight failures, 30 seconds) stays, and it is per listener. A peer on the same Wi-Fi can force that lockout. The UI shows locked and the `Retry-After` value. It does not keep sending the secret.

`POST /v1/lan/pair/begin`, grant edits, and revoke stay local. A paired peer that can dial `/v1/vfs/read` still cannot open a ticket or rewrite `outbound`.

Unknown `/v1/*` routes stay default-deny. With `llm` off, completions are not registered, so a serve key on the phone cannot call them either.

### Clock, order, and process death

Ticket expiry uses a monotonic clock, as the desktop listener already does. Grant order uses `revision`.

Process death drops the ticket, the capture, and any in-memory session a feature was holding. It does not drop the pair file. On the next start the capture is idle until `start`. A half-written pair file never replaces the previous one: the rename is the commit. Narrowing a grant or revoking a peer closes a stream that is already open. Checking the next request is not enough.

A peer that presents a token whose hash matches a `revoked` row gets 401. A peer whose hash matches and whose grant is `off` gets 403 with the current revision. The UI treats 401 as "pair again" and 403 as "this permission is off".

## 9. First slice

| # | Step | State |
|---|---|---|
| 1 | Feature struct on `AgentServerOptions`. Desktop serve with no override keeps today's routes | Done. A feature that is off answers 404 before the handler. An unknown `/v1/` path is 404. It is not `llm` |
| 2 | Keep the device id as a label, and record the TLS pin of the peer's listener in the same pair row. No second pairing protocol. A long-term device key waits until Windows and Android can both hold one | The id stays a label. The desktop dial book stores the phone pin. The phone's row for the desktop pin waits on the QR exchange. No second pairing protocol. Ed25519 is not assumed |
| 3 | Move scope checks for `files`, `audio`, and `video` off the frozen ticket and onto `allow_peer`, so a desktop can narrow them without a re-pair. `chat` and `tools` stay as they are | Done. `PairStore` version 3 is the desktop file. `files` is vfs write. Caps are nested under `allow_peer` |
| 4 | Phone listener with `llm`, `tools`, and `video_control` off. Grant, vfs mounts, `vfs://phone-<id>/...` | Done: `pm::node::PeerListener`, `PairStore`, per-network grants, TLS on the public port. `/health` has no authority. The phone id is random hex |
| 5 | Desktop browser for that URI, dialing the phone with the token the phone issued | Done: Places, `cp`, `lan/peers.json`. The dial is pinned HTTPS. A wrong pin sends no token |
| 6 | Phone-to-phone on the same LAN, same records | Done: the phone TLS client and the pair row. An announce stores that row. `test:phone-peer`. Places reads `lan/peers.json` |

Live `audio` and `video` reuse the existing start/stream routes once the grant check is per pair and those routes are not compiled inside the agent. `encryption.cpp` stays unlinked until phase 5, and then only for a feature that needs it.

## 10. Node without the agent

### Why

A desktop receives a phone folder in three steps: the phone pairs with the desktop's LAN proxy, the phone announces its listener on `POST /v1/lan/phone-vfs`, and the desktop stores a row in `lan/peers.json`. After that the file panel and `cp` dial the phone. The dial side (`src/vfs/phone_client.hpp`, the Places catalog) is in every build. The receive side is in one function, `run_llm_agent_openai_server`, and that function is compiled only with `FEATURE_COMMAND_LLM`. `tanit-viewer` builds with that flag off. A viewer can read a phone folder and can never be told about one.

`tanit-cli node serve` is that receive side with `llm` unmounted. It is compiled when `FEATURE_COMMAND_NODE` is on. The link is `FEATURE_COMMAND_LLM OR FEATURE_COMMAND_NODE`. The full and viewer feature sets leave `FEATURE_COMMAND_NODE` on. The notes below are the split that got here:

| Obstacle | Where |
|---|---|
| Every desktop route file includes `node_internal.hpp`, which includes the agent, the chat plugin, consent, and the session store | `node_lan.cpp` needs about ten small helpers from it: `openai_error`, `request_secrets`, `clip_text`, `trim_ascii`, the hop checks, `g_lan` |
| The auth gate, `/health`, the LAN lifecycle, and `listen` are written inline in `node.cpp` beside the completion gate | `register_routes`, `run_llm_agent_openai_server` |
| `pm-server-lib`, `pm-vfs-lib`, `pm_server_add_lan`, and the mDNS files were linked inside `if(FEATURE_COMMAND_LLM)` | Root `CMakeLists.txt`, three blocks. `test core phone-listener` was gated the same way for this reason only |

### Shape

One listener function, the core. It owns everything a node is with `llm` off. The agent is a layer that mounts more route groups onto the same `httplib::Server`. There is one `/v1/vfs` table, one auth gate, one LAN proxy, one `devices.json`.

```text
tanit-cli node serve                 tanit-cli llm agent --serve
        │                                      │
        │ ListenOptions                        │ AgentServerOptions -> ListenOptions + agent layer
        ▼                                      ▼
  pm::node::run_desktop_node(options, layer)
        validate, LAN proxy and mDNS, per-feature limits, workers
        router: a route runs only with the policy it was registered under
        /health  /ready
        /v1/lan/*            pairing, devices, phone announce
        /v1/vfs/*            authority "desktop", bookmark roots
        audio, video         when the binary has capture. Not part of the agent
        layer.mount(router)  completions, chat, realtime, tools, host, logs
        command-IPC instance, pairing QR, wait for cancel, stop
```

| Owner | Has | Does not have |
|---|---|---|
| `node-core` | Listen, the router, auth, `PairStore`, `/health`, `/ready`, `/v1/lan/*`, lifecycle | An include from `llm/`, the chat plugin, consent, or the session store. A link to `pm-encryption-lib` |
| `node-features` | vfs now. Audio, video, and control in phase 4. The agent only when `llm` is compiled: completions, chat, realtime, host, logs | A second listener, a second vfs table, its own bearer check |

`node-core/lifecycle/desktop.cpp` includes the desktop transport header and `vfs/phone_peers.hpp`. It is host-compiled, like the LAN proxy. It does not go into `pm-server-lib`. The phone listener and `PairStore` do. Shared folders arrive as parsed bookmark rows.

### Interfaces

`pm/server/options.hpp`, header only:

```cpp
namespace pm::server {
struct ListenOptions {
    std::string host = "127.0.0.1";
    int port = 8090;
    int http_workers = 8;
    std::size_t payload_max = 9u * 1024 * 1024;
    std::string serve_api_key;
    bool lan = false;
    int lan_port = 0;                 // 0 = port + 1
    std::string lan_name;
    bool pair_on_start = false;
    std::vector<std::string> pair_scopes;
    ServerFeatures features = node_features();   // lan and vfs
    std::string service = "tanit-node";          // the /health "service" field
};
/// Trim host, reject a bad port, reject a non-loopback bind with no serve key.
std::string validate(ListenOptions&);
}
```

`pm/node/desktop.hpp`. A feature does not receive `httplib::Server`. It registers routes on the router the core owns, and the router is what authenticates. The type lives with `node-core`. The include path stays `pm/node`.

```cpp
namespace pm::node {
struct RoutePolicy {
    /// files, audio, video, chat, or tools. Empty means any paired peer.
    std::string capability;
    bool paired_only = true;
    bool local_admin = false;
    std::size_t max_body = 0;
};

struct RequestContext {
    std::string peer_id;
    /// The outbound grant that allowed this call. Empty for local admin.
    pm::lan::Grant grant;
    /// Certificate pin of this connection, when the transport checked one.
    std::string tls_fp;
};

struct Router {
    void add(const char* method, const char* path, RoutePolicy policy,
             std::function<void(const RequestContext&, const httplib::Request&, httplib::Response&)> handler);
};

struct DesktopLayer {
    /// Extra route groups. Called once, after lan and vfs are registered.
    std::function<void(Router&)> mount;
    /// Extra fields for /health.
    std::function<void(nlohmann::json&)> health;
    /// After the listener stopped, before the LAN proxy is destroyed.
    std::function<void()> stopped;
    /// Command-IPC kind of this process.
    media::cmd_ipc::ProcessKind kind = media::cmd_ipc::ProcessKind::Node;
};
int run_desktop_node(const pm::server::ListenOptions&, DesktopLayer layer = {});
}
```

`layer.scope` is not part of this. A route with no policy is not registered, and an unregistered path is 404. The handler still decides the object: this mount, this path, this stream.

`run_llm_agent_openai_server(const AgentServerOptions&)` keeps its name and its callers. It copies the listener fields into `ListenOptions` (workers from `resolved_http_workers`, payload cap 500 MiB, `service = "tanit-llm-agent"`, kind `LlmAgent`), builds the layer, and calls `run_desktop_node`. `AgentServerOptions` stays flat. `validate_server_options` calls `pm::server::validate` for the listener fields, so the bind rule exists once.

### Rules the core keeps

- **Wire.** Every route keeps its status codes and bodies. The LAN routes keep the `{"error":{"message","type","code"}}` envelope, built by a helper in `core_internal.hpp`. The vfs routes keep `{"ok":false,"code","error"}`. With the agent layer on, `/health` is byte-compatible with today.
- **Gate.** An unregistered path is 404. A hop header that is not the proxy's secret, or that arrives on any socket but the proxy's loopback connection, is 400. The hop proves the proxy wrote the request. It is not a capability. `pair/begin`, `devices`, and `devices/revoke` are `local_admin`. Loopback origin is not that privilege: those routes need the local IPC or a local credential. Then the serve key, and only for the capabilities that key was granted. Then a paired device token, checked against the route's capability and the peer's outbound grant. Otherwise 401. There is no last step that accepts a request because it came from loopback with no credential.
- **Serve key.** It stays the credential a legacy OpenAI client sends. Its grant is the set named at startup. Adding a feature later does not add that feature to every key already issued.
- **Local development exception.** A build may mark a named list of routes as open on loopback with no credential. Pairing admin, vfs, audio, video, and host tools are not on that list. A new route is not on it unless someone adds it.
- **Scope.** `/v1/lan/info` is any paired device. `/v1/vfs/*` and `POST /v1/lan/phone-vfs` need `files`. Audio routes need `audio`. Video routes need `video`. The phone listener uses the same policies. It does not keep a second gate.
- **Announce with a pair token.** Today `device_scope_ok` has no row for `/v1/lan/phone-vfs`, so a phone that paired by QR gets 403 and only the serve key can announce. A viewer user has no serve key to type into a phone. The `files` policy above closes that. The handler already ties the stored row to the announcing pair id and refuses a second device that claims the same phone.
- **Offered scopes.** A pairing ticket offers only scopes whose feature is on. `node serve` offers `files`. A ticket for `chat` or `tools` from a node with `llm` off is an error at `--pair`, not a scope that can never be used.
- **One node per profile.** `node serve` and `llm agent --serve` share the port default, the TLS identity, `devices.json`, and the mDNS name. The agent server is the superset. The second process fails at bind and says which port is taken.
- **LAN bind.** `node serve --lan` binds HTTP to loopback and the TLS proxy to the LAN. A phone arrives through the proxy with a pair token. The loopback port is not itself a credential. `--host 0.0.0.0` still requires `--serve-api-key`.

### CLI

```text
tanit-cli node serve [--host H] [--port N] [--serve-api-key K]
                     [--lan] [--lan-port N] [--lan-name S] [--pair] [--pair-scopes files]
                     [--audio-rate 16000|24000|48000] [--audio-bits 16]
tanit-cli node devices
tanit-cli node revoke <id>
```

The verb is `node`. `serve` is taken by the Drogon REST server (`src/cli/pm_image_cmd_serve.cpp`, `Cmd::Serve`). The build flag is `FEATURE_COMMAND_NODE`. `FEATURE_NODES` is the NodeHub graph editor and has nothing to do with this.

`llm agent --serve` keeps every flag. `--lan-devices` and `--lan-revoke` stay and call the same two functions as `node devices` and `node revoke`. `TANIT_SERVE_API_KEY` and `TANIT_SERVE_LAN` apply to both verbs.

`node serve` mounts `lan` and `vfs`, and audio and video when phase 4 has moved them and the binary has capture. `GET /v1/models` is the desktop preset list. A paired phone and the serve key can read it. `/v1/chat/completions` and every tool route are 404 for every caller, including the serve key.

### Build

| Flag | Compiles |
|---|---|
| `FEATURE_COMMAND_NODE` or `FEATURE_COMMAND_LLM` | `pm-server-lib`, `pm-vfs-lib`, `pm_server_add_lan`, `pm_server_add_mdns`, and the core through `pm_server_add_desktop_node(target)` in `host.cmake` |
| `FEATURE_COMMAND_NODE` | `src/cli/pm_image_cmd_node.cpp`, `Cmd::Node` |
| `FEATURE_COMMAND_LLM` | The agent layer through `pm_llm_sources(cli)`, as today |

`FEATURE_COMMAND_NODE` is on in the full and the viewer feature sets.

### What stays out

`pm-encryption-lib` is not linked. `/v1/logs` stays in the agent layer (`node_logs.cpp`). On a plain node it is 404. The both-pin QR exchange stays parked. The desktop dial book stores the phone pin. The phone's row for the desktop listener pin is not filled by the current ticket QR. The tray starts the node. Pairing starts from Settings or an explicit `node serve --pair`.

## 11. What is left

Phases 1 through 4 and the pair-row half of phase 6 are in the tree. `PairStore` version 3 is the only pair file. `node serve` mounts lan, vfs, audio, and video when the binary has capture. The phone listener, the desktop dial, desktop-to-desktop, and phone-to-phone use that row. `peer_fp` stays empty. Both-pin QR exchange stays parked. `encryption.cpp` is not linked.

Rows 1 through 6 are in the tree and covered by the suite on that row. E2EE stays after this list. The tray node no longer passes `--pair`.

### Pair and grant todos

The phone in these suites is `tanit-cli test core phone-listener`: the same listener the Android app runs, on loopback, with its own pair file. `lan-peer` is the edit the phone's Shared folders screen makes. `phone-post` sends an announce. `phone-dial` reads `/v1/vfs/mounts` the way Places does. No handset is required. `test:phone-peer` already stores an announce on the pair row when the bearer is the pair token. `test:vfs-phone` already narrows a grant and refuses a dial before a network is granted. `test:node-serve` announces with the pair token and with the serve key. Both write the pair row.

Rows 1 through 6 are fixed. A network refusal names the current vfs, and a lower revision replaces the cache. Revoking a device drops the phone rows it announced and their Places cache. An unreachable phone stays in Places with `offline` on the label.

| | Gap | Where | Done when | Suite |
|---|---|---|---|---|
| 1 done | A fresh pair on the phone stores `vfs=off` and no network. An announce then carries no address, and `phone-dial` does not open a socket. Shared folders turns on read and a network, and the announce carries one address | `peer_announce_json` in `listener.cpp` | A phone with `vfs=off` or an empty network list announces no `urls`. `phone-dial` does not open a socket. After `lan-peer grant` of read plus `127.0.0.0/8`, the announce carries one `https://127.0.0.1` url and mounts return 200 | `test:vfs-phone` |
| 2 done | The phone calls `/v1/lan/phone-vfs` with the desktop serve key. That announce writes `urls`, `tls_fp`, and a wrapped dial token onto the phone's pair row and into `lan/peers.json`. A pair-token announce still writes the caller's row | `register_lan_routes` in `node_lan.cpp` | An announce with the serve key writes `urls`, `tls_fp`, and a wrapped dial token onto that phone's row in `devices.json`, and the same fields into `peers.json`. The plaintext `tn1_` is in neither file | `test:node-serve` |
| 3 done | A new pair on the phone has an empty `token_sha256`. The desktop's old dial gets 401, the stored token is dropped, and the next announce carries a new token | `peer_announce_json` in `listener.cpp`. `drop_token` in `phone_peers.hpp` | Restart the phone listener on a new pair file, dial with the old token, expect 401, expect the stored dial token gone. The next announce body carries a new token. The following mounts call is 200 | `test:vfs-phone` |
| 4 done | A second confirm of the same device id stores the empty grant at a higher revision. `authorize` returns that grant | `Service::complete_pairing` in `lan_win.cpp` | Pair the same device id twice. The second row's revision is greater. A grant that the second confirm replaced is the one `authorize` returns | `test:node-peer` |
| 5 done | A fresh confirm matches section 3: revision 1, vfs off, audio off, video off, chat off, tools off. The ticket intersection only decides that the confirm is allowed. Settings is what turns a grant on | `complete_pairing` in `lan_win.cpp` | A fresh confirm matches section 3. A later Settings edit is what turns a grant on | `test:node-serve` |
| 6 done | `note_grant` ignores a revision that is not greater than the cached one. A fresh phone pair at revision 1 leaves a cached `write` at revision 4 in place. An `ENETWORK` body named the revision and no vfs, so the cache kept the old vfs | `note_grant` in `phone_peers.hpp`. `admit` in `listener.cpp` | A smaller revision replaces the cache. The vfs value is the one in that document, and an empty vfs clears it. `ENETWORK` and the announce `EGRANT` include `vfs` | `test:vfs-phone` |

Both-pin QR exchange stays parked and is not a row in this table.

The Devices page is its own Settings section (`devices` in `apps/settings`). Folder access is one control: Off, Read, or Write. An enabled audio, video, chat, or tools box uses the primary fill. The page says this PC allows the device, and that phone folders are set on the phone. The pairing code lists the three steps after a confirm and does not list ticket scopes as grants. It needs `npm run build:settings:embed` and a desktop build before it shows.

### E2EE

Bytes that two paired peers exchange directly stay on authenticated TLS. E2EE is only for a file that a relay or another store will hold.

- An E2EE target links the node and `pm-encryption-lib`. `pm-server-lib` and `node serve` do not.
- The first use is `FileOffer` / `FileInbox`. That store never sees the plaintext. Direct vfs stays on TLS and the pair row.
- `Handshake`, `TextSession`, `SecureFlow`, `SignalEndpoint`, `Broker`, and `pm::host::Device` stay out of the node until a feature has a requirement TLS, the file envelope, or WebRTC cannot meet.
- WebRTC is not a host setting. There is no `node-transports/webrtc`. A later group voice path would be a WebRTC session per remote participant, with NetEQ inside that session. It is not a backend of `/v1/audio/stream`.

### Tray and GUI node

The agent row is `llm agent --serve` on port 8090. The node row is `node serve` on port 8092, TLS 8093 (`node_service()` in `src/cli/pm_image_cmd_tray.cpp`). It does not pass `--pair`. A stored node row that still has `--pair` or `--pair-scopes` loses both the next time the tray reads `services.json`. Pairing starts from Settings or from `node serve --pair`. A node row that omits `--port`, or that uses the agent's HTTP or TLS port, is rewritten to 8092 and 8093 on that same read. The two listeners used to share 8090 and 8091. `SO_REUSEADDR` let both accept. A hop minted by one process then landed on the other, which is **400** `invalid LAN hop`. A bearer the other process does not hold is **401**.

A process that is still alive is the same failure. `run_desktop` asks IPC before it binds. `list_instances()` already drops a dead pid. A live `node` or `llm-agent` whose label ends in `:<port>` makes the new process exit with `already served by`. It does not bind over the leftover. The tray's own start check uses that same IPC list. Restart the tray after this build so the node that is still on 8090 exits and the next one listens on 8092.

A call that presents a hop the proxy of this process did not write is **400** `invalid LAN hop` (`lan_hop_ok` in `node-core/auth/lan_gate.cpp`: the header is `X-Tanit-Lan-Hop`, the peer must be loopback or `proxy_peer`, and the secret must match `g_lan`). A call with no serve key and no pair token is **401**.

## Packages and files

| Piece | Files |
|---|---|
| Gate, 401, invalid hop | `packages/server.cpp/src/node-core/auth/desktop_gate.cpp`, `lan_gate.cpp` |
| Listener, TLS, sessions | `node-core/lifecycle/listener.cpp`, `listener_tls.cpp`, `desktop.cpp`, `sessions.cpp`, `routes/node_serve.cpp` |
| Pair file | `node-core/pair/pair_store.cpp`, `tanit-node/include/lan/pair_store.hpp` |
| Desktop TLS proxy, QR, mDNS | `node-transports/desktop/lan_win.cpp`, `lan_qr.cpp`, `mdns_win.cpp` |
| Phone listener | `node-core/lifecycle/listener.cpp`, `node-transports/phone/vfs_listener.cpp` |
| Routes | `node-features/vfs/vfs.cpp`, `audio/node_audio.cpp`, `video/node_video.cpp`, `agent/node_lan.cpp` |
| CLI | `src/cli/pm_image_cmd_node.cpp` |
| Tray and Settings launch | `src/cli/pm_image_cmd_tray.cpp`, `src/win/settings_services.cpp` |
| GUI pair ticket | `src/win/ui_next/filepanel/FilePanelSourceCatalog.cpp` (`pair` over IPC) |
| Desktop dial | `src/vfs/peer_dial.hpp`, `src/vfs/phone_client.hpp` |
| Desktop file-panel Places | `src/win/ui_next/filepanel/FilePanelSourceCatalog.cpp`, `FilePanelLocationMenu.cpp`, `RemoteVfsFolderModel.cpp`; interface and migration todos in `tanit-mesh-overview.md` §5–6 |
| Phone dial and capture | `android/tanit/.../chat/PhoneVfs.kt`, `DesktopAudio.kt`, `audio/VoiceSetup.kt`, `audio/VoiceGearSheet.kt` |
| Capture format | `packages/audio.cpp/src/source_host.cpp`, `include/pm/audio/stream_gap.hpp` |
| E2EE, not linked | `packages/encryption.cpp` |

## Tests

Run these after a change to the pair row, the gate, the hop, or a dial. Each one uses a private config directory. None of them is the tray.

| Command | What it holds |
|---|---|
| `npm run test:node-serve` | One `node serve`. Health, serve key, vfs, a forged hop is 400, a revoked token is 401, a files grant on audio is 403, a path outside the mount. A confirm stores every grant off. A serve-key announce writes the phone's pair row and `lan/peers.json`. The pair-token announce still writes the caller's row. Revoking the announcer drops that phone from `peers.json` and the Places cache. Revoking the phone drops its own row |
| `npm run test:node-peer` | Two desktops. Pair on the TLS port, pin check, vfs read after a settings grant. A wrong pin sends nothing. A second pair of the same device id moves the revision and the grant that authorizes is the empty one |
| `npm run test:phone-peer` | Two phone listeners. Same pin rule, vfs read, announce onto the pair row |
| `npm run test:vfs-phone` | Desktop dials a phone listener (`test core phone-listener`, the same listener as the app). Pin, restart, cleartext refusal, grant narrow, no socket before a network is granted. An announce with folder access off carries no address. A new pair file makes the old dial token 401 and the next announce carries a new one. A lower inbound revision replaces a cached `write`, and `ENETWORK` names the current vfs |
| `npm run test:agent-lan` | `llm agent --serve` with a bearer. A confirm stores every grant off. Models, audio, and an announce stay 403 until a files grant. Revoke drops `peers.json` and the Places cache |
| `npm run test:audio-pipe` | Two desktops, audio scope, session id, two readers, stale stop, `--audio-rate` default, explicit 16 kHz |
| `npm run test:node-tray` | One node. IPC lists it. A second `node serve` on that port exits. The first still answers, and a forged hop is 400. After the first exits, the port can be served again. A node row with no port is stored on 8092 when this process is the one reading `services.json`, and `--pair` is removed from that row. The agent row keeps its own `--pair`. When 8092 is free, `tray start node` comes back on 8092 and 8093 after a restart and does not open a pairing window |

`PhoneVfsInstrumentedTest` is the on-device pin and grant check. It is not a substitute for the tray process, and the six pair todos do not need it. The both-pin QR exchange stays parked and is not one of these suites.

