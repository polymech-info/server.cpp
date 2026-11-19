# Tanit mesh

**Date:** 2026-11-19  
**Status:** design and tracking for the node. The code is `packages/server.cpp`. Shipped: `PairStore` version 2 as the only pair file, `tanit-cli node serve` (lan and vfs), the phone listener, `/v1/vfs` on both sides, and the desktop browser for a phone folder. `llm agent --serve` is the same listener with the agent routes mounted. The phone listener terminates TLS, and the desktop dials it with the certificate pin. Desktop-to-desktop uses the same pair row. A phone dials another phone with the phone TLS client and that same row. When a phone tells a paired peer where it listens, that peer stores the address, pin, and wrapped token on the pair row. The desktop also keeps `lan/peers.json` so Places can open the phone folder. The pairing screen is still open. Section 10 is the listener split. Section 11 is the order of work.  
**Reads with:** `packages/server.cpp/README.md` (module index), `packages/server.cpp/docs/node-today.md` (what compiles now), `android/vfs-next.md` (the phone-folder slice log and manual tests), `packages/llm.cpp/docs/llm-server.md` (the agent routes), `docs/phone-mesh.md` (the longer product sketch), `packages/encryption.cpp/docs/design.md`.

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
    "outbound": { "revision": 4, "vfs": "read", "audio": "off", "video": "off", "chat": "off", "tools": "off" },
  "inbound":  { "revision": 2, "vfs": "read", "audio": "listen", "video": "off" },
  "created": "2026-11-17T12:00:00Z",
  "last_seen": "2026-11-17T12:04:11Z"
}
```

The file on disk is `{"version": 2, "identity", "devices"}`. `outbound` is what this device allows that peer to do. `vfs` is `off`, `read`, or `write`. `audio`, `video`, `chat`, and `tools` are `on` or `off`. This file is the authority for those resources. `inbound` in the sketch above is not written. A request is allowed only when the serving device's own `outbound` says so. `urls` and `dial_token` are how this device dials that peer. `dial_token` is wrapped. It is not `token_sha256`. Desktop-to-desktop stores both directions on this row. A phone announce stores the same fields on the caller's row. Places still opens a phone folder from `lan/peers.json`.

The token authenticates the peer. It does not carry the grant. `GET /v1/lan/grant` returns the caller's `outbound` row. The user edits grants on the device that owns the resource. That edit is local. There is no route a peer can call to raise what they are allowed to do.

Trust is `verifying`, `paired`, or `revoked`. An empty grant on a `paired` row means the peer is still paired and can refresh `GET /v1/lan/grant`. `revoked` rejects the token. Those are different states: a stolen token still follows later grant edits, and only revoke drops the hash.

Same device id with a new TLS pin is an endpoint change: update `tls_fp` after the peer proves it still holds the token, and do not revoke the row. A new installation is a new device id: revoke the old row. Key rotation, once a long-term key exists, updates `peer_fp` and keeps the id. The id is not derived from the key.

Caps stay small. The desktop listener already refuses the 65th device. A phone caps at 16 peers.

## 3. Permissions

Three grants, each directed, each editable after pairing. Pairing itself grants none of them. The first successful confirm stores `vfs=off`, `audio=off`, `video=off` at revision 1. This matches desktop bookmarks, where `share` defaults off, and the desktop ticket, where `audio` and `video` are opt-in.

| Grant | Values | What the peer may do |
|---|---|---|
| `vfs` | `off`, `read`, `write` | `write` includes read, mkdir, and delete inside a published mount. The jail is that mount |
| `audio` | `off`, `on` | Open this device's microphone sources. The stream format stays 48 kHz stereo s16le, the contract `/v1/audio/stream` already uses. The publisher adapts its capture to that format |
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

Each outbound edit increments `revision`. The counter is the order. A wall-clock timestamp is not: a peer with a wrong clock must not restore an older `write` by replaying an announcement. The peer applies a grant document only when `revision` is greater than the cached one. The serving device does not consult that cache when it allows a request.

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
packages/server.cpp/
  src/base/
    include/pm/server/      features.hpp, secret.hpp, vfs.hpp
    src/vfs.cpp             /v1/vfs/*. Authority, roots, and authorize are arguments
  src/tanit-node/
    include/lan/            pair_store.hpp
    include/pm/node/        node.hpp, peer_listener.hpp, phone_vfs.hpp
    include/pm/server/      shared_folder.hpp turns parsed bookmark rows into mount roots
    peer/                   pair_store.cpp, listener.cpp (the agent-free listener the phone runs)
    desktop/                node.cpp and node_<feature>.cpp, lan_win.cpp, lan_qr.cpp, mdns_win.cpp
    android/                node.cpp, vfs_listener.cpp
  cmake/host.cmake          pm_server_add_lan, pm_server_add_mdns
```

`pm-server-lib` is `vfs.cpp`, `listener.cpp`, and `pair_store.cpp`. It does not include `src/`. Every other file in the tree reads the settings store or the agent, so the host target compiles it. That is the tree that compiles now. After the split the same files sit in `node-core`, `node-transports`, `node-features`, and `node-e2ee`, listed in `packages/server.cpp/docs/node-refactor.md`.

| Package | Keeps | The node calls |
|---|---|---|
| `packages/server.cpp` | Route tables, the pair file (`devices.json` hash, grant, revision), both listeners | — |
| `packages/llm.cpp` | Turn loop, sessions, tools, speak, realtime, chat fields on `AgentServerOptions` | `run_one_completion` and the session store, from the agent layer only |
| `packages/vfs.cpp` | `Store`, jail, path policy. Its own `/api/vfs` server stays. It is not the mesh route | `list`, `stat`, `read`, `write`, `mkdir`, `delete` |
| `packages/audio.cpp` | `SourceHost`, `SinkHost`, the 48 kHz contract | status, sources, start, stream, play |
| `packages/video.cpp` | Capture, MJPEG, the streaming session | status, sources, start, mjpeg, snapshot |
| `packages/commons.cpp` | Config dir, paths, strings, logging, the local secret wrap | those helpers |
| `packages/encryption.cpp` | Independent library, its own tests and vectors. It does not include `server.cpp` | nothing yet. Only `node-e2ee` links it, and `node serve` does not |

Two things in this section are still plan, not code. Routes are registered and then refused: `route_enabled` answers 404 before the handler when the feature is off. The desktop listener is one function inside the agent build. Section 10 splits it.

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
| 3 | Move scope checks for `files`, `audio`, and `video` off the frozen ticket and onto `outbound`, so a desktop can narrow them without a re-pair. `chat` and `tools` stay as they are | Done. `PairStore` version 2 is the desktop file. `files` is vfs write. `chat` and `tools` are explicit `on`/`off` capabilities |
| 4 | Phone listener with `llm`, `tools`, and `video_control` off. Grant, vfs mounts, `vfs://phone-<id>/...` | Done for vfs: `pm::node::PeerListener`, `PairStore`, per-network grants, TLS on the public port. `/health` has no authority. NSD is still open. The phone id is random hex |
| 5 | Desktop browser for that URI, dialing the phone with the token the phone issued | Done: Places, `cp`, `lan/peers.json`. The dial is pinned HTTPS. A wrong pin sends no token |
| 6 | Phone-to-phone on the same LAN, same records | The dial is the phone TLS client and the pair row. An announce stores that row. `test:phone-peer`. Places still reads `lan/peers.json`. The pairing screen is still open |

Live `audio` and `video` reuse the existing start/stream routes once the grant check is per pair and those routes are not compiled inside the agent. `encryption.cpp` stays unlinked until phase 5, and then only for a feature that needs it.

## 10. Node without the agent

### Why

A desktop receives a phone folder in three steps: the phone pairs with the desktop's LAN proxy, the phone announces its listener on `POST /v1/lan/phone-vfs`, and the desktop stores a row in `lan/peers.json`. After that the file panel and `cp` dial the phone. The dial side (`src/vfs/phone_client.hpp`, the Places catalog) is in every build. The receive side is in one function, `run_llm_agent_openai_server`, and that function is compiled only with `FEATURE_COMMAND_LLM`. `tanit-viewer` builds with that flag off. A viewer can read a phone folder and can never be told about one.

`tanit-cli node serve` is that receive side with `llm` unmounted. It is compiled when `FEATURE_COMMAND_NODE` is on. The link is `FEATURE_COMMAND_LLM OR FEATURE_COMMAND_NODE`. The viewer preset leaves `FEATURE_COMMAND_NODE` off, so a viewer can still read a phone folder and cannot be told about one. The notes below are the split that got here:

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

### What stays out of the mechanical move

The interfaces and CMake source ownership land first. The mechanical move then changes paths without changing which bytes a paired peer can see, so it temporarily preserves today's open-loopback pass. The following router-gate commit removes that pass. No commit takes a link on `pm-encryption-lib`.

- **Audio and video groups.** `node_audio.cpp` and `node_video.cpp` include the agent header, so they cannot move in the behavior-preserving commit. Phase 4 moves them. They do not stay in the agent layer. A node with `llm` off still serves a microphone or a camera when the binary has capture and the feature is on.
- **`/v1/logs`.** It forwards phone logs to VictoriaLogs through a helper in `llm.cpp`. It leaves `node_lan.cpp` for `node_logs.cpp` in the agent layer. On a plain node it is 404, and `LanLogShipper` must treat that as "no log sink".
- **The desktop pair schema.** Done in phase 3. `PairStore` version 2 is the only writer. A leftover ticket-scope file is imported once. `tls_fp` is the peer listener pin. The dial book stores the phone pin. The phone's row for the desktop pin waits on the QR exchange.
- **Phone TLS.** The public port is mbedtls, one socket per granted address. httplib stays on loopback. The certificate is the PEM beside the pair file. No granted address means no public socket.
- **A start button.** The viewer has no UI that starts the node. The tray service list has an `llm-agent` row. A `node` row follows phase 2.

## 11. Todos

The node is secure without `encryption.cpp`. That library is an optional feature target. It is not a dependency of `pm-server-lib` or of `node serve`, and it is not how vfs gets a secure socket.

The commits that reach these exits are in `packages/server.cpp/docs/node-impl.md`. Each commit leaves every target that owns a touched source linking and `test:vfs-phone` passing. The security checks run with `llm` compiled in and compiled out, on the desktop and on Android: a spoofed `/health`, a missing or wrong pin, a redirect or cleartext downgrade, a replayed token, a revoked peer that still holds a stream, a feature that is off, a grant used on a route it does not cover, a vfs path outside the mount, and a hop header the proxy did not write.

### Already due

The pair store and the bookmark files moved after the last link.

- [ ] Relink `tanit` and `tanit-cli`.
- [ ] Build `tanit_node_phone` with the NDK. Its source list changed.
- [ ] `CMakePresets.json` for the standalone `pm-server` CLI, then `npm run test:pm-server`.
- [x] `PairStore` reads `audio`, `video`, `chat`, and `tools`, replaces an existing Windows file, and keeps the phone cap at 16 and the desktop cap at 64.

### Phase 1 — Secure transport

Exit: a desktop reads a phone folder only after the phone certificate pin matches. `/health` does not choose the phone.

- [x] The phone listener terminates TLS. httplib stays on 127.0.0.1. mbedtls serves the public port with an app-private P-256 PEM beside the pair file (`listener.key`, `listener.crt`). The same files are reused after a restart. Announce URLs are `https://` and the body carries `tls_fp`. `/health` returns `role` and does not return `authority`.
- [x] The desktop dialer stores that pin, refuses `http://`, and does not follow a redirect when the pin is set. The token is attached only after the pin check. A wrong pin sends no vfs request. `test:vfs-phone` covers the pin, the restart, the cleartext public port, and the http refusal.
- [ ] The QR transaction still has to exchange both listener pins before pairing succeeds. Parked. The phone's row for the desktop pin is not filled by that exchange yet. A missing pin on the dial book is already a refusal.
- [x] The same PEM listener runs on a connected arm64-v8a phone (`PhoneVfsInstrumentedTest`). The pin is the same after stop and start. Deleting `listener.key` and `listener.crt` mints a new pin. No grant means no public socket. The public port is not cleartext HTTP. cpp-httplib does not hold the key.
- [x] One public socket per granted local address, one port, one handler. No granted address means no public socket. A grant change replaces the set. `test:vfs-phone` sees no listener before a network is granted, no listener after that network is removed, and one socket again when another computer is granted the same network.
- [x] A hop header is accepted only from loopback and only when it is the proxy's secret. Any other hop is 400. The hop is not a capability. `test:node-serve` sends a forged hop and gets 400.
- [ ] Tests still open: upgrade, a package uninstall, armeabi-v7a, and a redirect. Done on the phone: restart, a new pin after the key files are removed, no socket without a grant, and cleartext on the public port. Desktop already covers a wrong pin and a forged hop.

### Phase 2 — Node core split

Exit: `tanit-cli node serve` runs in a build with `FEATURE_COMMAND_LLM` off, and a viewer can be told about a phone folder.

Add the interfaces and source ownership before moving files. The move is then mechanical and does not change which bytes a paired peer can see. The following gate commit removes the pass `register_routes` gives a loopback caller with no credential. That pass is not copied.

- [ ] Add `ListenOptions`, `RoutePolicy`, `RequestContext`, `Router`, and `DesktopLayer` as behavior-preserving adapters at the current paths. Principal kinds are `RemotePair`, `ServeKey`, `LocalAdmin`, and `LocalAgent`. A local agent is injected only by an in-process call, has explicit capabilities and consent, and is never inferred from loopback.
- [ ] Add explicit CMake source groups for core, desktop transport, vfs, and agent while files remain at their current paths. Every owning target uses those groups.
- [ ] Then move into the directories in `packages/server.cpp/docs/node-refactor.md`, updating every source list in that commit. `node-core` gets the listener, router, auth, and `PairStore`. `node-features/agent` gets the completion gate and `/v1/logs`. `node-transports/desktop` gets the TLS proxy. Audio, video, and control stay put until phase 4. No `llm/` include in `node-core`.
- [ ] Switch to the router gate after the move. No `layer.scope`, and no `AuthFn` handed to a feature. Unknown `/v1/` is 404 and unauthenticated loopback is refused.
- [ ] `POST /v1/lan/phone-vfs` accepts a paired device with `files`. Tickets offer only scopes whose feature is on.
- [x] CMake: `FEATURE_COMMAND_NODE`, `pm_server_add_desktop_node`, and the three link blocks leave `if(FEATURE_COMMAND_LLM)`. Reconfigure with `node scripts/cmake.mjs --preset release-debug`. No `pm-encryption-lib` in that link.
- [x] CLI: `node serve`, `node devices`, `node revoke`. `Cmd::Node`, `ProcessKind::Node`.
- [x] `test core phone-listener` loses its `FEATURE_COMMAND_LLM` guard.
- [ ] Tests. `test:node-serve` covers `/health` as `tanit-node`, vfs with the serve key, completions and models 404, a files announce into `lan/peers.json`, a second pair id 409, and loopback vfs and pairing admin without a credential. `test:vfs-phone` passes. Still open: the same announce against `llm agent --serve`, `test:vfs-copy`, and `test:service`.
- [ ] Viewer feature set turns `FEATURE_COMMAND_NODE` on. Build the viewer and run `test-node-serve` against it.
- [ ] `packages/server.cpp/README.md` module table, `packages/llm.cpp/docs/llm-server.md` pointer, `npm run android:server -- --node`.
- [x] Tray `node` service row and a pair entry in the file panel, so a viewer user never opens a terminal.

### Phase 3 — One trust model, one route policy

Exit: the desktop and the phone enforce the same grants, and a route nobody registered is 404 on both.

- [x] `PairStore` version 2 is the only pair schema either host writes. There is no compatibility reader and no second writer. A desktop file that still has ticket scopes (`v`, `scopes`, `revoked`) is imported once: identity, ids, token hashes, timestamps, revocation, and scopes are kept, `files` becomes vfs write, and `audio`, `video`, `chat`, and `tools` become explicit capabilities. An invalid id or an unknown scope leaves that file untouched. The write backs up, flushes, and replaces. `peer_fp` is not filled in.
- [x] The device id stays the `vfs://` label. `tls_fp` is a field on the row and stays empty until the listener pin is known. The id is not derived from a key, and there is no `pm::room` step after the QR ticket.
- [x] A long-term device key is recorded only after Windows and Android both have a non-exportable key the process can sign with. Ed25519 is not assumed. `peer_fp` stays empty until then. Section 9 step 2, as restated there.
- [x] Desktop and phone both use `route_grant`. The phone still admits a peer by token and network, then applies that grant. A `/v1/` path the phone did not enable is 404. `route_enabled` does not treat an unknown `/v1/` path as `llm`.
- [x] The serve key is limited to `serve_capabilities` from startup. `node serve` grants `files`. The agent grants `files`, `audio`, `video`, `chat`, and `tools`. A key cannot call a route outside that set. Local admin routes still require that key on a request the proxy did not forward.
- [x] Local admin is the process IPC socket or the serve key on a request the proxy did not forward. IPC action `pair` opens a ticket without that key. A loopback HTTP call with no key is not admin.
- [x] A live call registers under its peer, capability, and accepted grant revision. Revoke cancels that peer's calls. Narrowing folder access cancels `files` calls. An upload re-reads the grant between chunks, deletes the partial file, and does not publish it. An audio stream stops on that cancel, and re-checks the pair token while it runs.
- [x] `test:node-serve` covers a revoked token (401), a `files` grant on audio (403), video control while that feature is off (404), and a `..` path that does not list the parent. `lan-grant` cancels a live session when the grant narrows. `test:vfs-phone` covers the parent path and a write after the grant is narrowed. A multi-chunk microphone capture is not in the orchestrator. Old-schema migration is not a test.

### Phase 4 — Features that are not the agent

Exit: vfs, audio, and video answer on a node with `llm` off, when the binary contains them.

- [x] `node-features/audio` and `node-features/video` include the capture headers and the node gate, not the agent header. `node serve` mounts them when the binary has capture, and its serve key gains `audio` and `video`. `video_control` stays off, including on the phone. Pointer control stays in the video host; it is not a separate feature file yet.
- [x] Body size and worker count are host listener settings, with hard defaults. `node serve` uses 9 MiB and 8 workers. The phone listener uses 9 MiB and 4 workers. The agent process sets 500 MiB and keeps its turn gate, default 32, on LLM routes only. A vfs write over 8 MiB is refused by vfs. A stream is not a request body, so it takes none of those caps.
- [ ] WebRTC is not a host setting and not a feature. `node-transports/webrtc` stays empty until a media path needs signaling. When that path exists, the host mounts an authenticated signaling route and checks the negotiated fingerprint against the pair. Media stays on SRTP. No `PMD1` wrapper.

### Phase 5 — One E2EE use

Exit: bytes stored where the peer is not serving them are ciphertext there. `node serve` still links no `encryption.cpp`.

- [ ] An E2EE feature target links the node and `pm-encryption-lib`. `pm-server-lib` does not.
- [ ] The first use is `FileOffer` / `FileInbox` for one file that a relay or another store will hold. That store never sees the plaintext. Direct vfs stays on TLS and the pair row.
- [ ] `Handshake`, `TextSession`, `SecureFlow`, `SignalEndpoint`, `Broker`, and `pm::host::Device` stay out of the node until a feature has a requirement TLS, the file envelope, or WebRTC cannot meet.

The in-process agent became `LocalAgent` in phase 2. It has capabilities and consent, but no pair row, room membership, or bearer token.

### Phase 6 — Remove the duplicates

Exit: one gate, one `devices.json` schema, and no protocol linked into the node that no feature calls.

- [ ] The ticket-scope parser in `lan_win.cpp` is only the one-shot import. Delete it once no desktop file still needs that pass, and delete the open-loopback pass if any caller of it remains.
- [x] Desktop-to-desktop uses the pair row. One desktop pairs to the other's pinned TLS port, stores that pin and the wrapped token, and reads `/v1/vfs` only after the pin matches. A wrong pin sends no vfs request. `test:node-peer`. The device id is a 16-hex label in `identity.json`. It is not the TLS fingerprint.
- [x] Two phone listeners use the pair row. One dials the other with the phone TLS client, stores the pin and the wrapped token, and reads `/v1/vfs` only after the pin matches. A wrong pin sends no vfs request. `test:phone-peer`.
- [x] An announce from a paired peer stores that peer's address, pin, and wrapped token on the pair row. The desktop also writes `lan/peers.json` so Places can open the phone folder. A phone listener accepts the same post. `test:phone-peer` and `test:node-serve`.
- [ ] The pairing screen where one phone shows the ticket is still open.
- [ ] Drop any `encryption.cpp` entry point the node gained and then did not call. The library's own tests keep it.
