# Tanit mesh overview

**Date:** 2026-11-22  
**Status:** a map of what is wired, which direction it runs, and what is still a stand-in. The pair-row contract stays in `tanit-mesh.md`. This file is the boundary list.

One pair protocol. One `PairStore` version 3 row (`allow_peer`). The device id is a `vfs://` label. The TLS pin is separate. `peer_fp` stays empty. `encryption.cpp` stays unlinked.

## 1. Capabilities

A cell is **serve** when that platform mounts the route, **call** when an app on that platform dials it, and **local** when the work never leaves the device. Empty means that direction is not in the tree.

| Capability | Desktop (`node serve`) | Desktop (`llm agent --serve`) | Phone listener | Phone app |
|---|---|---|---|---|
| Folders (`/v1/vfs`) | serve | serve | serve | call, both ways |
| Live mic / speakers (`/v1/audio`) | serve, when `FEATURE_AUDIO_SOURCES` | serve, same flag | not mounted | call the desktop only |
| Live camera / screen (`/v1/video`) | serve, when `FEATURE_VIDEO` and `FEATURE_VIDEO_STREAM`. `video_control` stays off | serve, including `/v1/video/control` | not mounted | no caller |
| Chat and the LLM | not mounted. `/v1/models` is the one exception below | serve | not mounted (`llm` off) | call the desktop agent |
| Tools, host, consent | not mounted | serve | not mounted | call consent and completions on the desktop agent |

`node serve` features are `node_features()` in `packages/server.cpp/src/base/include/pm/server/options.hpp`. The phone listener's feature struct is `phone_features()` in `features.hpp`. Audio and video stay off there until those routes are registered.

### Audio

| Direction | What happens |
|---|---|
| Desktop mic → phone | Voice, source **Remote Audio**. `DesktopAudio.kt` calls the desktop `/v1/audio/sources`, `/start`, and `/stream`. The phone mixes that stream with its own mic and can record the mix. |
| Phone → desktop speakers | Voice, output **Remote Audio**. `DesktopPlayback.kt` calls `/v1/audio/play/start`, `/play`, and `/play/stop` on the desktop. |
| Phone mic, on the phone | Local. `RecorderActivity` / `VoiceActivity` → `jni_pm_voice.cpp` → `pm::audio::session` in `packages/audio.cpp`. The phone listener does not publish this capture. |
| Desktop → desktop | The routes exist. `npm run test:audio-pipe` is the client. No desktop window pulls another desktop's mic. |
| Phone mic → desktop recorder | Missing. The desktop has no client for a phone `/v1/audio`, and the phone does not mount one. |
| Phone → phone | Missing. Same reason. |

The stream is stereo s16le. Rates are 16000, 24000, or 48000. Bits are 16. The grant value on the row is `on` or `off`. The mesh note's older `listen` name is not what `PairStore` writes.

The phone sends the token from the computer QR, stored as the LAN server `api_key` (`DesktopAudio.endpoint` → `LanComputer` / `nativeEnsureServers`). `Service::authorize` in `lan_win.cpp` turns that token into scopes from `allow_peer` on every call. Remote audio is 403 while the desktop's audio switch is off. The phone card cannot turn that switch on.

`/v1/audio/transcriptions` and `/v1/audio/speech` are not this capture. They belong to the llama server and the STT/TTS proxies (`CloudSpeech.kt`). The node's `/v1/audio` prefix would claim those paths if they were registered here. They are not.

`/v1/realtime/start` is a third path. It needs `chat` and `tools`, and it is the agent session. It is not `/v1/audio/stream`. Voice can have the remote mix open while Chat has a realtime session open. They do not share a capture owner in the route table.

### Video

| Direction | What happens |
|---|---|
| Desktop camera or screen → a peer | `node_video.cpp` mounts `/v1/video/status`, `/sources`, `/start`, `/stop`, `/mjpeg`, `/snapshot.jpg`, `/signal`. Capture types live in `packages/video.cpp`. |
| Phone → that desktop stream | No Kotlin caller of `/v1/video`. |
| Phone screen or camera → a file | Local. `ScreenRecorderActivity` uses the Android recorder. It is not a mesh source. `docs/android/video-android.md` keeps that app separate from the Video tab. |
| Phone Video tab | An LLM client. The tab sends a workflow to the desktop agent. It does not open `/v1/video/mjpeg`. |
| Pointer and keys | `/v1/video/control` is on for `llm agent --serve` and off for `node serve` and the phone. |

### Chat (LLM server)

The LLM is a desktop process: `llm agent --serve`. The phone is a client of that process.

| Piece | Role |
|---|---|
| Completions, sessions, models, speak, realtime | Desktop agent routes in `node-features/agent/`. The turn loop stays in `packages/llm.cpp`. |
| Phone Chat | `LanAgentSession.kt` posts `/v1/chat/completions` to the saved LAN server. `PhoneHost.kt` posts `/v1/chat/consent`. |
| A computer pairing code | Stores that LAN server (`lan-agent` + `pair_id`) and remembers the peer via `nativeLanRememberPeer`. `LanPair.kt` / `LanComputer.kt`. |
| `node serve` | `llm`, `tools`, and `host` are off. `/v1/chat/completions` is 404. `/v1/models` is allowed when `lan` is on; no feature flip. |
| Phone listener | `llm` is off. Completions are not registered. |
| Phone → phone chat | Missing. Neither phone mounts the agent. |

Chat on the pair row is a grant (`on` / `off`). It is not a second server. A phone with `chat=off` on the desktop's row is refused by the desktop agent. The phone's own row cannot host the agent.

## 2. Pairing and grants

Each device stores its own `lan/devices.json` (`PairStore` version 3). A new confirm stores every known capability off at revision 1 (`allow_peer` + `allow_peer_revision`). The ticket only decides that the confirm is allowed. Settings is what turns a grant on.

| | Desktop | Phone |
|---|---|---|
| Listener | HTTP on loopback, Schannel TLS proxy on the LAN. Tray node is `node serve` on 8092 / TLS 8093. The agent stays on 8090 / 8091. | `PeerListener`: httplib on 127.0.0.1, mbedtls on the public port. The default range is 8092–8100 (`peer_listener.hpp`). |
| Pair file | `%APPDATA%\PolyMech\tanit\lan\devices.json` | `files/tanit-profile/lan/devices.json` |
| Who edits the grant | Settings → Devices. Folder access is Off / Read / Write. Audio, video, chat, and tools are switches. | Paired devices. Folder access and networks only. `nativeLanSetGrant` writes `vfs` and networks. It does not write audio, video, chat, or tools. |
| What a computer QR does on the phone | — | Saves the LAN chat server. Opens chat. Does not add a paired-device card. |
| What a phone QR does on the other phone | — | `nativeLanRememberPeer` writes the pair row (`urls`, pin, wrapped dial token). |

`allow_peer` on the device that owns the resource is the authority. `inbound` in the mesh note's sketch is not written. A request is allowed only when the serving device's own row says so.

`vfs=write` includes read. Audio, video, chat, and tools do not follow from a folder grant. Revoke keeps the row and clears the caps. **Remove Device** on the phone deletes the row (`PairStore::forget`), the staged `workspace/peers/<id>` tree, and bookmarks whose ref starts with `vfs://peer/<id>/`.

Networks are part of the phone's folder grant. An announce with `vfs=off` or an empty network list carries no address. The desktop dials a phone only after that announce has stored `urls`, `tls_fp`, and a wrapped token.

### Direction is local

Permissions are not implicitly bidirectional.

If desktop D has a row for phone P, `D.devices[P].allow_peer` means “what D allows P to do to resources served by D.” The row on P is a different local decision. It may allow D more, less, or nothing. Neither side may widen the other's policy.

```text
desktop row for phone: allow_peer = what the phone may use on the desktop
phone row for desktop: allow_peer = what the desktop may use on the phone
```

`dial_token`, `urls`, and `tls_fp` point in the other direction: they are how this device makes an outbound request to that peer. Keeping dial material and `allow_peer` on one peer row is useful.

A pair can be mutually reachable without having symmetric permissions. Pairing creates trust and credentials. Both `allow_peer` documents start empty. A later permission request is only a request. The owner must approve it locally.

The current computer-QR path obscures this rule. It stores the desktop-issued token as the phone's LAN server `api_key`, without creating the corresponding phone `PairStore` row. The desktop still makes the authorization decision from its own row. The phone UI cannot show the complete two-direction relationship.

### Current permission shape

The current model is not a bit mask. It is a fixed struct:

```cpp
struct Grant {
    int revision;
    VfsGrant vfs;                    // off, read, write
    std::string audio;               // off, on
    std::string video;               // off, on
    std::string chat;                // off, on
    std::string tools;               // off, on
    std::vector<std::string> networks;
};
```

It still has the limits of a bit mask:

- `grant_scope_known`, `grant_set_scope`, `grant_scopes`, `set_caps`, the Settings RPC, and route policy all know the same closed list.
- Audio capture and speaker playback are one `audio` switch.
- Camera, screen, snapshots, and control are mostly one `video` switch.
- All tools are one switch even though consent is per operation.
- VFS has one level for every published mount.
- A global revision changes when any field changes. The phone VFS stream guard compares that whole revision. An unrelated permission edit can therefore invalidate a VFS operation even when VFS stayed allowed.
- Unknown future permissions cannot round-trip through an older writer. A fixed struct silently makes every writer a schema gate.

### Capability document

Use stable, namespaced capability ids and typed JSON values. The store preserves an unknown capability value exactly. A registry interprets only capabilities this build implements.

```json
{
  "version": 3,
  "allow_peer": {
    "vfs": {
      "revision": 4,
      "level": "read",
      "resources": ["mount:photos", "mount:recordings"],
      "conditions": { "networks": ["192.168.1.0/24"] }
    },
    "audio.capture": {
      "revision": 2,
      "level": "use",
      "resources": ["mic:*", "loopback:*"]
    },
    "audio.playback": {
      "revision": 1,
      "level": "off"
    },
    "video.capture": {
      "revision": 3,
      "level": "use",
      "resources": ["camera:front"]
    },
    "chat.turn": {
      "revision": 5,
      "level": "use"
    },
    "tools.call": {
      "revision": 7,
      "level": "ask",
      "resources": ["filesystem.read", "calendar.*"]
    }
  }
}
```

Capability ids are protocol. UI labels are not. Initial ids:

| Capability | Operations it gates |
|---|---|
| `vfs` | list, stat, read, write, mkdir, move, delete. `level` is off, read, or write |
| `audio.capture` | sources, select, start, stream, stop |
| `audio.playback` | outputs, select output, play, stop |
| `video.capture` | sources, select, start, MJPEG, snapshot, stop |
| `video.control` | pointer and key injection. Separate from capture |
| `chat.turn` | completions, sessions, chat events |
| `chat.realtime` | realtime start, events, PTT, speaker, stop |
| `speech.stt` | transcription |
| `speech.tts` | speak and speech generation |
| `tools.call` | named tool operations. `level=ask` invokes consent |
| `host.open` | open a path or UI on the serving device |

The policy query is semantic:

```cpp
Decision authorize(
    const PeerPolicy& policy,
    std::string_view capability,
    std::string_view operation,
    std::string_view resource,
    const RequestContext& context);
```

It is not `flags & kAudio`. Route registration declares a capability and operation. The handler supplies the concrete resource after parsing the request. For example, the route gate checks `vfs/read`; the handler checks `mount:photos` and the path jail.

Rules:

- Missing capability is deny.
- Unknown capability is stored and returned, but this build cannot authorize it.
- `level=ask` never lets the remote caller edit policy. It starts a local consent decision for this operation (`authorize_peer` + installed prompt; default Deny).
- A capability has its own revision. Narrowing `audio.capture` stops audio capture sessions. It does not stop a VFS read.
- A whole-document generation may still order snapshots. Enforcement and cancellation use the relevant capability revision.
- Resource lists narrow a capability. An empty or missing resource list means all resources published under that capability only when the capability definition says so.
- Conditions hold transport context such as allowed networks. They do not become capabilities.
- Route requirements may be AND or OR, expressed by registration (`chat.realtime` and `tools.call`, for example), not by minting combined scope names.
- The serving device is authoritative. A fetched remote policy is display/cache data and is named `remote_policy_hint`, never `inbound`.

This replaces PairStore version 2 in one schema change. There is no version 2 compatibility reader or second writer. An old file is rejected and the devices pair again.

### Boundaries

- Pairing grants nothing.
- The owner of the microphone, the camera, the folder, or the agent is the one who edits that grant.
- One device's grant does not extend through another device.
- The token identifies the peer. It does not carry the grant. `GET /v1/lan/grant` returns the caller's outbound row.
- Tailscale is a saved address. It is not a pin and it is not a token.
- `encryption.cpp` is not the transport. Direct vfs, audio, and video stay on authenticated TLS. E2EE is only for a file a relay will hold, and that target does not exist yet.
- The QR still carries one pin. The desktop dial book stores the phone pin from the announce. The phone's row for the desktop listener pin is not filled by that same ticket.
- On one computer, the phone listener's default 8092 is the node HTTP port, and 8093 is the node TLS port. Two devices do not share that socket. A `phone-listener` test on the machine that is already serving the node does.

## 3. Band-aids and drifts

These are the places a second book, a dead flag, or an old name is doing the job the pair row was meant to do.

| Drift | What it does today | Shape to aim at |
|---|---|---|
| `lan/peers.json` | Desktop Places and `cp` dial a phone from this file (`src/vfs/phone_peers.hpp`, `phone_client.hpp`). The pair row in `devices.json` is the grant. The dial book is a second file the announce also writes. | One row. Places reads `devices.json` for `urls`, `tls_fp`, and `dial_token`. |
| Computer QR vs phone QR | A computer code becomes the chat server (`LAN_SERVER_ID`, preset `connection=lan`). The `api_key` on that row is the `tn1_` from the confirm, not the desktop serve key. Voice, playback, chat, and the chat-computer folder dial all send it. A phone code becomes a pair row, and the file sidebar dials that row through `nativeLanPeerDial`. | A paired computer is one card and one dial. The serve key stays a local admin credential. |
| `vfs://peer/<id>/` | Android bookmarks and the file sidebar use this ref so Remove Device can find them. The mesh name is `vfs://phone-<id>/<mount>/<path>`. Desktop Places already uses that name. | The phone sidebar uses `vfs://phone-<id>/…`. `vfs://peer/` goes away. |
| `phone_features().audio` and `.video` | Both stay true. `listener.cpp` mounts `/health`, `/v1/lan/pair`, `/v1/lan/grant`, `/v1/lan/phone-vfs`, and `/v1/vfs/*`. No audio or video route. | The flag matches the routes. Audio and video turn on only when the phone listener registers them. |
| Grant names in `tanit-mesh.md` §3 and §6 | The note still says `audio=listen` and `video=watch`. The row stores `on` / `off`. | One vocabulary. The row is `on` / `off`. |
| `inbound` | Drawn in the pair-record sketch. Not stored. The desktop keeps a cached copy of the phone's grant in the dial book (`note_grant` in `phone_peers.hpp`). | The cache is a hint. The serving device's `outbound` is the decision. Drop the sketch field. |
| `/v1/models` on `node serve` | The feature is off, then the handler turns `llm` on for the authorize call so a paired peer can read presets. | Either the route is a node route with its own grant, or it stays on the agent. The one-off flip goes away. |
| Ticket scopes | `--pair-scopes` still exists on the CLI. A confirm stores every grant off. Settings is the grant. | Docs and the CLI stop describing ticket scopes as the stored grant. |
| `Room.grants` | In-memory bits in `encryption.cpp`. `invite` rejects `k_grant_files`. Not the pair grant. | Leave it in the library. No node reads it. |
| Settings bundle | Devices paste, Discover, and the grant layout live in `apps/settings`. The tray shows the last `build:settings:embed`. | Embed after a Devices change, then restart the tray. |
| Both-pin QR | Parked. Direct desktop→phone vfs works because the announce stored the phone pin. The reverse pin is the chat server's fingerprint, saved beside the serve token, not as `tls_fp` on a pair row. | One ticket carries both listener pins, or each side learns the pin on the first pinned dial and writes it on the row it already has. |

## 4. Packages and code

Paths are relative to the repo root.

### Shared

| Package | Keeps | Called by |
|---|---|---|
| `packages/server.cpp` | Routes, `PairStore`, both listeners | Desktop node, desktop agent, phone listener |
| `packages/vfs.cpp` | Jail and path policy. Its own `/api/vfs` server is not the mesh route | `node-features/vfs/vfs.cpp` |
| `packages/audio.cpp` | `SourceHost`, `SinkHost`, and `pm::audio::session` (phone WAV recorder) | `node_audio.cpp`, `jni_pm_voice.cpp` |
| `packages/video.cpp` | Capture and MJPEG | `node_video.cpp` |
| `packages/llm.cpp` | Turn loop, sessions, tools | Agent layer only |
| `packages/commons.cpp` | Config dir, strings, the local secret wrap | Both hosts |
| `packages/encryption.cpp` | Unlinked | Nothing in the node |

### Desktop

| Surface | Code |
|---|---|
| `node serve` | `packages/server.cpp/src/node-core/routes/node_serve.cpp`, `src/cli/pm_image_cmd_node.cpp` |
| Agent on the same gate | `node-features/agent/node.cpp`, `node_chat.cpp`, `node_llm.cpp`, `node_realtime.cpp` |
| LAN proxy, QR, mDNS | `node-transports/desktop/lan_win.cpp`, `lan_qr.cpp`, `mdns_win.cpp` |
| Pair file | `node-core/pair/pair_store.cpp`, `tanit-node/include/lan/pair_store.hpp` |
| Auth | `node-core/auth/desktop_gate.cpp`, `lan_gate.cpp` |
| Phone folders in Places and `cp` | `src/vfs/phone_client.hpp`, `src/vfs/phone_peers.hpp` (`lan/peers.json`) |
| Desktop-to-desktop dial | `src/vfs/peer_dial.hpp` |
| Settings → Devices | `apps/settings/src/settings/PairedDevicesCard.tsx` |
| Tray node | `src/cli/pm_image_cmd_tray.cpp` |
| Live audio routes | `node-features/audio/node_audio.cpp` → `packages/audio.cpp/src/source_host.cpp`, `sink_host.cpp` |
| Live video routes | `node-features/video/node_video.cpp` → `packages/video.cpp` |
| Folder routes | `node-features/vfs/vfs.cpp` |
| File panel Places | `src/win/ui_next/filepanel/FilePanelSourceCatalog.cpp`, `FilePanelLocationMenu.cpp`, `ShellFolderModel.cpp` |
| VFS file-panel provider | `src/win/ui_next/filepanel/RemoteVfsFolderModel.cpp` → `src/vfs/client.hpp`, `phone_client.hpp` |

### Phone

| Surface | Code |
|---|---|
| Listener | `node-core/lifecycle/listener.cpp`, `node-transports/phone/vfs_listener.cpp` |
| JNI | `android/tanit/app/src/main/cpp/jni_pm_settings.cpp`, `jni_pm_voice.cpp` |
| Pair screen | `android/tanit/.../ui/settings/PairingCodeActivity.kt`, `PhoneSharedFolders.kt` |
| Computer code → chat server | `android/tanit/.../chat/LanPair.kt` |
| Announce of this phone's folders | `android/tanit/.../chat/PhoneVfs.kt` → `POST /v1/lan/phone-vfs` |
| File sidebar | `android/tanit/.../ui/FileBrowserActivity.kt`, `ui/files/FileBrowseModel.kt` |
| Dial the chat computer's folders | `android/tanit/.../chat/LanDesktopVfs.kt` (LAN server from `nativeEnsureServers`) |
| Dial a paired device's folders | `LanDesktopVfs.peerEndpoint` → `nativeLanPeerDial` |
| Voice, remote audio in | `android/tanit/.../ui/VoiceActivity.kt`, `audio/VoiceSetup.kt`, `chat/DesktopAudio.kt` |
| Voice, remote audio out | `android/tanit/.../audio/DesktopPlayback.kt` |
| Voice, local mic file | `jni_pm_voice.cpp` → `packages/audio.cpp/include/pm/audio/session/recorder.hpp` |
| Screen recording | `android/tanit/.../ui/ScreenRecorderActivity.kt` (local) |
| Video tab | Chat with `app=video`. See `docs/android/video-android.md` |
| Chat client | `android/tanit/.../chat/LanAgentSession.kt`, `PhoneHost.kt` |

## 5. Places interface

The Windows file panel and the Android file manager are two views of the same product surface.

| Surface | Root | Catalog |
|---|---|---|
| Windows | `filepanel:places` | `FilePanelSourceCatalog::Compose` → `ShellFolderModel::OpenPlaces`; the location menu separately calls `BuiltInSources` |
| Android | Places drawer | `FileBrowseModel.places` plus the asynchronous paired-device rows from `peerPlaces` |

Both surfaces must expose the same mesh rule: a paired device whose folder access is Read or Write has one section named after that device. Its shared mounts are rows under that section. An offline device keeps its last known rows and marks them offline. A refused or removed pair drops them.

### Current Windows behavior

`FilePanelSourceCatalog.cpp` reads `lan/phone-mounts-cache.json` synchronously. `RefreshPhoneMounts` then starts a detached thread and asks every row from `lan/peers.json` for `/v1/vfs/mounts`.

- A successful response replaces that device's cached mounts.
- An unreachable device keeps the cached mounts and adds `offline`.
- A refusal removes that device's cached mounts.
- The new cache is visible the next time Places is built. No refresh message updates the open view.
- Every phone folder uses `section = "Devices"`.
- The label adds the device name only when more than one phone exists.
- `Pair a phone` is a fake Shell location (`tanit:node-pair`) in the same section.
- The location menu appends the `Devices` section twice. The first call already consumes every row, so the second call duplicates it.
- `AddPhonePicturePlaces` lists every mount. Its name and the `dev only` todo no longer describe the function.

The row URI is already the mesh URI: `vfs://phone-<id>/<mount>`. `RemoteVfsFolderModel` parses it as mount `phone-<id>` and path `<mount>/…`; `pm::vfs::Client` dispatches that authority to `phone_client.hpp`. Keep that URI.

### Formal descriptor

Presentation code consumes one descriptor. Discovery and transport do not emit menu rows directly.

```cpp
enum class PlaceKind { Location, Action };
enum class PlaceGroupKind {
    Favorites, Recent, Local, Cloud, Computer, Drive, Device, Shared, Tanit, Ssh
};
enum class PlaceAvailability { Online, Offline, Unknown };

struct Place {
    std::string id;                  // stable row id
    PlaceKind kind;
    PlaceGroupKind group_kind;
    std::string group_id;            // device id for Device
    std::string device_id;           // empty for non-device rows
    std::string title;               // mount label, never decorated with device name
    std::string detail;              // status or secondary address
    std::string uri;                 // empty for Action
    std::string action;              // e.g. pair-device; empty for Location
    PlaceAvailability availability;
    FilePanelItemCapability capabilities;
    std::string icon;
};
```

The exact namespace may live in the VFS package. The contract matters:

- `id` is stable across refreshes. A device mount uses `device:<id>:mount:<mount>`.
- `group_id` is stable data. The rendered group title is the current device name.
- `title` is only the mount label. It never becomes `Pictures (Pixel)`.
- `uri` is canonical and portable. Paired devices use `vfs://phone-<id>/<mount>`.
- An action has `action`, not a URI disguised as a folder. Pairing is `pair-device`.
- `availability` is state. ` · offline` is presentation, not part of the label.
- `capabilities` come from the mount's `can` intersection and the live grant. The UI does not infer Write from the provider type.
- An empty successful mount list renders the device section with “No shared folders”.
- Unknown means the first refresh has not completed. Offline means a known device could not be reached. Refused means remove the rows.

### Snapshot and refresh

Places is a snapshot with a generation:

1. Return local rows and the last accepted remote snapshot immediately.
2. Refresh paired devices in the background.
3. Publish one generation-complete notification.
4. Rebuild an open sidebar in place. Keep selection by `Place.id`.
5. Discard a result from an older generation.

One owner writes the remote snapshot atomically. The menu and the full Places view read the same snapshot. Opening either surface must not start a second concurrent refresh.

Platform UI keeps localization, ordering, icons, and selection. Shared VFS code keeps canonical ids, URI construction, device grouping, availability, and mount capabilities. Android APIs, Windows Shell folders, MTP, Quick Access, and registry cloud discovery stay in their platform adapters.

## 6. Next todos

Rows 1–6 in `tanit-mesh.md` §11 are done. These are the gaps this map still shows.

| | Gap | Status | Done when |
|---|---|---|---|
| 1 | The phone listener's feature flags claim audio and video, and no route exists | done | `phone_features()` has audio and video off until those routes are registered |
| 2 | Places dials `lan/peers.json` while the grant lives in `devices.json` | done | `phone::peers()` prefers dialable rows from `devices.json`; `peers.json` is fallback |
| 3 | The phone treats a computer QR as a chat server and a phone QR as a pair | done (chat transport partial) | Computer QR writes `nativeLanRememberPeer` and the `lan-agent` row keeps the pair id as `pair_id` (`ServerProfile`). Folders, the sidebar's Shared folders, audio, the phone announce, the log shipper, and the Settings chat key resolve through `LanComputer` → `nativeLanPeerDial(pair_id)`. A profile with only the legacy `lan-agent` key falls back to that key. `nativeLanPeerDial` no longer needs `allow_peer.vfs`, because that grant is what the peer may do on this phone, not how this phone dials it. Still open inside this row: the native chat/realtime session reads `base_url` and `api_key` from the `lan-agent` row, not from the pair row |
| 4 | The phone sidebar names folders `vfs://peer/<id>/` | done | New refs are `vfs://<device-id>/<mount>/…`. Old `vfs://peer/` bookmarks still resolve |
| 5 | Paired devices on the phone can edit folders only | done | Card edits folders and networks only. Audio/video stay off in `phone_features` |
| 6 | No client pulls a phone mic or a phone camera, and no phone client pulls desktop video | open | Blocked, not stubbed. `listener.cpp` mounts no `/v1/audio/*` or `/v1/video/*` route and `phone_features()` keeps both off (todo 1). No flag path or thin route exists to build on, and this pass does not invent a mic or camera stack. Needs phone audio/video routes first (gated by `audio.capture` / `video.capture`), then desktop and phone clients |
| 7 | `node serve` flips `llm` on to authorize `/v1/models` | done | `/v1/models` is allowed when `lan` is on. No feature flip |
| 8 | Both listener pins are not in the QR | parked | Same as `tanit-mesh.md` |
| 9 | Windows groups every phone mount under one `Devices` section | done | One section per device name. Pair Device is a separate Pair action |
| 10 | `FilePanelLocationMenu` appends `Devices` twice | done | Second append removed. Device sections are listed once |
| 11 | Windows refreshes phone mounts for the next open only | done | `WM_FILEPANEL_PLACES_READY` rebuilds an open Places view |
| 12 | Windows labels encode offline state and device name | done | Device name is the section. Mount title is clean. Offline is presentation only |
| 13 | Windows remote rows expose only Open/Download | done | `/v1/vfs/mounts` and `/v1/vfs/list` return `can` (`list`, `stat`, `read`, and with write `write`, `mkdir`, `move`, `delete`). `phone_client` narrows it to the routes the client has (`list`, `stat`, `read`), `pm::vfs::List::can` carries it, and `CapabilitiesFromCan` (`PlaceDescriptor.hpp`) builds `FilePanelItemCapability` in `RemoteVfsFolderModel` and Places rows. A phone `write` does not become Upload until the client has a write route |
| 14 | Android and Windows Places models diverge | partial | Windows has the formal descriptor header (`PlaceDescriptor.hpp`: `Place`, `PlaceKind`, `PlaceGroupKind`, `PlaceAvailability`) and `FilePanelSource` carries `id`, `groupKind`, `groupId`, `detail`, `capabilities`, with `ToPlace`. Android `PlaceRow` mirrors `deviceId`, `availability`, `action`. Open: one shared C++ type for both platforms, `groupKind` and `detail` on Android, and an Android "No shared folders" / offline state from the same snapshot |
| 15 | `AddPhonePicturePlaces` obsolete name | done | Renamed to `AddPairedDevicePlaces` |
| 16 | `Grant` is a closed struct | done | PairStore version 3 writes nested `allow_peer`. Unknown capabilities round-trip |
| 17 | `outbound` naming | done | C++ and JSON use `allow_peer`. Version 2 / `outbound` files are rejected |
| 18 | One global grant revision | done | Per-capability revisions. VFS live guard watches `vfs_revision` |
| 19 | Audio/video/chat/tools combine distinct operations | partial | `audio.playback`, `video.control`, `chat.realtime`, `speech.stt`, `speech.tts`, `host.open` are registered ids (`capability_reserved`). They round-trip like unknown ids and `grant_authorize` answers `Unsupported` for them whatever level the file says. They stay off until a route registers them and `Grant` models them. Routes still gate on the combined `RouteGrant` (`/v1/audio` for both capture and playback, `/v1/video/control` as `video`) |
| 20 | VFS permission is peer-wide | done | `vfs.resources` (`mount:photos`, `photos`, `docs*`, `*`) narrows mounts. `LlmVfsAccess::mount_allowed` is set on the phone listener and the desktop peer gate when the list is non-empty. A refused mount is absent from `/v1/vfs/mounts` and answers 404 on list, stat, read, write, mkdir, delete, move, and resolve. Empty or missing means every published mount |
| 21 | Permission requests as remote policy edits | partial | `authorize_peer` is the testable core (default Deny → `EASK`; AllowOnce / Persist*). Desktop `Service::prepare` installs `ensure_win32_mesh_consent_prompt` → ConsentDlg with mesh copy in en/de/es/fr/it/ar/zh (`ConsentDlg_i18n::mesh_strings_for`, follows `appearance.display_language`). Headless stays Deny. Open: Android Compose; async/non-blocking prompt |
| 22 | Route policy uses a flat scope list | partial | `grant_authorize(grant, capability, operation, resource)` is the semantic query. The phone listener's vfs gate, write flag, live guard, and `/v1/lan/phone-vfs`, and the desktop peer's `write` and mount list use it. `grant_scopes` is now a projection of it and stays for `RouteGrant` and the API. Open: express `RouteGrant` as capability and operation per route |

E2EE stays after this list. `encryption.cpp` stays unlinked until a file must sit where the peer is not serving it.
