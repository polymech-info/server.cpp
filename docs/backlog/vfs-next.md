# Phone shared folders

Status: Pairing grants nothing. A folder opens only when that computer was granted the folder and the network the request arrived on. The sections above this file's "Architecture" heading describe the previous slice. Where they disagree with Architecture, Architecture is the current one.

## Drift still open

- The socket is cleartext HTTP. There is no `_tanit._tcp` and no SPKI pin for the phone listener. TLS on the phone would be `lan_android.cpp`, and the desktop TLS stack is Schannel, which does not belong in the APK.
- The authority is `phone-` plus random hex in `phone-node-id`, not an Ed25519 device id. `packages/encryption.cpp` stays unlinked.
- The listener secret is still the desktop serve key. A phone-issued token can be posted as `token`, and a rebuilt `tanit-cli` stores that instead of copying the desktop bearer. The running server does not have that store yet, so the live pair keeps the desktop key.
- `TANIT_VFS_AUTHORITY` is still process-wide `setenv`, set once when the listener binds.

Resolved in this pass: `android/node.cpp` supplies the feature set and the listener refuses to bind when vfs is off. Read does not grant write. Bearer parsing is `pm/server/secret.hpp`. Places no longer invents a Pictures row or copies the address into the process environment. The client reads `lan/phone-vfs.json` and dials an emulator `10.0.2.*` address as `127.0.0.1` on the same port (`adb forward`). httplib is fetched at v0.16.3 when the desktop dependency tree is absent.

The paired device is left as it is. Pairing is not part of this slice.

## Todos

- [x] Record the encryption constraints for the later chat / audio / file / video work. Do not link `packages/encryption.cpp`.
- [x] Seed a granted Pictures folder (`TANIT_VFS_SEED_DIR`) and publish it as `vfs://phone-<id>/pictures`.
- [x] File panel lists that folder when `TANIT_PHONE_VFS_URL` is set (`FilePanelSourceCatalog`, `RemoteVfsFolderModel`). `CustomFileView` shows catalog sources; it does not grow a second browser.
- [x] `tanit-cli cp vfs://phone-<id>/pictures/<file> <local>` reads through `/v1/vfs`.
- [x] `npm run test:vfs-phone` covers desktop to that folder.
- [x] Phone settings lists this phone's own folders. Pictures starts shared. A path with `://` is rejected.
- [x] Places shows Phone pictures under Devices, and desktop bookmarks with Share on under Shared folders.
- [x] Run the vfs listener inside the Android process while a folder is shared. `POST /v1/lan/phone-vfs` stores the address for Places. `TANIT_PHONE_VFS_URL` still overrides when the file is absent.
- [x] Places opens from `lan/phone-mounts-cache.json` and refreshes mounts off the UI thread. Phone listener and desktop client log `[phone-vfs]` lines. `test:vfs-phone` also checks stat, an unknown mount, and `..`. `PhoneVfsInstrumentedTest` hits loopback on the device.
- [ ] Chat, live audio, live video, and files that must sit while the peer is gone. Those follow the rules below. They are not this folder read.

## How a folder is named

The listener still serves `/v1/vfs/*`. `TANIT_VFS_AUTHORITY` replaces the fixed `desktop` host (default stays `desktop`, so the existing desktop share test is unchanged).

| Piece | Value |
| --- | --- |
| Bookmark | `kind=node`, `node_kind=folder`, `share=true`, label `Pictures` |
| Listener mount | `pictures` |
| Browse URI | `vfs://phone-<id>/pictures/<path>` |
| List | `GET /v1/vfs/list?mount=pictures&path=` |
| Read | `GET /v1/vfs/read?mount=pictures&path=<file>` |

`parse_vfs_browse` keeps `vfs://{mount}/{path}`. For a phone, `mount` is `phone-<id>` and the first path segment is the shared folder. `home`, `models`, and `software` still go to the cloud catalog.

The seed is added only when `TANIT_VFS_SEED_DIR` is an existing directory. It is the granted Pictures row for tests. It does not write the user's settings.

`TANIT_PHONE_VFS_URL` is the phone (or the test listener). `TANIT_PHONE_VFS_ID` defaults to `phone-sim` and must look like `phone-<token>`. `TANIT_PHONE_VFS_KEY` is optional; loopback with no serve key stays open.

A phone file copies onto a local path. Copy onto ssh, ftp, or a cloud mount is unchanged and still not a phone hop. Reads stop at 32 MiB.

## Encryption, when this server grows

`packages/encryption.cpp` is not linked into tanit, tanit-cli, or the Android app. The library's own design is the constraint for chat, audio, files, and video later. This folder read does not use it.

Three jobs stay separate. Identity is the pinned handshake. Authorization is the per-peer grant on the device that owns the folder or the capture. Delivery is the channel that matches the bytes. The content type is not a fourth cryptographic switch.

Do not copy these from the library as it stands:

- A room-wide OR of invite bits. A pair grant is one peer, edited on the device that owns it. `Room.grants` is not that grant.
- An unauthenticated handshake (`PM_ENCRYPTION_UNAUTHENTICATED_KX`, or a channel opened with no identity).
- A signal address that is not bound to the identity key.
- One flow key that does not ratchet. `rekey` must drop a key the peer could have kept.
- A room grant treated as a room key. A later member with the bit still cannot read an older file.
- The broker as a place for file or media bytes. It is a small opaque log.

What carries which bytes:

- This slice's list, stat, and read stay inside the phone's TLS listener, with the bearer. They are not relayed through a third device.
- A file that must remain readable after the sender is gone uses FileOffer / FileInbox later, one content key sealed per recipient. Removing a recipient later does not make an older ciphertext unreadable.
- Live mic and camera stay on the existing stream routes while the grant is held. When a forwarder is on the path, that media is SRTP, not a second cipher beside the stream.
- Chat text is a text session pinned to the identity key, not this vfs read and not the unauthenticated channel.
- Narrowing audio or video stops the capture and drops the publisher key. The next listen needs a new epoch.
- The pair row and the platform key (Keystore or CNG) are the durable store. Do not restore a half-open ratchet from a backup. Process death drops the ticket and the capture, not the pair file.

## Affected files

- `packages/server.cpp/src/base/src/vfs.cpp` — authority from `TANIT_VFS_AUTHORITY`; Pictures seed from `TANIT_VFS_SEED_DIR`.
- `packages/server.cpp/src/base/include/pm/server/vfs.hpp` — URI comment.
- `src/vfs/phone_client.hpp` — desktop client for `/v1/vfs` on `vfs://phone-<id>/…`.
- `src/vfs/operations/copy.cpp` — `cp` of a phone file onto a local path.
- `packages/server.cpp/src/tanit-node/android/vfs_listener.cpp` — in-process `/v1/vfs` while a folder is shared.
- `android/tanit/app/src/main/kotlin/com/polymech/pmimage/chat/PhoneVfs.kt` — notification that keeps that process awake.
- `packages/server.cpp/src/tanit-node/desktop/node_lan.cpp` — `POST /v1/lan/phone-vfs` writes `lan/phone-vfs.json`.
- `src/win/ui_next/filepanel/FilePanelSourceCatalog.cpp` — Places reads the last mount list and refreshes it off the UI thread.
- `src/win/ui_next/filepanel/RemoteVfsFolderModel.cpp` — listing for that source. `CustomFileView` uses this model.
- `tests/orchestrator/test-vfs-phone.mjs` — desktop reads the seeded folder, checks stat and a bad path, then `cp`.
- `android/tanit/app/src/androidTest/java/com/polymech/pmimage/PhoneVfsInstrumentedTest.kt` — loopback listener on the phone. Suite name `vfs`.
- `package.json` — `test:vfs-phone`.

## Test

```text
tanit test core phone-vfs --json
```

That probe expects the desktop listener on `127.0.0.1:8090`, then lists a shared folder on the paired phone, reads one small file, and copies the same vfs URI onto a local path. The two local copies must match.

```text
npm run test:vfs-phone
```

The script starts `tanit-cli llm agent --serve` on 127.0.0.1 with `TANIT_VFS_AUTHORITY=phone-sim` and a temp Pictures directory, checks mounts, list, read, stat, an unknown mount, and `..`, then copies `vfs://phone-sim/pictures/seed.txt` with `cp`.

```text
node android/tanit/scripts/run-android-tests.cjs vfs
```

That suite starts the in-process listener, checks `/health`, a missing key, `/v1/vfs/mounts`, and a list of the shared folder, on every device Gradle can see. The write check expects 403. The APK that contains it did not install: the emulator package manager stopped answering. The physical phone was not on adb for that run. The passing `tanit test core phone-vfs` used the listener that was already up.

## Handoff: decide these before more code

Nothing in this section is a decision. The next pass should answer it, then change the pair screen and the listener to match.

### Grants per network

A folder share and a pair scope are not a network grant. Today `share` publishes a folder to whoever can dial the listener. The desktop ticket scope `files` is the other direction: what the phone may do on the desktop. `docs/tanit-mesh.md` says pairing itself grants `vfs=off`, and a later grant is per peer, edited on the device that owns the folder. Neither one names an interface.

The listener binds `0.0.0.0` and then announces a single IPv4. `lan_ipv4` skips `127.0.0.1` and `169.254.0.0/16`, prefers `192.168.0.0/16`, then `10.0.0.0/8`, then `172.16.0.0/12`, and takes anything else last. `100.64.0.0/10` (Tailscale) falls in that last bucket, so a tailnet address loses to Wi-Fi when both are up. The desktop rewrites an announced `10.0.2.0/24` to `127.0.0.1` on the same port because that range is the emulator NAT, and the desktop only reaches it through `adb forward`. One `lan/phone-vfs.json` stores the last announce, so the emulator and the physical phone replace each other.

These prefixes are different grants, and the user never sees the choice:

| Prefix | What it usually is | Open question |
| --- | --- | --- |
| `192.168.0.0/16` | Home or office Wi-Fi | May this paired computer read the shared folders on this LAN? |
| `10.0.0.0/8` except `10.0.2.0/24` | Another private LAN, sometimes a VPN | Same question, separately. A `10.` address is not Wi-Fi just because it won the rank. |
| `10.0.2.0/24` | Emulator NAT | Developer path. It is not a network the user paired. |
| `127.0.0.1` | This machine, or the desktop side of `adb forward` | Loopback tests and the emulator forward. Not a user-facing grant. |
| `172.16.0.0/12` | Private LAN or a container/VPN | Separate grant, same as `10.` |
| `100.64.0.0/10` | Tailscale | The tailnet is a different trust domain from the Wi-Fi the phone is also on. Publishing the Wi-Fi address into the tailnet, or the tailnet address onto the Wi-Fi, are two grants. |
| `0.0.0.0` | The bind, not an announce | The socket currently accepts every interface even when only one address was announced. |

Decide, then show it in the Android pair flow:

- A grant is per peer and per prefix, or per peer only and the prefix is just the current route. Those are different products.
- Turning a folder on does not silently extend it to a network that appeared later (joining Tailscale, changing Wi-Fi, plugging into a new LAN).
- The pair screen lists the interfaces that exist now, with a human name and the prefix, and the user marks which of those this computer may use. A raw IP is the detail, not the only label.
- `127.0.0.1` and `10.0.2.0/24` stay off that screen. They are how tests and the emulator reach the listener.
- Two paired devices need two stored addresses. The last announce must not erase the other.

### Background process

`PhoneVfsService` is a `specialUse` foreground service. The notification says folders are being shared. `START_NOT_STICKY`. `HomeActivity` and `ChatActivity` call `sync` from `onStart`. It is not started from `Application.onCreate`, and it is not restarted by the boot receiver (`ScheduleBootReceiver` is the schedule only). No shared folders means the service stops. Process death drops the socket. The pair file stays. The mesh line "the listener is up while a published mount exists" and the line "a sleeping phone is offline" are both still in force, and they have not been reconciled with Doze.

Still open:

- Leaving the app, with a folder still shared, should keep the notification and the socket, or the phone should go offline until the app is open again.
- After the process is killed, the next open of Tanit is what brings the listener back. Nothing else does.
- A foreground service is the only reason Android does not freeze this process. Whether that service should exist at all depends on the store and company answers below.

### Play store

`specialUse` is a restricted foreground-service type. The manifest subtype is "Serve this phone's shared folders to a paired computer while a folder is shared." Play Console asks for a declaration and a justification, and a long-lived listener is a weak fit for `specialUse`. `dataSync` is for a user-started transfer that finishes. `connectedDevice` is for a device the user paired, and it has its own type rules. Which type this service is allowed to use is not chosen yet.

Also undecided for a store build: cleartext on `0.0.0.0` (the debug network config allows cleartext everywhere; the release config allows it only for localhost, and that config does not govern an inbound server socket), a notification that stays up for as long as a folder is shared, and whether the listener is in the store listing or only in a sideload/company build.

### Company rules

No written rule in this repo says whether a phone may listen on a LAN or a tailnet, or whether `lan/phone-vfs.json` may hold the bearer in plaintext. The constraints already adopted are: do not link `packages/encryption.cpp`, do not log bearers or file bytes, and do not treat a folder share as a write grant. These still need an owner:

- Cleartext on the LAN versus TLS with a pinned SPKI before any company device enables the listener.
- Binding every interface versus binding only the prefixes the user granted.
- The desktop serve key acting as the phone's listener secret. The phone should issue its own token. The running `tanit-cli` does not store that token yet.
- Tailscale as an allowed path for company machines, or as off until someone names it.

## Architecture

One listener, `pm::node::PeerListener`, serves `/health`, `GET /v1/lan/grant`, and `/v1/vfs/*`. The Android app and `tanit test core phone-listener` both start that file. Android only supplies the profile, the phone name, and the interfaces that are up. The vfs routes take a host (`authority`, `roots`, `authorize`) and read no environment variable.

The phone owns `files/tanit-profile/lan/devices.json`. One row is one computer. A new row is `paired`, `vfs=off`, no network, revision 1. The phone issues a `tn1_` token and stores its SHA-256. The desktop serve key is not that token.

Each request is checked in this order, on the phone:

1. The address the request arrived on must sit inside a network some paired computer was granted. Otherwise 403 `ENETWORK`, including `/health`.
2. The bearer must be that computer's current token. Unknown or revoked is 401 `EPAIR`.
3. That computer's own grant must cover this network (403 `ENETWORK`) and must not be `vfs=off` (403 `EGRANT`). `read` is list, stat, and read. `write` adds the mutating routes. A write on a read grant is 403 `EACCES`. Refusals carry the grant revision.

`GET /v1/lan/grant` returns the caller's own row and stays 200 when vfs is off. Edits (grant, revoke, pair again, issue a token) are local: the phone screen, or `tanit test core lan-peer`. No route writes the pair file. The file is read on every request, so the next request sees the edit. A network that appears later is not added. A grant names a network of prefix 8 or tighter, so `0.0.0.0/0` is refused. `127.0.0.0/8` is a real grant, shown as "This phone only", and it is how `adb forward` and the instrumented test reach the listener.

The phone tells the desktop where it listens with `POST /v1/lan/phone-vfs`: `{authority, name, urls[]}`. The urls are only this phone's addresses on networks granted to that computer. The reply is `{ok, authority, token: "held"|"missing"}`. On `missing` the phone issues a token and posts once more, on the same pinned connection the pair already uses. The desktop stores the row in `lan/peers.json`. The token is wrapped with the platform secret (`w1:` plus hex) before it is written. `lan/phone-vfs.json` is removed and is not read.

To open a folder the desktop looks the phone up by `phone-<id>`, asks each announced address for `/health` with no token, and sends the token only to an address that answers with that phone's name. Places reads `lan/phone-mounts-cache.json` and refreshes it off the UI thread. A phone that answers and refuses loses its cached rows. A phone that is only unreachable keeps them.

A computer that was paired before this model has `vfs=off` and no network until those are turned on under Settings, Shared folders.

## Manual testing

Desktop, no phone. Both passed on the current `tanit-cli`:

```text
tanit-cli test core lan-grant --json
npm run test:vfs-phone
tanit test core phone-vfs --json
```

`lan-grant` checks the pair file in process: pairing grants nothing, a token is stored as a hash, one network is not another computer's network, rotation kills the old token, revoke and pair-again start from nothing, the cap is 16. `test:vfs-phone` runs the same listener the phone runs, on `127.0.0.1`, and walks 401, 403 `EGRANT`, 403 `ENETWORK`, read, a refused write, `cp vfs://phone-sim/pictures/seed.txt`, a narrowed grant, revoke, and pair-again. It does not print the token.

On a phone, after the APK that contains this listener is installed:

1. Pair as before. Open Settings, Shared folders. Turn on a folder.
2. Under the paired computer, turn on "Open shared folders" and one network. Wi-Fi, Tailscale, and "This phone only" are separate switches. "Change and delete files" is the write grant.
3. Leave Tanit open so the phone can announce. The desktop must be the paired one, with `tanit` serving LAN (`npm run android:server`), rebuilt so it stores `lan/peers.json`.
4. On the desktop, open Places twice. The first open starts the refresh. The second shows the phone's folder. Copy a file with `cp vfs://phone-<id>/<folder>/<file> <local>`.
5. Turn the network off on the phone. The next copy is refused. Turn the computer off ("Remove this computer"). The next copy is refused, and pairing again does not revive the old token.

```text
tanit test core phone-vfs --json
```

That probe expects the desktop listener on `127.0.0.1:8090` and a phone that has already announced with read and a network this computer is on. It lists one shared folder, reads one small file, and copies the same vfs URI.

```text
node android/tanit/scripts/run-android-tests.cjs vfs
```

That suite is the phone-side walk of the same rules, over loopback, with a pair row the test adds. It needs the new APK. It was not run in the pass that wrote this section.

Still not decided, and not papered over: the phone listener is cleartext HTTP with no SPKI pin, the vfs name is random hex rather than an Ed25519 device id, the desktop's own `devices.json` is not this pair file, a grant matches a whole CIDR, and the foreground-service type for Play is still the open question in the section above.
