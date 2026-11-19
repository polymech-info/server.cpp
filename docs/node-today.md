# Node today

**Date:** 2026-11-19  
**Status:** the code as it compiles now. The planned split is [node-refactor.md](node-refactor.md). Where `encryption.cpp` meets these types is [encryption-seams.md](encryption-seams.md).  
**Reads with:** [README](../README.md) (module index), [docs/tanit-mesh.md](../../../docs/tanit-mesh.md) (design and todos).

Two listeners exist. They share the vfs route table and nothing else.

| | Desktop listener | Paired-peer listener |
|---|---|---|
| Entry | `run_llm_agent_openai_server` in `desktop/node.cpp` | `pm::node::PeerListener` in `peer/listener.cpp` |
| Runs | On the desktop, only inside `llm agent --serve` | On the phone today. The file is portable |
| Transport | HTTP on loopback. A Schannel proxy in front of it for the LAN | Cleartext HTTP on `0.0.0.0`, first free port from 8092 to 8100 |
| Caller is known by | The serve key, a `tn1_` token in `lan_win.cpp`, or open loopback | A `tn1_` token in `PairStore` |
| What a peer may do | Ticket scopes, fixed at pairing: `chat`, `files`, `tools`, `video`, `audio` | The `outbound` grant row. Editable, with a revision |
| Pair file | `lan\devices.json`, `StoredDevice` rows | `lan/devices.json`, `pm::lan::Peer` rows |
| Routes | Every group | `/health`, `/v1/lan/grant`, `/v1/vfs/*` |

Both pair files are named `devices.json`. They are two schemas written by two different files.

## 1. Who compiles what

```mermaid
flowchart LR
    subgraph lib["pm-server-lib, static"]
        V["base/src/vfs.cpp"]
        L["peer/listener.cpp"]
        P["peer/pair_store.cpp"]
    end
    subgraph desk["host-compiled, desktop"]
        N["desktop/node.cpp<br/>node_llm, node_chat, node_realtime,<br/>node_audio, node_video, node_host, node_lan"]
        W["desktop/lan_win.cpp, lan_qr.cpp<br/>pm_server_add_lan"]
        M["desktop/mdns_win.cpp<br/>pm_server_add_mdns"]
        B["shared_folder.hpp<br/>parsed bookmark rows"]
    end
    subgraph phone["tanit_node_phone, NDK"]
        A["android/node.cpp<br/>android/vfs_listener.cpp"]
    end

    T["tanit, tanit-cli, pm-llm<br/>inside if FEATURE_COMMAND_LLM"]
    T --> lib
    T --> desk
    phone -. "same files, by path, not the library" .-> lib
    phone -.-> B
    lib --> C["pm-commons-lib"]
    lib --> S["pm-vfs-lib"]
    lib --> H["httplib, nlohmann_json"]
    N --> LLM["llm.cpp: agent, sessions, consent"]
    E["pm-encryption-lib"]
    E -. "not linked by anything here" .- lib
```

A build with `FEATURE_COMMAND_LLM` off links none of this. That is why `tanit-viewer` cannot be told about a phone folder.

## 2. Classes

### Portable: the route table and the feature flags

`base/`. No environment, no settings store, no agent.

```mermaid
classDiagram
    direction LR

    class ServerFeatures {
        +bool lan
        +bool vfs
        +bool audio
        +bool video
        +bool video_control
        +bool llm
        +bool tools
        +bool host
    }
    class features_hpp {
        <<functions>>
        +phone_features() ServerFeatures
        +route_enabled(features, path) bool
    }
    class secret_hpp {
        <<functions>>
        +constant_time_equal(a, b) bool
        +bearer_token(authorization) string
        +request_bearer(req) string
    }
    class VfsRoot {
        +string name
        +string label
        +string path
    }
    class LlmVfsAccess {
        +bool full
        +bool files
        +bool write
        +string device_id
        +int grant_revision
    }
    class LlmVfsHost {
        +string authority
        +roots() vector~VfsRoot~
        +authorize(req, res, access) bool
    }
    class vfs_cpp {
        <<functions>>
        +register_llm_vfs_routes(svr, host)
        +vfs_authority_valid(authority) bool
        +shared_file_for_path(path, roots, authority)
    }

    features_hpp ..> ServerFeatures
    vfs_cpp --> LlmVfsHost : takes
    LlmVfsHost ..> VfsRoot : roots
    LlmVfsHost ..> LlmVfsAccess : authorize fills
```

The routes read no settings. The node names itself in `authority` and supplies the folders and the authorize callback.

### Portable: the pair file and the paired-peer listener

`peer/`.

```mermaid
classDiagram
    direction TB

    class Grant {
        +int revision
        +VfsGrant vfs
        +string audio
        +string video
        +vector~string~ networks
    }
    class Peer {
        +string id
        +string name
        +string peer_fp
        +string tls_fp
        +string token_sha256
        +Trust trust
        +Grant outbound
        +string created
        +string last_seen
    }
    class Access {
        +Verdict verdict
        +Peer peer
    }
    class PairStore {
        +load(rows) bool
        +find(id, peer) bool
        +ensure_peer(id, name, tls_fp) bool
        +issue_token(id, token) bool
        +set_grant(id, vfs, networks) bool
        +revoke(id) bool
        +repair(id) bool
        +authorize(token) Access
        +any_peer_on(local_ipv4) bool
    }
    class PeerListenerHost {
        +string role
        +string authority
        +path pair_file
        +roots() vector~VfsRoot~
        +enter()
        +log(warn, line)
        +string bind_host
        +int port_first
        +int port_last
    }
    class PeerListener {
        +start(host) bool
        +stop()
        +listening() bool
        +port() int
    }
    class peer_listener_hpp {
        <<functions>>
        +peer_state_json(store, authority, networks)
        +peer_announce_json(store, peer_id, ..., rotate)
    }
    class LlmVfsHost

    PairStore --> Peer : rows in devices.json
    Peer *-- Grant : outbound
    PairStore ..> Access : authorize returns
    PeerListener *-- PeerListenerHost
    PeerListener *-- PairStore : reads the file per request
    PeerListener --> LlmVfsHost : fills it from the grant
    peer_listener_hpp ..> PairStore
```

`Peer.peer_fp` is in the row and nothing writes it. `Trust` is `Verifying`, `Paired`, or `Revoked`. `VfsGrant` is `Off`, `Read`, or `Write`. `audio` and `video` are stored strings that no route checks yet.

### Desktop: the listener and the gate

`desktop/node.cpp` and the route files.

```mermaid
classDiagram
    direction LR

    class AgentServerOptions {
        <<llm.cpp>>
        +string host
        +int port
        +string serve_api_key
        +bool lan
        +int lan_port
        +string lan_name
        +bool pair_on_start
        +string pair_scopes
        +int concurrency
        +ServerFeatures features
    }
    class node_cpp {
        <<desktop/node.cpp>>
        +run_llm_agent_openai_server(opt) int
        -register_routes(svr, opt, gate)
        -require_v1_auth(req, res) bool
        -device_scope_ok(dev, req) bool
        -request_secrets(req)
        -lan_hop_ok(req) bool
        -machine_local_request(req) bool
        -Service g_lan
    }
    class InflightGate {
        +stats() Stats
        +Slot(gate, wait_ms)
    }
    class route_groups {
        <<desktop/node_feature.cpp>>
        +register_llm_routes()
        +register_chat_routes()
        +register_realtime_routes()
        +register_audio_routes()
        +register_video_routes()
        +register_host_routes()
        +register_lan_routes()
    }
    class DeviceAuth {
        +string id
        +string name
        +vector~string~ scopes
        +has(scope) bool
    }
    class Service
    class LlmVfsHost

    node_cpp --> AgentServerOptions : reads
    node_cpp *-- InflightGate
    node_cpp --> Service : g_lan, while --lan
    node_cpp --> route_groups : mounts every group
    node_cpp --> LlmVfsHost : authority desktop
    route_groups ..> node_cpp : calls require_v1_auth
    node_cpp ..> DeviceAuth : device_scope_ok reads scopes
```

Every `node_*.cpp` includes `node_internal.hpp`, and that header includes the agent, the chat plugin, consent, and the session store.

### Desktop: the LAN service and the dial side

`desktop/lan_win.cpp`, and two files outside this package.

```mermaid
classDiagram
    direction TB

    class Service {
        <<lan/tanit_lan.hpp>>
        +prepare(display_name) bool
        +listen(http_host, http_port, tls_port) bool
        +stop()
        +info() PublicInfo
        +hop_matches(presented) bool
        +open_pairing(scopes, ttl_sec, ticket) bool
        +reveal_qr(ticket) string
        +complete_pairing(secret, device, scopes) PairError
        +authorize(token, dev) bool
        +devices() vector~DeviceInfo~
        +revoke(id) bool
    }
    class LanServiceImpl {
        <<desktop/lan_win.cpp>>
        +string fingerprint
        +string hop
        +Ticket ticket
        +vector~StoredDevice~ devices
        +Publisher mdns
        +cert, cred
    }
    class StoredDevice {
        +string id
        +string name
        +string token_sha256
        +vector~string~ scopes
        +string created
        +string last_seen
        +bool revoked
    }
    class RequestForwarder {
        <<TLS proxy, per client>>
        +take(data, n, upstream) bool
        -rewrite(head, out) bool
    }
    class phone_peers {
        <<src/vfs/phone_peers.hpp>>
        +find_peer(authority) Peer
        +store_peer(authority, name, urls, token, owner)
        +note_grant(authority, revision, vfs)
        +forget_peer(authority) bool
    }
    class phone_client {
        <<src/vfs/phone_client.hpp>>
        +grant(device) GrantResult
        +mounts(device) MountsResult
        +list(device, path) ListResult
        +stat(device, path) StatResult
        +read_to_file(device, path, target)
    }
    class node_lan_cpp {
        <<desktop/node_lan.cpp>>
        +register_lan_routes(svr, auth)
    }

    Service *-- LanServiceImpl
    LanServiceImpl *-- StoredDevice : lan/devices.json
    LanServiceImpl *-- RequestForwarder
    node_lan_cpp --> Service : pairing, devices, revoke
    node_lan_cpp --> phone_peers : POST /v1/lan/phone-vfs
    phone_client --> phone_peers : token and urls for the dial
```

`phone_peers` and `phone_client` are the dial side. They are in `src/vfs`, in every build.

## 3. Request flow

### Desktop gate

`require_v1_auth` is a closure inside `register_routes`. Each handler calls it first.

```mermaid
flowchart TD
    R["request on loopback HTTP"] --> F{"route_enabled<br/>for this path?"}
    F -- no --> E404["404 not found"]
    F -- yes --> H{"hop header present<br/>and not ours?"}
    H -- yes --> E400["400 invalid LAN hop"]
    H -- no --> C{"pair/begin, devices,<br/>devices/revoke?"}
    C -- yes --> L{"dialed loopback directly,<br/>no hop header?"}
    L -- no --> E403a["403 local-only"]
    L -- yes --> PASS["handler runs"]
    C -- no --> K{"a presented secret<br/>equals serve_api_key?"}
    K -- yes --> PASS
    K -- no --> D{"g_lan.authorize<br/>accepts a secret?"}
    D -- yes --> SC{"device_scope_ok<br/>for this path?"}
    SC -- no --> E403b["403 insufficient_scope"]
    SC -- yes --> PASS
    D -- no --> O{"no TLS hop and<br/>no serve key set?"}
    O -- yes --> PASS
    O -- no --> E401["401 unauthorized"]
```

Three things do not go through that closure:

- `/health` and `/ready` have no check.
- `GET /v1/lan/info` has no check. `POST /v1/lan/pair` runs its own hop test and then the ticket.
- The vfs group has its own `authorize`, built in `register_routes`. It repeats the hop, serve key, token, and open-loopback steps and asks for `files`.

None of those three consult `route_enabled`. Setting `features.vfs` or `features.lan` to false does not turn those paths off on the desktop.

`device_scope_ok` ends in `return false`. A path with no row is refused for every paired device. `POST /v1/lan/phone-vfs` has no row.

### Paired-peer listener

Three checks, on the device that owns the folders. `PairStore` reads the file on every call, so an edit applies to the next request.

```mermaid
flowchart TD
    R["request, cleartext HTTP"] --> EN["host.enter<br/>Android pins the profile"]
    EN --> N1{"1. local address is inside a network<br/>some paired peer was granted?"}
    N1 -- no --> X1["403 ENETWORK<br/>no route runs"]
    N1 -- yes --> RT{"path"}
    RT -- "/health" --> OK1["200 role, authority"]
    RT -- "/v1/lan/grant, /v1/vfs/*" --> T{"2. bearer is a token<br/>in the pair file?"}
    T -- "unknown or revoked" --> X2["401 EPAIR"]
    T -- paired --> N2{"3. this peer's grant<br/>names this network?"}
    N2 -- no --> X3["403 ENETWORK + revision"]
    N2 -- yes --> Q{"route"}
    Q -- grant --> OK2["200 the caller's outbound row"]
    Q -- vfs --> G{"outbound.vfs"}
    G -- off --> X4["403 EGRANT + revision"]
    G -- "read or write" --> AC["LlmVfsAccess: files,<br/>write only when vfs is write"]
    AC --> J["vfs.cpp: mount lookup, jail, Store"]
    J -- "a mutating route without write" --> X5["403 EACCES + revision"]
```

`ServerFeatures` is not consulted per request here. `android/vfs_listener.cpp` checks `android_listener_features().vfs` once, before it starts the listener.

## 4. Sequences

### A phone pairs with a desktop

```mermaid
sequenceDiagram
    autonumber
    participant U as Desktop user
    participant N as Node HTTP
    participant S as lan Service
    participant X as TLS proxy
    participant P as Phone

    U->>N: POST /v1/lan/pair/begin, local only
    N->>S: open_pairing(scopes, ttl 300)
    S-->>N: ticket: secret, tanit://pair uri, QR
    N-->>U: QR on screen
    P->>X: TLS connect to the LAN port
    Note over P,X: The phone compares the SPKI SHA-256 with fp from the QR
    P->>X: POST /v1/lan/pair with the secret
    X->>N: same request plus the hop and peer headers
    N->>S: complete_pairing
    S->>S: scopes, new tn1_ token, hash into devices.json
    S-->>N: PairGrant
    N-->>X: 200 token, device_id, fingerprint, scopes
    X-->>P: same body, inside TLS
    Note over P: The token plaintext exists once
```

The body of step 6 is the secret, `device_id`, `device_name`, and the scopes the phone asks for. The stored scopes are the offered ones intersected with those. The proxy drops any `X-Tanit-Lan-Hop` or `X-Tanit-Lan-Peer` header the client sent and writes its own. The node treats a request as a phone when the hop header matches. Eight wrong secrets lock the ticket for 30 seconds.

### A phone shares a folder, and the desktop reads it

```mermaid
sequenceDiagram
    autonumber
    participant UI as Phone UI
    participant PS as PairStore
    participant PL as PeerListener
    participant DN as Desktop node
    participant PC as phone_client

    UI->>PS: phone_lan_ensure_peer(desktop TLS fp)
    Note over PS: New row: paired, vfs off, no network, revision 1
    UI->>PS: phone_lan_set_grant(id, read, one network)
    UI->>PL: phone_vfs_sync(profile)
    Note over PL: Starts only when a bookmark has share set
    UI->>PS: phone_lan_announce(id, name, rotate)
    PS-->>UI: authority, name, urls, the new token once
    UI->>DN: POST /v1/lan/phone-vfs
    Note over UI,DN: Only the serve key passes today
    DN->>DN: store_peer into lan/peers.json
    DN-->>UI: 200 token held or missing
    PC->>PL: GET /health on each announced url, no token
    PL-->>PC: role, authority
    Note over PC,PL: The first url whose authority names this phone gets the token
    PC->>PL: GET /v1/lan/grant with Bearer tn1_
    PL->>PS: authorize(token), then the three checks
    PL-->>PC: the outbound row
    PC->>PL: GET /v1/vfs/mounts, list, stat, read
    PL-->>PC: file bytes
```

The first three participants are on the phone. Kotlin calls them over JNI. The last two are on the desktop.

Step 6 goes through the desktop TLS proxy. A pair token is refused there because `device_scope_ok` has no row for that path.

Everything `phone_client` sends is cleartext HTTP. The token and the file bytes are readable on that network. The address that receives the token is chosen by an unauthenticated `/health` answer.

## 5. State on disk

| File | Device | Written by | Holds |
|---|---|---|---|
| `lan\identity.json` | Desktop | `lan_win.cpp` | SPKI SHA-256 of the RSA key in container `TanitLanIdentity.rsa.v1`. A change revokes every device row |
| `lan\devices.json` | Desktop | `lan_win.cpp` | `StoredDevice`: id, name, token hash, ticket scopes, revoked. At most 64 |
| `lan\peers.json` | Desktop | `src/vfs/phone_peers.hpp` | Phones this computer may dial: authority, urls, the phone's token wrapped by secure storage, cached grant |
| `lan/devices.json` | Phone | `peer/pair_store.cpp` | `Peer`: id, name, `peer_fp`, `tls_fp`, token hash, trust, `outbound`. At most 16 |
| `phone-node-id` | Phone | `android/vfs_listener.cpp` | `phone-` plus 16 random hex. The vfs authority |

In memory only: the pairing ticket, the hop secret, the `InflightGate` counters. No Ed25519 key exists on either side.
