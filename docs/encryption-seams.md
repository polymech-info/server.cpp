# Where encryption.cpp attaches

**Date:** 2026-11-19  
**Status:** snapshot from before the architecture pass. Nothing links, and [tanit-mesh.md](../../../docs/tanit-mesh.md) section 7 keeps it that way: `pm-server-lib` does not link `pm-encryption-lib`. The handshake-over-a-route sequence and the second pairing step below are not the plan. Phase 5 uses `FileOffer` for one file a relay will hold. The class map of the types that exist is still the map.  
**Reads with:** [node-today.md](node-today.md), [encryption.cpp README](../../encryption.cpp/README.md), [design.md](../../encryption.cpp/docs/design.md), [protocol-model.md](../../encryption.cpp/docs/protocol-model.md).

The library holds protocol state and no socket, file, or key store. The node holds the socket, the pair file, and the grant. A feature that needs both links both. The node library does not link the crypto library.

## 1. What the library asks of a host

| Library type | The host must supply | Node today | After section 10 and section 9 steps 3 and 2 |
|---|---|---|---|
| `Identity` | A 32-byte seed on every start. The type has `generate` and `from_seed`, and no export | Nothing. The desktop identity is the TLS key. The phone id is random hex in `phone-node-id` | A seed wrapped by the platform store. The device id is derived from the public key |
| `Handshake`, `TextSession` | The peer's 32-byte Ed25519 key before message 1, and one context string | `Peer.peer_fp` is in the row and empty. `StoredDevice` has no field | The pair row holds the key on both devices |
| `SecureChannel` | A place to keep the object between two requests. One caller at a time | Neither listener keeps per-peer memory | A session table beside the pair store. Memory only |
| `pm::room` pairing | A way to carry the offer and the accept, and a screen for the fingerprint | The ticket exchange only | A second step after the ticket |
| `FileOffer`, `FileInbox` | Storage for chunks | Not on this path | Used when the bytes sit somewhere the peer is not. Direct vfs stays on the pair row |
| `SecureFlow` | A flow id, a scope, an epoch | Not on this path | Live audio and video stay on the stream routes. `PMD1` is the test host's envelope |
| `LogSink` | A sink. The library has no global logger | The listeners log through `logger` and `PeerListenerHost.log` | `CommonsLog` forwards to `pm::log` when the include path has it |

Not used by a mesh host: `SecureChannel::initiator` and `responder` without an identity, `SignalEndpoint`, `Broker`, `Room.grants`, `pm::host::Device`.

## 2. Classes at the seam

`exists` is this package. `pm encryption` and `pm room` are the library. The three marked `proposed` do not exist.

```mermaid
classDiagram
    direction TB

    class PairStore {
        <<exists, pm lan>>
        +authorize(token) Access
        +find(id, peer) bool
        +revoke(id) bool
    }
    class Peer {
        <<exists, pm lan>>
        +string id
        +string peer_fp
        +string tls_fp
        +string token_sha256
        +Trust trust
        +Grant outbound
    }
    class PeerListenerHost {
        <<exists, pm node>>
        +string authority
        +path pair_file
        +roots()
        +enter()
        +log(warn, line)
    }
    class IdentityHost {
        <<proposed>>
        +self() Identity
        +device_id() string
    }
    class SessionTable {
        <<proposed, memory only>>
        +open(peer_id, peer_key, role) TextSession
        +find(peer_id, session_id) TextSession
        +drop(peer_id)
    }
    class secure_routes {
        <<proposed, base>>
        +register_secure_routes(svr, host)
    }
    class Identity {
        <<pm encryption>>
        +from_seed(seed) Identity
        +duplicate() Identity
        +public_key() IdentityPublic
        +sign(message, signature) Error
    }
    class TextSession {
        <<pm encryption>>
        +role_for(self, peer) EndpointRole
        +open(policy, role, self, peer, context) Error
        +wants_pull() bool
        +wants_push() bool
        +pull(frame) Error
        +push(frame) Error
        +ready() bool
        +seal(text, frame) Error
        +open_text(frame, text) Error
    }
    class Handshake {
        <<pm encryption>>
        +write_message(message) Error
        +read_message(message) Error
        +complete() bool
        +take_channel() SecureChannel
    }
    class SecureChannel {
        <<pm encryption>>
        +seal(plaintext, content_type, frame) Error
        +open(frame, expected_type, plaintext) Error
        +session_id() SessionId
    }
    class pairing {
        <<pm room, functions>>
        +create_offer(initiator, pairing_id) PairOffer
        +accept_offer(responder, offer) PairAccept
        +fingerprint_of(first, second, pairing_id) Fingerprint
        +confirm_pairing(initiator, accept, displayed) PairedDevice
    }
    class PairedDevice {
        <<pm room>>
        +IdentityPublic peer
        +Id pairing_id
        +Trust trust
        +uint32 grants
    }

    PairStore --> Peer : rows
    PeerListenerHost --> IdentityHost : supplies
    secure_routes --> PairStore : caller to row
    secure_routes --> SessionTable : one live session per peer
    secure_routes --> IdentityHost : self
    IdentityHost --> Identity : from_seed
    SessionTable *-- TextSession
    TextSession *-- Handshake : until ready
    TextSession *-- SecureChannel : after ready
    Identity ..> Handshake : a duplicate signs
    Peer ..> TextSession : the pinned key, 32 bytes
    pairing ..> PairedDevice : confirm_pairing
    PairedDevice ..> Peer : host copies peer and pairing_id, never grants
```

`secure_routes` follows `vfs.cpp`: a route table in `base` that takes a host struct and reads no settings. That keeps it in `pm-server-lib` and in the phone image, and both listeners can mount it.

`PairStore::revoke` has to reach `SessionTable::drop`. Revoking the pair closes chat. Turning `vfs` off does not.

## 3. Before and after the split

```mermaid
flowchart TB
    subgraph today["Linked today"]
        T0["pm-encryption-lib"]
        T1["pm-server-lib<br/>peer/listener.cpp mounts the group for a phone<br/>peer/pair_store.cpp holds the key"]
        T2["a new desktop/node_x.cpp<br/>includes node_internal.hpp, so the agent"]
        T3["scope: a row in device_scope_ok<br/>ticket strings, no grant row"]
        T4["peer key: no slot<br/>StoredDevice has none"]
        T5["build: only inside if FEATURE_COMMAND_LLM<br/>the viewer gets no route"]
        T6["dial side: src/vfs/phone_client.hpp<br/>outside this package"]
        T0 --> T1
        T0 --> T2
        T2 --> T3
        T2 --> T4
        T2 --> T5
        T0 --> T6
    end
    subgraph later["Linked after section 10, then section 9 steps 3 and 2"]
        L0["pm-encryption-lib"]
        L1["pm-server-lib<br/>the same group, the same row"]
        L2["core.cpp mounts the group<br/>node serve and llm agent --serve"]
        L3["scope: a core row"]
        L4["peer key: PairStore rows<br/>on the desktop too"]
        L5["build: pm_server_add_desktop_node<br/>viewer included"]
        L6["agent layer: the LLM joins<br/>as a peer of the room"]
        L7["dial side: unchanged place"]
        L0 --> L1
        L1 --> L2
        L2 --> L3
        L2 --> L4
        L2 --> L5
        L2 --> L6
        L0 --> L7
    end
    today ~~~ later
```

| Work | Before step 1 of section 11 | Why |
|---|---|---|
| Peer key and pairing id in the `Peer` row | Safe | `pair_store.cpp` is portable and the split does not touch it |
| Identity seed storage per host | Safe | Host code. Neither listener file is involved |
| Route table in `base/`, host struct | Safe | New files. Same pattern as `vfs.cpp` |
| Mount it in `PeerListener::start` | Safe | `peer/` is not part of the split |
| CMake link on the desktop | Safe | `sodium` and `pm-commons-lib` already exist in the root build |
| A desktop route in `node_*.cpp` | Wait | Step 1 rewrites `node.cpp`, `node_lan.cpp`, and `node_internal.hpp`. The route would move again and would exist only in the agent build |
| A row in `device_scope_ok` | Wait | That function splits into core rows and `layer.scope` |
| A key field in `StoredDevice` | Do not | Section 9 step 3 replaces that file with `PairStore` rows |
| Ed25519 as the device id | Wait | Section 9 step 2. It changes `vfs://phone-<id>` authorities and `peers.json` keys |

## 4. Order

```mermaid
flowchart TD
    S10["Section 11 steps 1 to 9<br/>core split, node serve"]
    S93["Section 9 step 3<br/>desktop devices.json becomes PairStore rows"]
    S92["Section 9 step 2<br/>Ed25519 device identity, TLS pin kept apart"]
    PX["Any time, portable<br/>key in the Peer row, route table in base,<br/>desktop link"]
    AN["Android<br/>libsodium and the library under the NDK, SA-16"]
    CH["pm-encryption on the paired channel<br/>PMEH handshake, PME2 frames"]
    RG["Chat as a route group"]
    LM["An LLM joins as a peer<br/>on a node whose llm feature is on"]

    S10 --> S93
    S93 --> S92
    S92 --> CH
    PX --> CH
    AN --> CH
    S10 --> CH
    CH --> RG
    RG --> LM
    S10 --> LM
```

The channel depends on the identity step more than on the split. The split decides where the desktop half lives and whether a viewer has it.

## 5. Sequences

### The second pairing step

The ticket exchange stays as it is. This runs after it. Which device creates the offer, and which route carries the two messages, are not fixed.

```mermaid
sequenceDiagram
    autonumber
    participant A as Device A
    participant B as Device B

    Note over A,B: Existing: SPKI check, ticket secret, tn1_ token
    A->>A: create_offer(identity, pairing_id)
    A->>B: PairOffer with pairing id, A's Ed25519 key, signature
    B->>B: accept_offer verifies the offer and signs
    B-->>A: PairAccept with pairing id, both keys, signature
    A->>A: fingerprint_of(both keys, pairing_id)
    B->>B: fingerprint_of(both keys, pairing_id)
    Note over A,B: Both screens show the same 8 bytes. The user compares them
    A->>A: confirm_pairing(identity, accept, fingerprint read from B)
    Note over A: PairedDevice with the peer key, the pairing id, trust paired
    A->>A: write the row with B's key, trust paired
    B->>B: the user confirms, the host writes the row with A's key
```

Device B has no `confirm_pairing` call. Its host marks the row after the user confirms. Until then the row is `verifying`, a value `PairStore` has and never writes today.

`PairedDevice.grants` comes back as chat. It is not the pair grant. A new row still stores `vfs=off`, `audio=off`, `video=off` at revision 1.

### Handshake and the first frame

Drawn for a desktop dialing a phone's `PeerListener`. The reverse direction has the same shape behind the desktop gate.

```mermaid
sequenceDiagram
    autonumber
    participant D as Dialer
    participant L as Listener route group
    participant PS as PairStore
    participant ST as Session table

    D->>D: TextSession open, LiveSession, initiator, peer key from the row
    D->>D: pull gives message 1
    D->>L: POST handshake, body PMEH 1, 87 bytes
    L->>PS: find the paired row for this caller
    PS-->>L: row with the pinned Ed25519 key
    L->>ST: TextSession open, LiveSession, responder, key from the row
    L->>ST: push message 1, pull message 2
    L-->>D: 200, body PMEH 2, 151 bytes
    D->>D: push message 2 checks the listener's signature against the pin
    D->>D: pull gives message 3, the dialer's session is ready
    D->>L: POST handshake, body PMEH 3, 87 bytes
    L->>ST: push message 3 checks the dialer's signature, ready
    L-->>D: 200, no body
    Note over D,L: This 200 tells the dialer the listener finished. The handshake has no fourth message
    D->>D: seal(text) gives a PME2 frame, sequence 0
    D->>L: POST frame, body PME2
    L->>ST: open_text
    ST-->>L: text, or Replay, Stale, AuthenticationFailed
    L-->>D: 200, with a PME2 frame back when there is one
```

- Message 2 proves the listener holds the pinned key. Today the dialer picks an address by an unauthenticated `/health` answer and then sends the token.
- The session id is 16 bytes in every handshake message and at offset 16 of every `PME2` frame. The table can key on the peer id and that value.
- A process restart drops the table. The next request is a new handshake. Nothing restores a half-open session.

## 6. Gate with a sealed body

On the paired-peer listener. Check 1 and the row lookup are the checks that exist. The rest is new.

```mermaid
flowchart TD
    R["request to the route group"] --> N{"check 1, unchanged:<br/>network granted to some peer?"}
    N -- no --> X1["403 ENETWORK"]
    N -- yes --> W{"which paired row?<br/>bearer token, or the key in message 1"}
    W -- "none, or revoked" --> X2["401 EPAIR"]
    W -- paired --> N2{"check 3, unchanged:<br/>this peer's grant names this network?"}
    N2 -- no --> X3["403 ENETWORK + revision"]
    N2 -- yes --> KY{"row holds an Ed25519 key?"}
    KY -- no --> X4["refuse: pair again.<br/>Rows written before step 2 have none"]
    KY -- yes --> RT{"route"}
    RT -- handshake --> HS["TextSession push and pull.<br/>A failure drops that session"]
    RT -- frame --> RD{"a ready session<br/>for this session id?"}
    RD -- no --> X5["refuse: handshake first"]
    RD -- yes --> OP{"open_text"}
    OP -- "Replay, Stale,<br/>AuthenticationFailed" --> X6["refuse. The window does not move"]
    OP -- ok --> DL["hand the text to the host"]
```

Chat is not one of the three grants. A paired row is enough, and `outbound.vfs` is not read here.

On the desktop the same group sits behind the core gate. The Schannel proxy ends TLS and forwards to loopback. A `PME2` frame ends inside the node process, one hop later.

## 7. Sizes

| Thing | Size | Where |
|---|---|---|
| `PMEH` message 1, 2, 3 | 87, 151, 87 bytes, exact | `protocol-model.md` |
| `PME2` overhead | 60-byte header, the content-type label, a 16-byte tag | `protocol-model.md` |
| Text plaintext per frame | 12 KiB | `k_text_max_plaintext` |
| Room frame | 16 KiB | `k_max_room_frame` |
| `SecureChannel` default plaintext cap | 64 MiB. Pass a smaller one | `k_default_max_plaintext` |
| Replay window | Sequence 0 first, then 64 frames out of order | `k_replay_window` |
| Listener body cap | 9 MiB | `PeerListener::start`, and `ListenOptions.payload_max` later |
| vfs write cap | 8 MiB | `base/src/vfs.cpp` |
| Phone announce body | 16 KiB | `node_lan.cpp` |

## 8. Build

| Image | `sodium` | `pm-commons-lib` | State |
|---|---|---|---|
| Desktop root build | Fetched at the root for encrypted settings, at the same pin the library uses | Yes | Links as is |
| Standalone `pm-server` | The library fetches it | `server.cpp` adds it first | Needs one `add_subdirectory` |
| Android `tanit_node_phone` | No | No. That build has `pm_core` | The library's CMake stops without `pm-commons-lib`. The NDK build is SA-16, open |

Sketch for the root, after commons and before this package:

```cmake
set(PM_ENCRYPTION_UNAUTHENTICATED_KX OFF CACHE BOOL "" FORCE)
set(PM_ENCRYPTION_LIBSIGNAL OFF CACHE BOOL "" FORCE)
if(NOT TARGET pm-encryption-lib)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/packages/encryption.cpp
                   ${CMAKE_CURRENT_BINARY_DIR}/pm-encryption-lib EXCLUDE_FROM_ALL)
endif()
```

`PM_ENCRYPTION_UNAUTHENTICATED_KX` defaults to on. A mesh host does not call that constructor, and off removes it. That configuration has not been built here. `PM_ENCRYPTION_LIBSIGNAL` off keeps the image BSD.

The phone image compiles this package's files by path, not as a library. The same choice has to be made for the encryption sources.

## 9. Not settled

1. **Token before or after the handshake.** The three checks run bearer first. On the cleartext listener that sends the token before anything is proven. Message 1 carries the dialer's Ed25519 key in the clear, so the listener can find the row by that key and the token can travel inside the first sealed frame, or not at all on sealed routes.
2. **The row holds a fingerprint.** `peer_fp` is described as the pairing fingerprint. `Handshake` needs the 32-byte key, and 8 bytes of BLAKE2b cannot give it back. The row needs the key and the pairing id.
3. **Where the Ed25519 secret lives.** tanit-mesh sections 2 and 8 put the private key in Android Keystore and CNG, non-exportable. `Identity` keeps the secret in process memory and is built from a seed. The library has no opaque key handle. Its README plans one under layer 2 and lists secure key storage as not implemented. Until it has one, the platform store can only wrap the seed.
4. **Route prefix and feature.** `/v1/chat/*` is the agent's chat. `route_enabled` sends any unlisted `/v1/` path to `llm`, so a new group is 404 on every node with `llm` off until it has a `ServerFeatures` field and a row there. `device_scope_ok` refuses a path with no row. `PeerListener` mounts routes directly and uses neither.
5. **Who initiates.** `TextSession::role_for` picks by key order, so the HTTP client may be the responder. The diagram lets the dialer initiate. Both devices may listen, so without one rule a pair can end up with two sessions.
6. **How a listener sends.** An HTTP listener cannot push. Either an event stream like `/v1/chat/events`, or the peer dials back. A sleeping phone is offline in both cases.
7. **The context string.** It is bound into both signatures, 1 to 4096 bytes, and both sides must pass the same bytes. Nothing in the pair row names it.
8. **Whether vfs bytes ride the channel.** tanit-mesh section 7 keeps folder bytes inside TLS on a LAN. The phone listener has no TLS, and that is a separate todo. `design.md` allows vfs copies on the LAN channel. If they do, that is `SecureChannel` with its own content-type label, not `TextSession`: text is capped at 12 KiB and labeled `text/plain`.
9. **Threads.** `SecureChannel` and `TextSession` keep plain counters. The phone listener runs four workers. The session table needs one lock per session. Frame 0 has to arrive before any other frame on that channel. After it, 64 may arrive out of order.
10. **Trust values.** `pm::room::Trust` has `Unknown`. `pm::lan::Trust` starts at `Verifying`. `ensure_peer` writes a new row as `paired` today, because there is no second step yet.
