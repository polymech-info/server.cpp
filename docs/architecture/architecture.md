# pm-server architecture

One Tanit listener. Features are flags on that process. `node serve` mounts lan, vfs, and capture when the binary has it. `llm agent --serve` adds the agent on the same gate. The phone listener is the same shape with llm, tools, video control, and host off.

`packages/encryption.cpp` is not linked. Paired vfs, audio, and video ride authenticated TLS. The pin is checked before the token.

| Diagram | What it shows |
|---------|----------------|
| [overview.html](overview.html) | Dialer, desktop proxy, phone listener, the gate, and the route groups |
| [topologies.html](topologies.html) | Which devices reach vfs, audio, and video over LAN or Tailscale |

## Listeners

A dialer uses a saved URL. On the desktop, the LAN proxy terminates TLS and mDNS advertises the node. The phone listener terminates TLS on its own port. Both arrive at the same auth gate.

## Grants

`PairStore` version 2 is `devices.json`. `outbound` is what this device allows that peer to do. Pairing itself grants nothing. A route that is off is not registered, so an unknown `/v1/` path is 404. A registered route the grant does not cover is 403. No credential is 401. A hop this process did not write is 400.

## Features

vfs is the folder jail in `packages/vfs.cpp`. audio and video call `packages/audio.cpp` and `packages/video.cpp` when those captures are compiled in. The agent layer is completions, tools, and host routes. It is not a second server, and a node with llm off does not mount it.

## Access

A paired desktop or phone can read the other's vfs over a saved LAN address or a saved Tailscale URL. The URL is only another dial. The pin is still checked first, then the token.

Audio and video answer on the desktop listener. Video here is the route with the grant on. The phone listener mounts health, the grant route, and vfs. A video grant on the phone does not publish `/v1/video`.

The Chrome extension reaches the desktop through the native host and loopback. It is not a pair, and it does not dial vfs or audio. Chat on the LAN exists only while `llm agent --serve` is the listener. `node serve` leaves those routes unregistered. A second phone reaches another phone's vfs the same way. It does not reach that phone's microphone.
