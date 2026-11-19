# node-transports

Connection adapters for the node runtime:

- `desktop/`: Schannel TLS proxy and mDNS.
- `phone/`: the pinned TLS listener in front of the portable phone routes.
- `ipc/`: converts an authenticated host IPC caller into `LocalAdmin`; it does
  not own the host IPC server.
- `webrtc/`: authenticated signaling when a media path needs it. Media remains
  protected by SRTP.

A transport establishes a channel and its peer evidence. It does not grant a
feature capability. The router in `node-core` makes that decision.
