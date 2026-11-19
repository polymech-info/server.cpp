# node-features

Route groups mounted on the router owned by `node-core`:

- `vfs/`: `/v1/vfs` and bookmark roots.
- `audio/`: `/v1/audio`.
- `video/`: `/v1/video` except `/control`.
- `control/`: `/v1/video/control`; disabled on the phone.
- `agent/`: optional LLM, chat, realtime, host tools, and logs.

A feature registers routes and policies. It does not receive
`httplib::Server`, implement its own bearer gate, or infer authority from
loopback.
