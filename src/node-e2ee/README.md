# node-e2ee

Optional end-to-end encryption feature glue. This directory is absent from
`pm-server-lib` and `node serve`.

Its first target links both the node and `pm-encryption-lib` for
`FileOffer`/`FileInbox` bytes held by a relay. Direct VFS remains on pinned TLS.
`packages/encryption.cpp` remains independent and does not include
`packages/server.cpp`.

No source belongs here before phase 5 has a concrete stored-ciphertext use.
