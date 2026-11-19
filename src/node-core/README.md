# node-core

Feature-independent node runtime. This directory becomes the owner of:

- `routes/`: `ListenOptions`, route registration, dispatch, and feature availability.
- `auth/`: `RoutePolicy`, principals, hop validation, and authorization.
- `pair/`: `PairStore`, token hashes, grants, revisions, and migration.
- `lifecycle/`: desktop and phone listener startup, shutdown, and session cancellation.

Public headers keep the `pm/server` and `pm/node` include paths. Nothing in this
directory includes `llm/` or links `pm-encryption-lib`.

The migration order is interfaces, source ownership, mechanical moves, then the
router gate. See `../../docs/node-impl.md`.
