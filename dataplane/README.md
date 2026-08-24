# R-TRAPS data-plane reference

The project contract prefers Rust, but `cargo` and `rustc` are unavailable on
the current host.  This is a standard-library-only Python implementation of
the executable interfaces and safety invariants, not a throughput claim.

Implemented interfaces:

- `Directory.lookup(username, edge_id=None) -> DirectoryView`
- `PositiveScreen.query(view, password, edge_id) -> PositiveDecision`
- `NegativeCache.lookup(neg_key) -> CacheLookup`
- `Singleflight.execute(neg_key, verify_fn) -> TypedBackendResult`
- `InMemoryBackend.verify(username, password, expected_version)`
- `AuthDataPlane.authenticate(edge_id, username, password)`
- `AuthDataPlane.authenticate_padded(...) -> Future[AuthDecision]`

The negative key is full HMAC-SHA-256 and binds immutable account ID, account
generation, complete credential-set version, and the positive credential
token.  Missing, stale, uncertified, and crashed state is forwarded to the
backend.  Raw passwords are never stored in the negative cache or
singleflight map.

`AsyncResponsePadder` uses timer-backed future completion with a bounded pending
set.  At capacity it retains the configured timing floor using a bounded
synchronous fallback and exposes that event in metrics.
