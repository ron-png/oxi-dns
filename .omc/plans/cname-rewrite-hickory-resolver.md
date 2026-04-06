# Plan: Replace hand-rolled CNAME-chain resolution in `build_cname_rewrite_response` with `hickory-resolver`

## STATUS: ABANDONED (2026-04-06)

Pre-implementation investigation triggered the abandon criteria. Findings:

- ✅ `ResolverOpts::preserve_intermediates` does retain CNAME records in `Lookup` (verified in `hickory-resolver-0.25.2/src/caching_client.rs:409`). The refactor is *technically* possible.
- ⚠️ `hickory-resolver = "0.25"` in `Cargo.toml` has **no features enabled**. Supporting oxi-dns's DoT/DoH/DoQ upstreams via `hickory-resolver` requires turning on `tls-ring`, `https-ring`, and `quic-ring` features — a non-trivial dependency-surface expansion, not a free swap.
- 🚨 **Blocker the original plan missed:** `UpstreamForwarder::forward` (`src/dns/upstream.rs:725`) has *two* modes — forward-to-configured-upstreams **and** `forward_iterative` against `ROOT_SERVERS` when no upstreams are configured (line 925+). A resolver-based replacement would have to cover both, meaning either (a) build a `hickory-recursor` instance in parallel for the no-upstreams case, or (b) keep the manual loop as a fallback (which defeats the refactor).

The result is that "delete a 100-line for-loop + HashSet" turns into "maintain two parallel resolver/recursor instances kept in sync with `UpstreamForwarder`'s runtime config, plus enable 3 new hickory-resolver feature flags, plus introduce a test seam". The current code is correct, in production, and routes through the single uniform `UpstreamForwarder::forward` dispatch — the refactor cost outweighs the benefit.

**Do not resurrect this plan unless** one of these changes:
1. oxi-dns drops the iterative mode (`forward_iterative`) entirely, OR
2. oxi-dns migrates *all* upstream forwarding to `hickory-resolver` (a separate, much larger refactor), at which point CNAME-rewrite naturally falls out of it.

The plan body below is preserved for historical context.

---



## Context

`src/dns/handler.rs:423-526` (`build_cname_rewrite_response`) currently:

1. Builds a synthetic `Message` with a fresh random ID and the safe-search CNAME target as the question.
2. Serializes it and pushes it through `UpstreamForwarder::forward(packet)` — i.e., it goes back through the *same* upstream the user already configured (DoT/DoH/DoQ/UDP).
3. Parses the wire response, extracts CNAME / A / AAAA records, follows the chain manually up to `MAX_CNAME_HOPS = 10`, with a `seen_targets` loop guard.
4. Glues the original-domain → first-CNAME synthetic record, the discovered CNAME chain, and address records into the final response and returns it.

This is invoked only from the safe-search rewrite path (`handler.rs:153-160`). The forwarder does the chain-walking *the user already wanted*; we are essentially re-implementing a stub resolver against our own forwarder.

## Goal

Use `hickory-resolver` (already in `Cargo.toml`) to do the CNAME chain resolution, removing the manual `Message` construction, the loop, and the dedup/hop-limit logic — without changing the externally observed response format (original domain → CNAME → … → A/AAAA, TTL forced to 3600, AA=false, RA=true, EDNS echoed).

## Critical constraint: where do CNAME-target lookups go?

The current code routes CNAME-target lookups through `UpstreamForwarder`, meaning:

- They use the user's configured upstreams (which may be DoH/DoT/DoQ).
- Blocklist / safe-search rules are *not* re-applied to the chain (no recursion into `process_dns_query`) — and that's intentional.
- The user's upstream choice — including any custom resolver — is honored.

A `hickory_resolver::TokioAsyncResolver` configured from `ResolverConfig::default()` would talk to **its own** nameservers (Google by default), bypassing the user's upstream config. **That is a behavior regression and is not acceptable.**

Two viable options — **decision needed before implementation**:

### Option A — Build a `Resolver` from the user's configured upstreams

Read the upstream config (currently held inside `UpstreamForwarder`) and construct a `hickory_resolver::Resolver` whose `NameServerConfigGroup` mirrors it. Cache one resolver per `UpstreamForwarder` instance (build it lazily, store in an `OnceCell` on `UpstreamForwarder`).

- ✅ Real simplification — drops the entire manual loop.
- ✅ Gets resolver-level caching for free (matches user expectation that "lookups are cached").
- ❌ Requires mapping every upstream protocol oxi-dns supports (UDP, TCP, DoT, DoH, DoQ) to a `Protocol` value `hickory-resolver` accepts. If oxi-dns supports an upstream variant `hickory-resolver` doesn't (need to verify per-protocol), Option A is blocked.
- ❌ Two parallel paths to upstreams (forwarder for normal queries, resolver for CNAME chains) — risk of config drift.

### Option B — Keep `UpstreamForwarder`, just shrink the loop

Leave the forwarding mechanism alone. Replace only the manual `Message`/`Header`/`Query` construction with `hickory_proto`'s message builder helpers (if any are cleaner) and pull the chain-walk into a small helper.

- ✅ Zero behavior risk on the upstream side.
- ❌ Almost no code removed. The "swap" basically becomes a refactor for readability, not a dependency consolidation. Probably not worth a separate plan/PR.

**Recommendation:** Option A *if* protocol-mapping checks out for every upstream variant oxi-dns supports; otherwise drop the refactor entirely and keep the current code (which is correct).

## Pre-implementation investigation (do these first, before any code changes)

1. **Read `src/dns/upstream.rs` in full.** Map every upstream protocol variant `UpstreamForwarder` accepts. Confirm whether each one has a corresponding `hickory_resolver::config::Protocol` value (`Udp`, `Tcp`, `Tls`, `Https`, `Quic`, `H3`). If any variant is unsupported by `hickory-resolver` 0.25, **stop** and report — Option A is dead.
2. **Confirm `hickory-resolver` 0.25's lookup API.** Specifically: does `resolver.lookup(name, RecordType::A).await` return the *full chain* (CNAME records included in the answer set), or only the terminal records? If only terminal, we'd need to reconstruct the CNAME chain ourselves — partially defeating the point. Check via `cargo doc -p hickory-resolver` and the crate source under `~/.cargo/registry/src/`.
3. **Re-read the safe-search call site** (`handler.rs:153-160`) to confirm `query_type` is only ever `A` or `AAAA` here. The current code already assumes this (only matches `RData::A`/`RData::AAAA`); a resolver-based path should keep that assumption explicit and reject other types.
4. **Check whether `hickory-resolver` honors the request's recursion-desired flag** or always sets RD itself. The current code sets RD=true regardless; behavior should match.

If steps 1 or 2 fail, **abandon the refactor** and document why in a follow-up note in this plan file. Do not attempt Option B as a consolation — it's not worth it.

## Implementation steps (assuming Option A clears investigation)

1. **Add a lazily-built resolver to `UpstreamForwarder`.**
   - Field: `cname_resolver: tokio::sync::OnceCell<hickory_resolver::TokioAsyncResolver>` (or `std::sync::OnceLock` if no async init needed).
   - Method: `async fn resolver(&self) -> Result<&TokioAsyncResolver, DnsError>` — builds the resolver from the same upstream config the forwarder already holds.
   - The resolver's `ResolverOpts` should set `preserve_intermediates: true` so CNAME records appear in the lookup result. **This is the key option** — without it the entire refactor is pointless.

2. **Rewrite `build_cname_rewrite_response`.**
   - Drop `MAX_CNAME_HOPS`, `seen_targets`, the wire-format request building, the inner loop, and the manual answer-section walk.
   - Call `upstream.resolver().await?.lookup(cname_fqdn, query_type).await`.
   - Iterate the returned `Lookup`'s records: keep CNAME records as the chain, A/AAAA as address records. TTL-rewrite to 3600.
   - Prepend the original-domain → first-CNAME synthetic record (unchanged from current code).
   - Build the response `Message` exactly as today (same header flags, EDNS echo, query echo).

3. **Error handling.** `Lookup` errors (NXDOMAIN on the CNAME target, timeout, refused) should map to `Option::None` — same as current code, which silently returns `None` and lets the caller fall through to normal forwarding. Do NOT propagate errors here; that would change observed behavior.

4. **Delete dead imports.** `rand` may be unused after removing the manual `Message` ID generation — check `Cargo.toml` to see if `rand` is used elsewhere before removing it.

## Testing (write before implementation — TDD)

Existing tests in `handler.rs` cover `build_blocked_response` and friends but **not** `build_cname_rewrite_response`. We need to add coverage *before* touching the function. Required tests:

1. **`cname_rewrite_returns_chain_with_terminal_a`** — mock upstream returning `cname.target. CNAME other.target.` then `other.target. A 1.2.3.4`. Assert response has: original→cname, cname→other, other→1.2.3.4, all TTL=3600, header AA=false, RA=true, ID echoed, query echoed.
2. **`cname_rewrite_returns_chain_with_terminal_aaaa`** — same shape, AAAA query.
3. **`cname_rewrite_loop_protection`** — mock upstream returning a CNAME loop (`a → b → a`). Assert the function terminates and returns `Some` with whatever chain it built (current behavior — verify exact shape from current code first, then encode it as the test). After refactor, hickory-resolver's own loop protection should produce equivalent or better behavior.
4. **`cname_rewrite_upstream_failure_returns_none`** — mock upstream returns `Err`. Assert `None`.
5. **`cname_rewrite_no_address_records_returns_none_or_chain_only`** — mock upstream returns CNAME chain that never resolves to A/AAAA. **Determine current behavior empirically first** (the current loop breaks on `!found_cname` even with empty `address_records`, returning a CNAME-only response — verify this is intentional). Encode whatever it does as the test.

The hard part: `UpstreamForwarder` is concrete, not a trait. To mock it for tests we need either:
- (a) Extract a `trait Forwarder { async fn forward(&self, …) -> …; }` and have `UpstreamForwarder` implement it, then take `&dyn Forwarder` in `build_cname_rewrite_response`. **Adds an abstraction the rest of the codebase doesn't need** — only worth it if we commit to writing these tests.
- (b) Spin up a real local UDP DNS server in tests using `hickory-server`. Heavier setup but no production code changes.
- (c) Skip the unit tests and rely on a manual smoke test against a real DNS server. **Unacceptable for a refactor of the hot path** — refactor is not safe without coverage.

**Decision needed:** which testing approach. Recommendation: (a), because the trait is small and the seam is useful long-term, and because (b) couples the tests to network/port availability.

## Verification checklist

- [ ] `cargo build` clean.
- [ ] `cargo test` — all existing handler tests still pass, all new CNAME tests pass.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.
- [ ] Manual smoke test: configure a safe-search CNAME rule (e.g., YouTube restricted mode CNAME), query A and AAAA from `dig`, confirm the response contains the chain and final address(es), TTL=3600, and that the response works end-to-end through a browser.
- [ ] Run with a non-default upstream (e.g., DoH to Quad9) and verify CNAME-chain queries actually traverse *that* upstream — `tcpdump`/upstream logs, not just "it returned an answer".

## Out of scope

- Replacing `UpstreamForwarder` itself with `hickory-resolver` for normal (non-CNAME-rewrite) queries. Much larger refactor; entirely separate plan.
- Adding resolver-level caching for normal queries.
- Touching the safe-search target lookup logic (`features::get_safe_search_target`).

## Abandon criteria

If any of these become true during implementation, stop and report rather than working around:

- `hickory-resolver` 0.25 cannot be configured against one of oxi-dns's supported upstream protocols.
- `preserve_intermediates` does not actually return CNAME records in the `Lookup` result (verify with a real test before proceeding).
- The mocking seam (Option a above) requires invasive changes outside `dns/handler.rs` and `dns/upstream.rs`.
- Behavior diverges from current in any test that encodes today's observed behavior, and the divergence isn't a clear improvement.
