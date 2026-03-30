# Manual Blocklist Refresh with Per-Source Progress

## Summary

Add a "Refresh Now" button to the blocklist sources section of the dashboard. Clicking it triggers an SSE-streamed refresh that shows per-source progress (success with domain count, or failure). Below the sources list, a live-ticking timer shows how long ago the last refresh completed (HH:mm:ss format).

## Backend Changes

### New Field: `last_refreshed_at`

Add to `BlocklistManager`:

```rust
last_refreshed_at: Arc<RwLock<Option<std::time::Instant>>>
```

Updated by both the manual refresh endpoint and the existing background auto-refresh task.

### New Endpoint: `GET /api/blocklist-sources/refresh` (SSE)

Streams progress events as each blocklist source is fetched. The connection stays open until all sources are processed.

**Event types:**

```
event: progress
data: {"source": "https://example.com/list.txt", "index": 1, "total": 5, "status": "ok", "domains": 12340}

event: progress
data: {"source": "https://other.com/hosts", "index": 2, "total": 5, "status": "error", "error": "timeout"}

event: done
data: {"total_domains": 42310, "sources_ok": 4, "sources_failed": 1, "refreshed_at": "2026-03-30T14:22:05Z"}
```

**Implementation:**

- Iterate over configured sources sequentially
- For each source, attempt to fetch and parse
- On success: update the source's domain set, send `progress` event with `status: "ok"` and domain count
- On failure: keep existing domains for that source (graceful degradation), send `progress` event with `status: "error"` and error message
- After all sources: rebuild the unified blocked set, update `last_refreshed_at`, send `done` event with summary
- Uses Axum's SSE support (`axum::response::sse::Sse`)

**Concurrency guard:** Only one refresh can run at a time. If a refresh is already in progress (manual or auto), the endpoint returns `409 Conflict`.

### New Endpoint: `GET /api/blocklist-sources/last-refresh`

Returns the timestamp of the last completed refresh.

```json
{"refreshed_at": "2026-03-30T14:22:05Z"}
```

Returns `{"refreshed_at": null}` if no refresh has completed since startup.

### Background Task Update

The existing auto-refresh loop in `main.rs` must also update `last_refreshed_at` after calling `refresh_sources()`. The concurrency guard should prevent the background task and a manual refresh from running simultaneously — if a manual refresh is in progress, the background task skips that cycle.

## Frontend Changes

### Refresh Button & Last Refreshed Timer

Added as a footer row below the blocklist sources list:

```
[Last refreshed: 00:05:12 ago]                    [↻ Refresh Now]
```

- **Position:** Below the sources `<ul>`, above the auto-refresh interval row
- **Left side:** "Last refreshed: HH:mm:ss ago" — or "Never refreshed" if null
- **Right side:** "Refresh Now" button styled with accent color

### Live Timer

- `setInterval` ticking every second
- Computes elapsed time from stored refresh timestamp
- Format: `HH:mm:ss` (e.g., `01:23:45 ago`)
- Resets to `00:00:00 ago` when a refresh completes
- On page load, fetches initial value from `GET /api/blocklist-sources/last-refresh`

### Per-Source Progress During Refresh

When "Refresh Now" is clicked:

1. Button disables and shows a loading state
2. Opens `EventSource` to `GET /api/blocklist-sources/refresh`
3. On each `progress` event: update the corresponding source row with:
   - Green `✓ {count}` on success
   - Red `✗ failed` on error
4. On `done` event: re-enable button, reset the "last refreshed" timer, close the EventSource
5. On connection error: re-enable button, show error message

### Source Row Enhancement

Each source in the list gains a status indicator area (right side, before the Remove button) that shows the per-source result after a refresh. This status is transient — it appears after a refresh and clears on page reload.

## Scope Boundaries

- No changes to config persistence (refresh doesn't change config)
- No changes to the blocklist parsing logic
- No changes to the auto-refresh interval UI
- The `refreshed_at` timestamp is in-memory only (not persisted to config) — resets on restart
