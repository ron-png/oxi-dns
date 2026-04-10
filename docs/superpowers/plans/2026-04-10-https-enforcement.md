# HTTPS Enforcement & Sensitive-Feature Gating — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the HTTPS dashboard port editable in the Network tab, add an off-by-default auto-redirect toggle, unconditionally block sensitive API writes over plain HTTP, and recommend a password rotation when HTTPS enforcement is first enabled.

**Architecture:** Adds two fields to `WebConfig` (`auto_redirect_https: bool`, `password_change_recommended: bool`). Drops the `https_active` state input from the existing `sensitive_https_middleware` so it gates purely on the `IsHttps` request extension. `run_web_server` grows an `auto_redirect_https` parameter that branches whether the HTTP listener redirects or serves. The network API (`GET/POST /api/system/network`) exposes the new fields. A new `GET /api/system/security-status` endpoint tells the frontend whether to show banners. Dashboard gets HTTPS-port listener row, auto-redirect toggle, two global banners, and per-form inline replacement for sensitive forms.

**Tech Stack:** Rust, axum 0.8, tokio, rustls, serde, tokio-rustls, vanilla JS + HTML in `src/web/dashboard.html`.

---

## File Structure

### Modified
- `src/config.rs` — two new fields on `WebConfig`
- `src/web/mod.rs`:
  - `AppState` — drop `https_active` field (no longer needed)
  - `sensitive_https_middleware` — drop `State<bool>` extractor, gate purely on `IsHttps`
  - `run_web_server` — new `auto_redirect_https: bool` parameter, branch HTTP listener behavior
  - `api_system_network` + `UpdateNetworkRequest` + `api_update_network` — accept/return `https_listen` and `auto_redirect_https`, enforce 400 when enabling redirect without https_listen, set `password_change_recommended` on false→true transition, auto-clear redirect flag when https_listen is cleared
  - `api_change_password` — clear `password_change_recommended` on success
  - `api_security_status` — new handler
  - Router — register `/api/system/security-status`, remove `https_active` state wiring on `sensitive_https_middleware`
- `src/main.rs` — drop the `https_active` field from `AppState` construction, pass `auto_redirect_https` into `run_web_server`
- `src/web/dashboard.html`:
  - Add HTTPS row to `NETWORK_LISTENERS`
  - Add HTML markup for HTTPS port inputs + auto-redirect toggle inside the Network section
  - Add two global banners (HTTP warning, password-change recommendation) at the top of the dashboard layout + CSS
  - Wrap cert upload, ACME token, password-change forms with `data-requires-https` and init-time replacement
  - Extend `loadNetwork`/`saveNetwork` to handle new fields
  - Poll `/api/system/security-status` on load and after password/network actions

### No changes
- `src/reconfigure.rs` — `web.https_listen` stays out of the CLI allow-list (a unit test will enforce this)

---

## Task 1: Add config fields

**Files:**
- Modify: `src/config.rs:75-83`
- Test: `src/config.rs` (add to existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing test**

Add to the bottom of `src/config.rs`:

```rust
#[cfg(test)]
mod web_config_tests {
    use super::*;

    #[test]
    fn web_config_has_new_https_fields_with_defaults() {
        let toml_str = r#"
listen = ["0.0.0.0:9853"]
https_listen = ["0.0.0.0:9854"]
"#;
        let cfg: WebConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.listen, vec!["0.0.0.0:9853".to_string()]);
        assert_eq!(cfg.https_listen, Some(vec!["0.0.0.0:9854".to_string()]));
        assert!(!cfg.auto_redirect_https, "auto_redirect_https defaults to false");
        assert!(
            !cfg.password_change_recommended,
            "password_change_recommended defaults to false"
        );
    }

    #[test]
    fn web_config_round_trip_preserves_new_fields() {
        let toml_str = r#"
listen = ["0.0.0.0:9853"]
https_listen = ["0.0.0.0:9854"]
auto_redirect_https = true
password_change_recommended = true
"#;
        let cfg: WebConfig = toml::from_str(toml_str).expect("parse");
        assert!(cfg.auto_redirect_https);
        assert!(cfg.password_change_recommended);

        let serialized = toml::to_string(&cfg).expect("serialize");
        let reparsed: WebConfig = toml::from_str(&serialized).expect("reparse");
        assert!(reparsed.auto_redirect_https);
        assert!(reparsed.password_change_recommended);
    }

    #[test]
    fn web_config_missing_new_fields_defaults_false() {
        // Old configs must deserialize without error.
        let toml_str = r#"
listen = ["0.0.0.0:9853"]
"#;
        let cfg: WebConfig = toml::from_str(toml_str).expect("parse");
        assert!(!cfg.auto_redirect_https);
        assert!(!cfg.password_change_recommended);
        assert!(cfg.https_listen.is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib web_config_tests`
Expected: FAIL — `auto_redirect_https` / `password_change_recommended` fields don't exist on `WebConfig`.

- [ ] **Step 3: Add the two fields to `WebConfig`**

In `src/config.rs` around line 75-83, change the struct to:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    /// Addresses to listen on for the web admin UI
    #[serde(default = "default_web_listen", deserialize_with = "string_or_vec")]
    pub listen: Vec<String>,
    /// Addresses to listen on for the HTTPS web admin UI (opt-in)
    #[serde(default, deserialize_with = "string_or_vec_opt")]
    pub https_listen: Option<Vec<String>>,
    /// Force HTTP requests to redirect to HTTPS. Off by default.
    #[serde(default)]
    pub auto_redirect_https: bool,
    /// Set when auto_redirect_https is first enabled; cleared on successful
    /// password change. Drives the dashboard password-rotation banner.
    #[serde(default)]
    pub password_change_recommended: bool,
}
```

Also update `default_web_config()` (around line 286) to include the new fields:

```rust
fn default_web_config() -> WebConfig {
    WebConfig {
        listen: default_web_listen(),
        https_listen: None,
        auto_redirect_https: false,
        password_change_recommended: false,
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib web_config_tests`
Expected: PASS (all 3 tests).

- [ ] **Step 5: Run full config test module**

Run: `cargo test --lib config::`
Expected: PASS — no existing tests regressed.

- [ ] **Step 6: Commit**

```bash
git add src/config.rs
git commit -m "$(cat <<'EOF'
feat(config): add web.auto_redirect_https and web.password_change_recommended

Two new fields on WebConfig backing the HTTPS enforcement UX. Both
default to false and use #[serde(default)] for backward compatibility
with existing configs. password_change_recommended is a transient flag
set when auto_redirect_https is first enabled and cleared on a
successful password change.
EOF
)"
```

---

## Task 2: Reconfigure guard test

**Files:**
- Modify: `src/reconfigure.rs` (add to existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the guard test**

Add to the tests module in `src/reconfigure.rs`:

```rust
#[test]
fn web_https_listen_is_not_cli_reconfigurable() {
    // web.https_listen must be edited via the web UI, not via --reconfigure.
    // This guard prevents accidentally adding it to VALID_KEYS and
    // splitting the "where do you configure HTTPS" story.
    assert!(
        !VALID_KEYS.contains(&"web.https_listen"),
        "web.https_listen must NOT be in the CLI reconfigure allow-list — it is web-editable only"
    );
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test --lib reconfigure::tests::web_https_listen_is_not_cli_reconfigurable`
Expected: PASS immediately — `web.https_listen` is already absent from `VALID_KEYS`.

- [ ] **Step 3: Commit**

```bash
git add src/reconfigure.rs
git commit -m "test(reconfigure): guard that web.https_listen stays web-editable only"
```

---

## Task 3: Simplify `sensitive_https_middleware`

**Files:**
- Modify: `src/web/mod.rs:309-327`
- Modify: `src/web/mod.rs:471-475` (middleware registration)

- [ ] **Step 1: Update the middleware function**

Replace the existing `sensitive_https_middleware` function at line 309:

```rust
async fn sensitive_https_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if request.extensions().get::<IsHttps>().is_none()
        && SENSITIVE_PATHS.iter().any(|p| request.uri().path() == *p)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "This endpoint requires HTTPS. Use https:// to access the dashboard securely.",
                "code": "https_required"
            })),
        )
            .into_response();
    }
    next.run(request).await
}
```

Key changes: removed `State<bool>` extractor, removed `https_active` check, added `"code": "https_required"` so the frontend can distinguish this 403 from other 403s.

- [ ] **Step 2: Update middleware registration**

In `run_web_server` around line 471, replace:

```rust
        // Enforce HTTPS on sensitive endpoints
        .layer(axum::middleware::from_fn_with_state(
            state.https_active,
            sensitive_https_middleware,
        ))
```

with:

```rust
        // Enforce HTTPS on sensitive endpoints
        .layer(axum::middleware::from_fn(sensitive_https_middleware))
```

- [ ] **Step 3: Remove `https_active` from `AppState`**

In `src/web/mod.rs` around line 56, remove the field:

```rust
    pub acme: std::sync::Arc<crate::acme::AcmeState>,
    // remove: pub https_active: bool,
```

- [ ] **Step 4: Remove `https_active` from `AppState` construction in main.rs**

In `src/main.rs` around line 372, remove the line:

```rust
        https_active: config.web.https_listen.is_some(),
```

- [ ] **Step 5: Build and verify compilation**

Run: `cargo build`
Expected: PASS with no errors.

- [ ] **Step 6: Run web tests to verify no regression**

Run: `cargo test --lib web::`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/web/mod.rs src/main.rs
git commit -m "$(cat <<'EOF'
refactor(web): sensitive_https_middleware gates on protocol, not state

Drops the https_active state input. The middleware now blocks sensitive
writes over plain HTTP unconditionally — since a self-signed cert is
auto-generated at startup, HTTPS is always reachable and there's no
chicken-and-egg. Also adds a "code":"https_required" field to the 403
body so the frontend can distinguish this error from other 403s.
EOF
)"
```

---

## Task 4: Add `auto_redirect_https` parameter to `run_web_server`

**Files:**
- Modify: `src/web/mod.rs:329-335` (signature)
- Modify: `src/web/mod.rs:481-618` (HTTP listener branching)
- Modify: `src/main.rs:620-631` (caller)

**Context:** The existing code already has two HTTP paths — a redirect path (inside `if is_https_active`, lines ~553-587) and a full-app path (the else branch, lines ~588-618). Both use `axum::serve`. We want the redirect path to only fire when `is_https_active && auto_redirect_https`; otherwise, HTTP serves the full app. The cleanest refactor is to unify the "serve full app on HTTP" logic into one place.

- [ ] **Step 1: Update `run_web_server` signature**

At `src/web/mod.rs:329`, change the function signature:

```rust
pub async fn run_web_server(
    listen: &[String],
    https_listen: Option<&[String]>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    auto_redirect_https: bool,
    state: AppState,
) -> anyhow::Result<()> {
```

- [ ] **Step 2: Restructure the HTTP branching logic**

First, **read lines 481-618 of `src/web/mod.rs`** to see the current shape. You'll see:

```
if is_https_active {
    // serve HTTPS listeners
    // THEN: serve HTTP as redirect-only (lines ~553-587)
} else {
    // serve HTTP as full app (lines ~588-618)
}
```

Refactor to:

```
if is_https_active {
    // serve HTTPS listeners (unchanged)
}

if is_https_active && auto_redirect_https {
    // serve HTTP as redirect-only (move the existing redirect block here)
} else {
    // serve HTTP as full app (move the existing else-branch code here)
}
```

Concretely, inside `run_web_server`:

1. After the HTTPS listener loop finishes (the `for addr in https_addrs { ... }` block at ~line 492-551), close the `if is_https_active` block immediately — do NOT include the HTTP redirect block inside it.
2. Add a new sibling branch:
   ```rust
   if is_https_active && auto_redirect_https {
       // existing redirect block here — copy lines ~553-587 verbatim,
       // including the https_port derivation and the for loop
   } else {
       // existing full-app HTTP block here — copy lines ~588-618 verbatim
   }
   ```
3. Delete the now-orphaned else branch that currently serves HTTP as full app when `!is_https_active`.

After the refactor, the final structure should be:

```rust
let mut handles = Vec::new();
let is_https_active = https_listen.is_some() && tls_config.is_some();

if is_https_active {
    let tls_cfg = tls_config.unwrap();
    let https_addrs = https_listen.unwrap();
    // ... existing HTTPS listener loop (unchanged) ...
}

if is_https_active && auto_redirect_https {
    // existing HTTPS redirect block copied here, unchanged.
    // Note: this block references `https_addrs` and `https_listen` — since
    // we closed the `if is_https_active` block above, re-derive `https_addrs`
    // here: let https_addrs = https_listen.unwrap();
} else {
    // existing normal HTTP block copied here, unchanged
}
```

**Important:** inside the redirect branch, `https_addrs` needs to be re-fetched because the `if is_https_active` scope closed. Add `let https_addrs = https_listen.unwrap();` at the top of the redirect branch. The `unwrap` is safe because `is_https_active` implies `https_listen.is_some()`.

- [ ] **Step 3: Update `main.rs` caller**

In `src/main.rs` around line 606, capture the flag before moving config into `web_state`:

```rust
    let web_listen = config.web.listen.clone();
    let web_https_listen = config.web.https_listen.clone();
    let auto_redirect_https = config.web.auto_redirect_https;

    let web_tls_config = if web_https_listen.is_some() {
        // ... unchanged ...
    };

    let web_handle = tokio::spawn(async move {
        if let Err(e) = web::run_web_server(
            &web_listen,
            web_https_listen.as_deref(),
            web_tls_config,
            auto_redirect_https,
            web_state,
        )
        .await
        {
            tracing::error!("Web server error: {}", e);
        }
    });
```

- [ ] **Step 4: Build**

Run: `cargo build`
Expected: PASS.

- [ ] **Step 5: Run a manual smoke test**

Run: `./target/debug/oxi-dns config.toml &` then `curl -I http://127.0.0.1:9853/` (adapt config path). Expected: with `auto_redirect_https=false` (default), HTTP returns the dashboard (200 OK or 302 to `/login`), not a 301 redirect to HTTPS. Kill the process.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs src/web/mod.rs
git commit -m "$(cat <<'EOF'
feat(web): respect web.auto_redirect_https in HTTP listener

HTTP is only forced to redirect-only when auto_redirect_https is true.
When HTTPS is active but auto_redirect is off, HTTP serves the full app
and sensitive writes are blocked by the middleware (since IsHttps is
not set). Default off keeps HTTP accessible for LAN use out of the box.
EOF
)"
```

---

## Task 5: Extend Network API for new fields

**Files:**
- Modify: `src/web/mod.rs:687-850` (api_system_network, UpdateNetworkRequest, api_update_network)

- [ ] **Step 1: Add new fields to `api_system_network` response**

At line 687, extend the handler:

```rust
async fn api_system_network(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let config = Config::load(&state.config_path).unwrap_or_default();
    let interfaces = get_network_interfaces();

    Json(serde_json::json!({
        "dns_listen": config.dns.listen,
        "web_listen": config.web.listen,
        "https_listen": config.web.https_listen,
        "auto_redirect_https": config.web.auto_redirect_https,
        "dot_listen": config.dns.dot_listen,
        "doh_listen": config.dns.doh_listen,
        "doq_listen": config.dns.doq_listen,
        "interfaces": interfaces,
    }))
    .into_response()
}
```

- [ ] **Step 2: Add new fields to `UpdateNetworkRequest`**

At line 715:

```rust
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateNetworkRequest {
    dns_listen: Option<serde_json::Value>,
    web_listen: Option<serde_json::Value>,
    https_listen: Option<serde_json::Value>,
    auto_redirect_https: Option<bool>,
    dot_listen: Option<serde_json::Value>,
    doh_listen: Option<serde_json::Value>,
    doq_listen: Option<serde_json::Value>,
}
```

- [ ] **Step 3: Handle new fields in `api_update_network`**

At line 762, inside the handler, after the existing `dns_listen`/`web_listen` reject-block and before the dot/doh/doq handling, insert:

```rust
    // Track auto-redirect transition for password-change recommendation
    let previous_auto_redirect = config.web.auto_redirect_https;

    if let Some(ref val) = req.https_listen {
        config.web.https_listen = match parse_optional_listen_value(val) {
            Ok(listen) => listen,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": error })),
                )
                    .into_response();
            }
        };
        // If HTTPS is cleared while auto-redirect is on, force the toggle off
        // to avoid sending clients to a non-existent listener.
        if config.web.https_listen.is_none() && config.web.auto_redirect_https {
            config.web.auto_redirect_https = false;
            tracing::info!(
                "web.https_listen cleared — auto_redirect_https automatically disabled"
            );
        }
    }

    if let Some(enabled) = req.auto_redirect_https {
        if enabled && config.web.https_listen.is_none() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "HTTPS must be configured (https_listen) before enabling auto-redirect"
                })),
            )
                .into_response();
        }
        config.web.auto_redirect_https = enabled;
    }

    // If auto-redirect transitioned false -> true, set the password-rotation flag.
    if !previous_auto_redirect && config.web.auto_redirect_https {
        config.web.password_change_recommended = true;
        tracing::info!(
            "auto_redirect_https enabled — setting password_change_recommended=true"
        );
    }
```

- [ ] **Step 4: Include new fields in the response of `api_update_network`**

At the end of `api_update_network` (around line 841), update the response JSON:

```rust
    Json(serde_json::json!({
        "dns_listen": config.dns.listen,
        "web_listen": config.web.listen,
        "https_listen": config.web.https_listen,
        "auto_redirect_https": config.web.auto_redirect_https,
        "dot_listen": config.dns.dot_listen,
        "doh_listen": config.dns.doh_listen,
        "doq_listen": config.dns.doq_listen,
        "interfaces": interfaces,
    }))
    .into_response()
```

- [ ] **Step 5: Build**

Run: `cargo build`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/web/mod.rs
git commit -m "$(cat <<'EOF'
feat(web): expose https_listen and auto_redirect_https in network API

GET /api/system/network now returns both fields; POST accepts them.
Enabling auto_redirect_https when https_listen is unset returns 400.
Clearing https_listen while auto-redirect is on auto-disables the
toggle. A false->true transition of auto_redirect_https sets
password_change_recommended so the dashboard can prompt rotation.
EOF
)"
```

---

## Task 6: Clear `password_change_recommended` on password change

**Files:**
- Modify: `src/web/mod.rs:1257-1296` (api_change_password)

- [ ] **Step 1: Add the clear-flag logic**

In `api_change_password` at line 1286, after `state.auth.reset_password(...)` succeeds, add a config load-and-save:

```rust
    match state.auth.reset_password(user.id, &req.new_password).await {
        Ok(()) => {
            // Clear the password-rotation flag if set. Best-effort: swallow
            // save errors since the password change itself succeeded.
            if let Ok(mut config) = Config::load(&state.config_path) {
                if config.web.password_change_recommended {
                    config.web.password_change_recommended = false;
                    if let Err(e) = config.save(&state.config_path) {
                        tracing::warn!(
                            "Failed to clear password_change_recommended: {}",
                            e
                        );
                    } else {
                        tracing::info!(
                            "Password changed — cleared password_change_recommended"
                        );
                    }
                }
            }
            Ok(StatusCode::OK)
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response()),
    }
```

- [ ] **Step 2: Build**

Run: `cargo build`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat(web): clear password_change_recommended on successful password change"
```

---

## Task 7: Add `GET /api/system/security-status` endpoint

**Files:**
- Modify: `src/web/mod.rs` (new handler + route registration)

- [ ] **Step 1: Add the handler**

Near the other `/api/system` handlers in `src/web/mod.rs` (for example after `api_get_ipv6` around line 1890), add:

```rust
async fn api_security_status(
    axum::Extension(_user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Response {
    let is_https_request = request.extensions().get::<IsHttps>().is_some();
    let config = Config::load(&state.config_path).unwrap_or_default();
    Json(serde_json::json!({
        "is_https_request": is_https_request,
        "password_change_recommended": config.web.password_change_recommended,
        "https_available": config.web.https_listen.is_some(),
    }))
    .into_response()
}
```

- [ ] **Step 2: Register the route**

In `run_web_server` near the other `/api/system/*` routes (around line 424), add:

```rust
        .route("/api/system/security-status", get(api_security_status))
```

- [ ] **Step 3: Build**

Run: `cargo build`
Expected: PASS.

- [ ] **Step 4: Manual smoke test**

Start the server and curl the endpoint with an auth cookie. Expected JSON shape:
```json
{"is_https_request":false,"password_change_recommended":false,"https_available":true}
```

- [ ] **Step 5: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat(web): add GET /api/system/security-status for dashboard banners"
```

---

## Task 8: Integration test — sensitive middleware blocks HTTP

**Files:**
- Test: append a new test module at the bottom of `src/web/mod.rs`

- [ ] **Step 1: Add the test**

At the bottom of `src/web/mod.rs`:

```rust
#[cfg(test)]
mod sensitive_https_middleware_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn build_test_router() -> Router {
        Router::new()
            .route(
                "/api/system/tls/upload",
                post(|| async { StatusCode::OK }),
            )
            .layer(axum::middleware::from_fn(sensitive_https_middleware))
    }

    #[tokio::test]
    async fn blocks_http_request_to_sensitive_path() {
        let app = build_test_router();
        let req = Request::builder()
            .method("POST")
            .uri("/api/system/tls/upload")
            .body(Body::empty())
            .unwrap();
        // Note: no IsHttps extension => treated as HTTP
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn allows_https_request_to_sensitive_path() {
        let app = build_test_router();
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/system/tls/upload")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(IsHttps);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn allows_http_to_non_sensitive_path() {
        // A path not in SENSITIVE_PATHS should pass through over HTTP
        let app = Router::new()
            .route("/api/stats", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn(sensitive_https_middleware));
        let req = Request::builder()
            .method("GET")
            .uri("/api/stats")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
```

**Dependency check:** `tower` must be a `[dev-dependencies]` or `[dependencies]` entry with the `ServiceExt` feature. Run `grep '^tower' Cargo.toml` first — if it's not listed with `ServiceExt` available, add to `[dev-dependencies]`:

```toml
[dev-dependencies]
tower = { version = "0.5", features = ["util"] }
```

- [ ] **Step 2: Run the tests**

Run: `cargo test --lib sensitive_https_middleware_tests`
Expected: 3 PASS.

- [ ] **Step 3: Commit**

```bash
git add src/web/mod.rs Cargo.toml
git commit -m "test(web): integration tests for sensitive_https_middleware"
```

---

## Task 9: Integration test — network API transitions

**Files:**
- Test: extend the test module in Task 8 (or create a sibling module)

- [ ] **Step 1: Read how existing network tests are structured**

Run: `grep -n 'fn api_update_network_test\|test_update_network\|network_test' src/web/mod.rs`

If tests already exist for `api_update_network`, extend them. Otherwise, this task focuses on hand-verification via curl and defers automated coverage to the next phase — the tests require a lot of AppState fixture setup that doesn't exist yet. **Skip this task if no existing network-handler tests are present**, document in the commit that manual verification is the coverage for this change. Otherwise, add:

```rust
#[tokio::test]
async fn update_network_rejects_auto_redirect_without_https_listen() {
    // Pseudocode — adapt to existing test fixture
    let state = test_state_with_config(|cfg| {
        cfg.web.https_listen = None;
        cfg.web.auto_redirect_https = false;
    });
    let req = UpdateNetworkRequest {
        auto_redirect_https: Some(true),
        ..Default::default()
    };
    let resp = api_update_network(State(state), extension(admin_user()), Json(req)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_network_sets_password_flag_on_auto_redirect_enable() {
    let state = test_state_with_config(|cfg| {
        cfg.web.https_listen = Some(vec!["0.0.0.0:9854".to_string()]);
        cfg.web.auto_redirect_https = false;
        cfg.web.password_change_recommended = false;
    });
    let req = UpdateNetworkRequest {
        auto_redirect_https: Some(true),
        ..Default::default()
    };
    let _ = api_update_network(State(state.clone()), extension(admin_user()), Json(req)).await;
    let saved = Config::load(&state.config_path).unwrap();
    assert!(saved.web.password_change_recommended);
}
```

- [ ] **Step 2: Run tests if added**

Run: `cargo test --lib web::`
Expected: PASS. If fixtures don't exist, note the skip.

- [ ] **Step 3: Commit**

```bash
git add src/web/mod.rs
git commit -m "test(web): transition tests for api_update_network (if fixtures exist)"
```

---

## Task 10: Frontend — extend NETWORK_LISTENERS and add HTML markup

**Files:**
- Modify: `src/web/dashboard.html:3794-3800` (NETWORK_LISTENERS)
- Modify: `src/web/dashboard.html` network section HTML (search for the DoT/DoH/DoQ row markup)

- [ ] **Step 1: Add the HTTPS row to NETWORK_LISTENERS**

At line 3794, change the array to:

```js
        const NETWORK_LISTENERS = [
            { prefix: 'net-dns', key: 'dns.listen', serverKey: 'dns_listen', label: 'DNS Server', required: true, defaultPort: '53' },
            { prefix: 'net-web', key: 'web.listen', serverKey: 'web_listen', label: 'Web Dashboard (HTTP)', required: true, defaultPort: '9853' },
            { prefix: 'net-web-https', key: 'web.https_listen', serverKey: 'https_listen', label: 'Web Dashboard (HTTPS)', required: false, toggleId: 'toggle-web-https', proto: 'https', defaultPort: '9854' },
            { prefix: 'net-dot', key: 'dns.dot_listen', serverKey: 'dot_listen', label: 'DNS-over-TLS', required: false, toggleId: 'toggle-dot', proto: 'dot', defaultPort: '853' },
            { prefix: 'net-doh', key: 'dns.doh_listen', serverKey: 'doh_listen', label: 'DNS-over-HTTPS', required: false, toggleId: 'toggle-doh', proto: 'doh', defaultPort: '443' },
            { prefix: 'net-doq', key: 'dns.doq_listen', serverKey: 'doq_listen', label: 'DNS-over-QUIC', required: false, toggleId: 'toggle-doq', proto: 'doq', defaultPort: '853' },
        ];
```

- [ ] **Step 2: Find the existing HTML row template**

Run: `grep -n 'toggle-dot\|net-dot-ipv4' src/web/dashboard.html`

Read the surrounding context (~30 lines before and after) to identify the pattern used to render the DoT row. Copy that pattern into a new row for `net-web-https`:

Expected form — add a block like:
```html
<div class="network-row">
    <label class="network-label">
        <input type="checkbox" id="toggle-web-https">
        <span>Web Dashboard (HTTPS)</span>
    </label>
    <div class="network-ports">
        <label>
            <span>IPv4 port</span>
            <input type="number" id="net-web-https-ipv4-port" placeholder="9854" min="1" max="65535">
        </label>
        <label>
            <span>IPv6 port</span>
            <input type="number" id="net-web-https-ipv6-port" placeholder="9854" min="1" max="65535">
        </label>
    </div>
</div>
```

Adapt the exact markup to match the existing DoT/DoH/DoQ row structure — do not invent new CSS classes.

- [ ] **Step 3: Add the auto-redirect toggle row**

Below the new HTTPS row, add a standalone toggle row:

```html
<div class="network-row">
    <label class="network-label">
        <input type="checkbox" id="toggle-auto-redirect-https">
        <span>Auto-redirect HTTP → HTTPS</span>
    </label>
    <div class="network-toggle-description">
        When enabled, all plain HTTP requests are redirected to HTTPS. Requires HTTPS to be configured.
    </div>
</div>
```

(Match to existing toggle-row styling if present; otherwise inline styling is acceptable.)

- [ ] **Step 4: Manual smoke test — render the dashboard**

Rebuild with `cargo build --release`, start the server, open `http://host:9853/`. The Network tab should now show the HTTPS row and the auto-redirect toggle. Don't wire the save logic yet — that comes in Task 11.

- [ ] **Step 5: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat(dashboard): add HTTPS listener row and auto-redirect toggle markup"
```

---

## Task 11: Frontend — wire up load/save for new fields

**Files:**
- Modify: `src/web/dashboard.html` (network load/save JS, search for `api/system/network` fetch calls)

- [ ] **Step 1: Find the network load function**

Run: `grep -n 'api/system/network\|loadNetwork\|saveNetwork\|serverNetworkState' src/web/dashboard.html`

Identify (a) the function that GETs `/api/system/network` and populates `serverNetworkState`, and (b) the function that POSTs to the same endpoint.

- [ ] **Step 2: Extend the load function**

After the load function assigns `serverNetworkState`, add handling for the new fields. Example (adapt to actual code):

```js
// After serverNetworkState = await response.json();
const autoRedirectToggle = document.getElementById('toggle-auto-redirect-https');
if (autoRedirectToggle) {
    autoRedirectToggle.checked = !!serverNetworkState.auto_redirect_https;
    autoRedirectToggle.disabled = !serverNetworkState.https_listen || serverNetworkState.https_listen.length === 0;
}
```

Note: the generic `syncNetworkInputsFromServer` already handles listener rows for any entry in `NETWORK_LISTENERS` — so the HTTPS row will populate automatically via the existing loop. No changes needed there.

- [ ] **Step 3: Extend the save function**

Locate the POST body builder and add `auto_redirect_https` to the payload:

```js
const autoRedirectToggle = document.getElementById('toggle-auto-redirect-https');
const body = {
    // ...existing fields...
    auto_redirect_https: autoRedirectToggle ? autoRedirectToggle.checked : false,
};
```

The save function already posts to `/api/system/network`, which now accepts `https_listen` and `auto_redirect_https`. The existing `https_listen` serialization from the generic listener loop should work — verify by inspecting the built payload in devtools after Task 10's row is wired.

- [ ] **Step 4: Add disable-toggle-when-https-unset logic**

When the HTTPS toggle in the Network tab is unchecked (meaning `https_listen` will be cleared on save), grey out the auto-redirect toggle and uncheck it. Add an event listener to `toggle-web-https`:

```js
document.getElementById('toggle-web-https').addEventListener('change', (e) => {
    const redirectToggle = document.getElementById('toggle-auto-redirect-https');
    if (!e.target.checked && redirectToggle) {
        redirectToggle.checked = false;
        redirectToggle.disabled = true;
    } else if (redirectToggle) {
        redirectToggle.disabled = false;
    }
});
```

- [ ] **Step 5: Manual verification**

Open the Network tab in the browser. Toggle the HTTPS row off → auto-redirect toggle disables. Toggle it back on → auto-redirect re-enables. Save → reload → state is preserved in config.

- [ ] **Step 6: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat(dashboard): wire network tab load/save for auto_redirect_https"
```

---

## Task 12: Frontend — global HTTP warning banner

**Files:**
- Modify: `src/web/dashboard.html` (add banner markup, CSS, init logic)

- [ ] **Step 1: Add banner markup**

At the top of the dashboard `<body>` or the main dashboard container (find via `grep -n '<main\|dashboardMain\|id="main"' src/web/dashboard.html`), add:

```html
<div id="httpWarningBanner" class="security-banner security-banner--danger" style="display:none;">
    <span class="security-banner__icon">⚠</span>
    <div class="security-banner__body">
        <strong>You're connected over plain HTTP.</strong>
        Sensitive settings (certificates, ACME tokens, password changes) are disabled.
    </div>
    <a id="httpWarningSwitchBtn" class="security-banner__action" href="#">Switch to HTTPS →</a>
</div>
```

- [ ] **Step 2: Add CSS**

Near the existing dashboard CSS block (search for `.cert-tabs {` as a landmark), add:

```css
.security-banner {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    margin: 12px 0;
    border-radius: 6px;
    font-size: 14px;
}
.security-banner--danger {
    background: #fff2f0;
    border: 1px solid #ffccc7;
    color: #a8071a;
}
.security-banner--warning {
    background: #fffbe6;
    border: 1px solid #ffe58f;
    color: #874d00;
}
.security-banner__icon { font-size: 18px; }
.security-banner__body { flex: 1; }
.security-banner__action {
    padding: 6px 12px;
    background: currentColor;
    color: #fff;
    text-decoration: none;
    border-radius: 4px;
    font-weight: 600;
}
```

Adapt colors to the dashboard's existing palette (reference any existing alert/banner styling in the file).

- [ ] **Step 3: Add init logic**

In the dashboard init/DOMContentLoaded block, add:

```js
(function setupHttpBanner() {
    const banner = document.getElementById('httpWarningBanner');
    if (!banner) return;
    if (window.location.protocol !== 'http:') return;
    banner.style.display = 'flex';

    // Build the HTTPS URL from network config
    const btn = document.getElementById('httpWarningSwitchBtn');
    fetch('/api/system/network', { credentials: 'include' })
        .then(r => r.json())
        .then(data => {
            const httpsAddrs = data.https_listen || [];
            if (httpsAddrs.length === 0) {
                btn.style.display = 'none';
                return;
            }
            // Take the first entry and extract the port
            const first = httpsAddrs[0];
            const port = first.includes(':') ? first.split(':').pop() : '9854';
            const url = `https://${window.location.hostname}:${port}${window.location.pathname}${window.location.search}`;
            btn.href = url;
        })
        .catch(() => { btn.style.display = 'none'; });
})();
```

- [ ] **Step 4: Manual verification**

Reload the dashboard over HTTP. Banner visible with a working "Switch to HTTPS" button. Over HTTPS: banner hidden.

- [ ] **Step 5: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat(dashboard): global HTTP warning banner with Switch to HTTPS button"
```

---

## Task 13: Frontend — password-change recommendation banner

**Files:**
- Modify: `src/web/dashboard.html`

- [ ] **Step 1: Add banner markup**

Below the HTTP warning banner in Task 12:

```html
<div id="passwordRotationBanner" class="security-banner security-banner--warning" style="display:none;">
    <span class="security-banner__icon">🔑</span>
    <div class="security-banner__body">
        <strong>HTTPS is now active.</strong>
        Your account password may have been transmitted in plaintext before HTTPS was enabled. We recommend changing it now.
    </div>
    <a id="passwordRotationBtn" class="security-banner__action" href="#">Change password →</a>
</div>
```

- [ ] **Step 2: Wire init logic — poll security-status**

Add to the init block:

```js
async function refreshSecurityStatus() {
    try {
        const res = await fetch('/api/system/security-status', { credentials: 'include' });
        if (!res.ok) return;
        const status = await res.json();
        const banner = document.getElementById('passwordRotationBanner');
        if (!banner) return;
        // Only show on HTTPS — on HTTP, the HTTP banner takes precedence
        if (status.password_change_recommended && window.location.protocol === 'https:') {
            banner.style.display = 'flex';
        } else {
            banner.style.display = 'none';
        }
    } catch (e) {
        // silent — the banner simply doesn't show
    }
}

refreshSecurityStatus();
```

- [ ] **Step 3: Wire the "Change password" button**

Find how the existing dashboard opens the password-change form (likely a modal or tab). Update the banner button to invoke that. Example:

```js
document.getElementById('passwordRotationBtn').addEventListener('click', (e) => {
    e.preventDefault();
    // Call existing function that opens the password-change UI:
    openChangePasswordModal();  // replace with actual function name
});
```

Run `grep -n 'change-password\|changeNewPassword\|openPassword' src/web/dashboard.html` to find the actual handler.

- [ ] **Step 4: Refresh on password-change success**

Find the existing password-change submit handler (search for `/api/auth/change-password`) and call `refreshSecurityStatus()` after a successful response so the banner disappears.

- [ ] **Step 5: Manual verification**

1. Set `password_change_recommended = true` in config.toml manually, restart server.
2. Load dashboard over HTTPS → banner visible.
3. Click "Change password" → form opens.
4. Change password → banner disappears, config flag cleared.

- [ ] **Step 6: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat(dashboard): password rotation banner on HTTPS after first enforcement"
```

---

## Task 14: Frontend — sensitive form inline replacement

**Files:**
- Modify: `src/web/dashboard.html`

- [ ] **Step 1: Identify the three sensitive form containers**

Run: `grep -n 'uploadCertFile\|cloudflare_api_token\|changeNewPassword' src/web/dashboard.html`

You'll find:
- Cert upload form (around line 3496, `certTabUpload` container)
- ACME provider-token form (around line 3454, `certTabAcme` container — the input field for Cloudflare API token)
- Password-change form (around line 2737, the modal body)

- [ ] **Step 2: Add `data-requires-https` markers**

For each of the three form containers, add `data-requires-https="true"` attribute:

```html
<div class="cert-tab-content" id="certTabUpload" data-requires-https="true">
    ...
</div>
```

Repeat for `certTabAcme` and the password-change modal body.

- [ ] **Step 3: Add CSS for the warning replacement**

Add to the CSS block:

```css
.sensitive-warning {
    padding: 24px;
    border: 1px dashed var(--border, #ccc);
    border-radius: 6px;
    text-align: center;
    color: var(--text-muted, #888);
}
.sensitive-warning__icon { font-size: 28px; display: block; margin-bottom: 8px; }
.sensitive-warning__title { font-weight: 600; color: var(--text, #333); margin-bottom: 8px; }
.sensitive-warning__btn {
    display: inline-block;
    margin-top: 12px;
    padding: 8px 16px;
    background: var(--accent, #1890ff);
    color: #fff;
    text-decoration: none;
    border-radius: 4px;
}
```

- [ ] **Step 4: Add init-time replacement logic**

Add to the init block, AFTER the Task 12 HTTPS-URL resolution so we can reuse the URL:

```js
function applySensitiveFormGuards(httpsUrl) {
    if (window.location.protocol !== 'http:') return;
    const warningHtml = `
        <div class="sensitive-warning">
            <span class="sensitive-warning__icon">🔒</span>
            <div class="sensitive-warning__title">This feature requires HTTPS</div>
            <div>You're connected over plain HTTP. Switch to HTTPS to use this feature.</div>
            ${httpsUrl ? `<a class="sensitive-warning__btn" href="${httpsUrl}">Switch to HTTPS →</a>` : ''}
        </div>
    `;
    document.querySelectorAll('[data-requires-https="true"]').forEach((el) => {
        el.innerHTML = warningHtml;
    });
}
```

And call it from within the `setupHttpBanner` fetch-then block in Task 12 with the constructed HTTPS URL, OR call it with `null` if no HTTPS URL is available:

```js
// Inside the fetch().then block in setupHttpBanner:
const url = `https://${window.location.hostname}:${port}${window.location.pathname}${window.location.search}`;
btn.href = url;
applySensitiveFormGuards(url);
```

- [ ] **Step 5: Manual verification**

1. Load the dashboard over HTTP.
2. Open the cert upload tab → replaced with warning card.
3. Open the ACME tab → replaced with warning card.
4. Open the password change modal → replaced with warning card.
5. Switch to HTTPS → forms render normally.

- [ ] **Step 6: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat(dashboard): inline replace sensitive forms with HTTPS warning over HTTP"
```

---

## Task 15: End-to-end manual verification

**Files:** None modified. This is a full-path smoke test.

- [ ] **Step 1: Build release**

Run: `cargo build --release`
Expected: PASS.

- [ ] **Step 2: Start fresh**

Back up current config, delete it so the server regenerates defaults:
```bash
cp config.toml config.toml.bak
rm config.toml
./target/release/oxi-dns config.toml
```

Expected log lines include `Web admin HTTPS listening on 0.0.0.0:9854` (or similar, via self-signed cert).

- [ ] **Step 3: Test HTTP banner and form replacement**

Open `http://<host>:9853/` in a browser (after login).
- Red banner at top: "You're connected over plain HTTP..."
- Cert upload tab: warning card
- ACME tab: warning card
- Password change modal: warning card

- [ ] **Step 4: Test HTTP 403 for sensitive API**

Run:
```bash
curl -i -X POST http://<host>:9853/api/system/tls/upload \
  -H "Cookie: <auth cookie>" \
  -H "Content-Type: application/json" \
  -d '{}'
```
Expected: `HTTP/1.1 403 Forbidden` with JSON body `{"error":"This endpoint requires HTTPS...","code":"https_required"}`.

- [ ] **Step 5: Switch to HTTPS and verify forms render**

Open `https://<host>:9854/` (accept self-signed warning).
- HTTP banner gone
- Cert upload, ACME, password-change forms all functional.

- [ ] **Step 6: Enable HTTPS port edit**

In Network tab, change HTTPS port from 9854 → 9855. Save. Verify:
- Server logs a rebind on 9855
- `https://<host>:9855/` works
- `https://<host>:9854/` no longer responds

- [ ] **Step 7: Enable auto-redirect**

Flip the auto-redirect toggle ON. Save.
- `curl -I http://<host>:9853/` returns 301 to `https://<host>:9855/`
- Dashboard over HTTPS now shows the password-rotation banner

- [ ] **Step 8: Change password**

Change password via the form. Verify:
- Banner disappears
- `config.toml` shows `password_change_recommended = false`

- [ ] **Step 9: Disable auto-redirect**

Flip the toggle off. Save.
- `http://<host>:9853/` serves the dashboard again (not a redirect)
- Cert upload tab still shows the warning card over HTTP
- Password-rotation banner does not reappear

- [ ] **Step 10: Clear https_listen while auto-redirect is on**

Re-enable auto-redirect (toggle ON). Save. Verify it's on. Then toggle the HTTPS listener OFF and save. Verify:
- Server logs "auto_redirect_https automatically disabled"
- `config.toml` shows both `https_listen = null` (or missing) and `auto_redirect_https = false`

- [ ] **Step 11: Restore config**

```bash
mv config.toml.bak config.toml
```

- [ ] **Step 12: Commit any loose ends**

If the walkthrough exposed bugs, create a follow-up commit with the fix. Otherwise, no commit needed — this task is verification only.

---

## Self-review checklist (done before handoff)

**Spec coverage:**
- Config schema → Task 1 ✓
- Middleware simplification → Task 3 ✓
- `run_web_server` branch → Task 4 ✓
- Network API fields → Task 5 ✓
- Password-change hook → Task 6 ✓
- Security-status endpoint → Task 7 ✓
- Middleware integration test → Task 8 ✓
- Reconfigure guard → Task 2 ✓
- Dashboard HTTPS row → Task 10 ✓
- Auto-redirect toggle → Task 10-11 ✓
- HTTP banner → Task 12 ✓
- Password rotation banner → Task 13 ✓
- Sensitive form inline replacement → Task 14 ✓
- End-to-end manual verification → Task 15 ✓

**Type consistency:**
- `auto_redirect_https: bool`, `password_change_recommended: bool` — consistent across config, API, frontend
- `is_https_request` / `password_change_recommended` / `https_available` — consistent field names in `/api/system/security-status`
- `IsHttps` marker struct reused across all middleware checks

**No placeholders:** All tasks have concrete code or exact commands. Task 9 explicitly notes "skip if fixtures don't exist" as a deliberate scope decision (not a placeholder).
