# Cross-Platform Compatibility: Linux, macOS, FreeBSD

**Date:** 2026-03-29
**Status:** Draft
**Scope:** Ensure oxi-hole compiles and runs correctly on Linux, macOS, and FreeBSD. Other platforms should use Docker.

## Context

The release CI already builds binaries for Linux (amd64/arm64/armv7), macOS (amd64/arm64), and FreeBSD (amd64). However, the Rust source has two hardcoded `/tmp/` paths that assume Linux-style temp directories, and there's no compile-time guard preventing accidental non-Unix builds. The CI only runs checks on Linux.

## Changes

### 1. Replace hardcoded `/tmp/` paths with `std::env::temp_dir()`

**File:** `src/update.rs`

- Line 154: `/tmp/oxi-hole-update` → `std::env::temp_dir().join("oxi-hole-update")`
- Line 332: `/tmp/oxi-hole.ready` → `std::env::temp_dir().join("oxi-hole.ready")`

`std::env::temp_dir()` returns the platform-appropriate temp directory on all targets. The returned values are already used as `PathBuf`, so no downstream changes are needed.

### 2. Add compile-time guard for non-Unix platforms

**File:** `src/main.rs`

Add at the top of the file:

```rust
#[cfg(not(unix))]
compile_error!("oxi-hole only supports Unix platforms (Linux, macOS, FreeBSD). Use Docker for other platforms.");
```

This gives a clear error message instead of scattered compile failures from `#[cfg(unix)]` blocks, `SO_REUSEPORT`, and Unix-specific imports.

### 3. Add macOS CI runner

**File:** `.github/workflows/ci.yml`

Add a macOS job that runs `cargo check --all-targets` to catch platform-specific regressions. This ensures new code doesn't accidentally use Linux-only APIs.

The job only needs `cargo check` (not full test suite) to keep CI fast and avoid paying for expensive macOS runner minutes on the full test suite.

## What stays the same

- **`SO_REUSEPORT`**: Works on all three target platforms. No changes needed.
- **`#[cfg(unix)]` permission guards** in `src/update.rs`: Already correctly guarded. No changes needed.
- **Install script** (`scripts/install.sh`): Already handles Linux, macOS, and FreeBSD detection. No changes needed.
- **Release workflow**: Already builds for all three platforms. No changes needed.

## Out of scope

- **Windows support**: Use Docker instead.
- **Socket abstraction layers**: All three targets support `SO_REUSEPORT` with compatible-enough semantics for the zero-downtime takeover use case.
- **FreeBSD CI runner**: Cross-compilation in the release workflow provides sufficient coverage.
