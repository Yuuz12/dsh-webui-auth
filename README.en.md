# dsh-webui-auth

English | [中文](README.md)

A persistent WebUI authentication plugin for DeepSeek Harness. Once you create an account/password in **Settings → 身份认证 (Authentication)** or via the first-run login page, **unauthenticated browsers cannot load any WebUI resource, call any API, or open any realtime connection** — authentication is enforced at the HTTP/transport layer and cannot be bypassed through browser devtools.

## Architecture

Authentication is enforced in four layers, all implemented by **wrapping the webServer routes at runtime — no DSH core package source is modified**:

| Layer | Mechanism | Unauthenticated behavior |
|---|---|---|
| WebUI resources (index.html, /assets/*, SPA routes) | Plugin registers a `prefix ''` catch-all route; after session validation it hands off to frontend-static | 302 → login page |
| Plugin bundles (/plugins/*) | Wraps the `/plugins` prefix route handler at runtime | 401 |
| /api RPC surface | Wraps the `/api` prefix route handler at runtime | 401 |
| WebSocket (`/api/remote.mux`; legacy cores `/api/events.mux`, `/api/events.host`) | Wraps the upgrade route handlers at runtime | 401 upgrade rejected |

- **No core patching**: a DSH upgrade never overwrites patches and never leaves `/api` exposed after an upgrade. Every startup re-wraps the route tables, with a 2s→10s rescan loop that catches late-registered routes. **On v0.1.2-alpha.2+ the event-stream WebSocket lives at `/api/remote.mux` (registered by dsh-api-gateway); the candidate list adapts automatically, so the plugin no longer falsely reports "upgrade route missing".**
- **Fail-closed**: if the expected routes are missing (DSH internals changed so wrapping can't apply), `setup`/`configure` **refuse to enable authentication** and the problem is reported both in the host log and on the settings page — better unusable than "login enabled with an unprotected /api".
- **Cooperation with the core's own browser auth (v0.1.2-alpha.2+)**: that core version ships launch-token exchange with an origin-bound signed cookie (`dsh-auth-*`) guarding `/` and `/api`. After a successful plugin login the browser is automatically sent to the core's token-bearing root URL so the core cookie exchange runs too; `/api` requests pass through **unchanged** after the plugin session check (no more Host/Origin rewrite, which would break the core's cookie/Host binding). Both gates apply: a browser must hold the plugin session cookie **and** the core cookie.
- **Privileged methods behind a reverse proxy / LAN (legacy cores ≤ alpha.1)**: after the session check the plugin hands authenticated requests to the core in a "loopback shape", so the core's **loopback-pinned privileged methods** (settings/credentials/agentPreset/llm.discoverModels) work in proxied deployments — the session-cookie gate is a strictly stronger identity proof than the Host-header heuristic it replaces.
- **WebSocket and `trustedHosts`**: the WS upgrade handshake still goes through the core's own `requestRejection` / `isTrustedApiRequest`, so **in reverse-proxy / LAN deployments (non-loopback Host) you must also add the public hostname to `client-connection.trustedHosts` in the DSH config**, otherwise even authenticated upgrades are rejected.

Sessions are **server-side and persisted to disk** (`sessions.jsonl`, survive a DSH restart, expire server-side), carried by an `HttpOnly; SameSite=Lax` cookie (`dsh_wua_session`) that JS cannot read; changing the password **revokes every other session**.

## Installation

This plugin is a standard **bundle**, published on npm — the official `dsh plugin` command is the recommended way to install it. The manual method is kept as a fallback. Prerequisite: pnpm on the machine (Node ships corepack — run `corepack enable pnpm` to activate it).

### Method 1: npm install (recommended)

```sh
npx @deepseek-ai/dsh plugin --profile web add dsh-webui-auth
```

Pulls the prebuilt package from the npm registry (plain JS — no prepare script, no build authorization), adds the dependency and appends it to the `dsh.profile.bundles` list; the plugin row is inserted automatically via the bundle layer.

### Method 2: GitHub install

```sh
npx @deepseek-ai/dsh plugin --profile web add github:Yuuz12/dsh-webui-auth
```

Fetches the repository source (works directly — no build step either). Prefer Method 1 when the network to GitHub is unreliable.

### Method 3: manual (fallback)

1. Put the `dsh-webui-auth` directory into `profiles/web/node_modules/`
2. Add one row to the `insert` list in `profiles/web/cordis.patch.yml`:

```yaml
    - id: dsh-webui-auth
      name: 'dsh-webui-auth'
```

> Maintainer dev mode: `dsh plugin --profile web add ./dsh-webui-auth` from a local source checkout (`link:` install) — edit code, restart DSH, done; no reinstall needed.

### Common to all methods

**No core-package patches are needed** (no `[dsh-webui-auth patch]` markers, no `node_modules` edits) — just restart DSH. On startup the host log prints `[dsh-webui-auth] started, credentials file: ...`; if the route wrapping is incomplete it prints `ROUTE GATE INCOMPLETE` and authentication cannot be enabled (fail-closed).

## Uninstallation

### Method 1: `dsh plugin` command (for method-1 installs)

1. `npx @deepseek-ai/dsh plugin --profile web remove dsh-webui-auth` (removes both the dependency and the bundle layer)
2. Restart DSH

### Method 2: manual (for method-2 installs)

1. **Delete the plugin directory** `profiles/web/node_modules/dsh-webui-auth/` (since 0.3.1 runtime data lives outside the package, deleting it does not touch the account; to wipe the account too, also delete the `.dsh-webui-auth/` data directory — see "Data file locations")
2. **Remove the mount row** from `profiles/web/cordis.patch.yml`:

```yaml
    - id: dsh-webui-auth
      name: 'dsh-webui-auth'
```

   This step is required — otherwise the loader fails at startup because the package is missing.
3. **Restart DSH**

With either method, after the restart authentication is fully disabled (**no core sources to restore** — the plugin never modified core files). To also clear persisted sessions, delete `sessions.jsonl` in the data directory. If you previously used the older pre-hardening build, the leftover `dsh-webui-auth.session` key in browser localStorage is harmless and may be removed optionally.

## Usage

- **First enable (setup token required)**: while no credentials exist, authentication is off (all requests pass), but creating the administrator account requires a **per-boot setup token** — open WebUI → Settings → 身份认证 (Authentication), or visit `/dsh-webui-auth/login`, enter the token printed in the startup log as `[dsh-webui-auth] setup token (...)` (or read the `setup-token` file in the data directory, mode 0600), then create an account/password (≥8 characters, must include uppercase, lowercase, digit and special character). The token is regenerated on every boot and deleted once setup succeeds, preventing someone from claiming the administrator account in the "exposed before configured" window.
- **Username rule**: 3-32 characters of letters, digits, underscore or hyphen (enforced on create/change; legacy accounts are unaffected and can still log in).
- **Afterwards**: any unauthenticated visit to any path redirects to the login page; after login you stay signed in for the chosen **session lifetime** (browser session / 1 hour / 12 hours (default) / 1 day / 3 days), enforced server-side by expiry. **Sessions are persisted to disk — after a DSH restart logged-in devices stay signed in** (the expiry still applies). "Browser session" mode: the 30-minute window slides with activity, and closing the browser logs you out.
- **Change / disable / log out**: Settings → 身份认证 (all require the current password); changing the password revokes every other logged-in session.
- **Forgot password**: delete `dsh-webui-auth.json` in the data directory — a background check every minute disables authentication within at most 1 minute (no restart needed), then create a new account with a fresh setup token.

## Where data files live (depends on install mode)

Credentials and security data are stored in the **runtime data directory**, chosen automatically by install mode:

- **npm / GitHub / tarball installs**: the package lives inside `node_modules`, which is wholesale replaced on upgrade, reinstall or cleanup — so data is stored in a `.dsh-webui-auth/` directory **next to that `node_modules`** (usually the profile root, e.g. `~/.dsh/profiles/web/.dsh-webui-auth/`). Upgrading the plugin, `pnpm clean`, or reinstalling DSH no longer loses the account or login sessions.
- **Local link / source installs** (`dsh plugin add ./dsh-webui-auth`): the plugin source directory itself (managed with the repo and excluded from git via `.gitignore`; deleting the whole source checkout is what deletes the data).
- **Fallback**: when none of the above is writable, `$DSH_HOME/dsh-webui-auth/` (default `~/.dsh/dsh-webui-auth/`) is used.

Upgrading from 0.3.x: runtime data is **not migrated automatically**. If the legacy data (inside the package directory or `~/.dsh/dsh-webui-auth/`) still exists, copy `dsh-webui-auth.json`, `sessions.jsonl`, `audit-hmac-key` and `audit.jsonl` from the table below into the new data directory manually (for npm / GitHub / tarball installs that is `.dsh-webui-auth/` next to `node_modules`); otherwise just recreate the account with a fresh setup token (see "Forgot password").

Files in the data directory:

| File | Purpose | Permissions |
|---|---|---|
| `dsh-webui-auth.json` | Credentials (scrypt hash, v3 format; 0.2.x v2 credentials still verify and log in) | — |
| `audit.jsonl` | Audit log (IPs pseudonymized, see "Audit log") | — |
| `sessions.jsonl` | Persisted sessions (restart recovery) | 0600 |
| `audit-hmac-key` | HMAC key for audit-IP pseudonymization (auto-generated once) | 0600 |
| `setup-token` | First-run setup token (deleted after setup succeeds) | 0600 |

The data directory is chosen by install mode (npm / GitHub / tarball → `.dsh-webui-auth/` next to `node_modules`; link / source → the plugin source directory; fallback `$DSH_HOME/dsh-webui-auth/`); the "forgot password", audit and session paths above refer to that data directory.

## Audit log

Security events — login success/failure/rate-limit, setup, configure, disable, logout — are **appended as JSONL to `audit.jsonl`** in the data directory (timestamp, username, IP, user-agent, detail). **Client IPs are pseudonymized with HMAC-SHA256** (e.g. `hmac:5151e752|203.0.113.0/24`, with the /24 (IPv4) or /64 (IPv6) network prefix kept in cleartext for aggregation); raw addresses are never written to disk. Two ways to view:

- **CLI** (recommended): run `node index.js audit [--limit N]` (last 20 entries by default; run from the module path):
  ```sh
  node index.js audit --limit 50
  ```
- **Settings page**: Settings → 身份认证 → "最近登录记录" (Recent activity) shows the last 8 entries.

Audit write failures never block authentication (only a host-log warning).

## Appearance

Both the login page and the "Settings → 身份认证 (Authentication)" settings page follow DSH's **built-in appearance setting** (Settings → General → Appearance: Light / Dark / System); no separate appearance switch is provided. The settings page lives inside the WebUI and consumes DSH's theme tokens directly, so it tracks light/dark automatically. The login page is a standalone page: the server reads the current appearance preference (settings `ui-theme.preference`), injects it into the page, and the page mirrors DSH's boot logic — `System` resolves via `prefers-color-scheme` and reacts live to OS changes. The login response is served with `cache-control: no-store`, so a refresh picks up any appearance change immediately.

## What to do after upgrading DSH

**Nothing.** The plugin never modifies core packages — after a DSH upgrade the runtime route wrapping is re-applied automatically on startup. **On v0.1.2-alpha.2+** the plugin adapts to the `/api/remote.mux` event-stream route and cooperates with the core's built-in browser auth (launch-token ↔ signed cookie): after logging into the plugin, the browser is automatically guided through the core authentication, after which the WebUI works normally. If the wrapping is incomplete (DSH internals changed), the host log prints `ROUTE GATE INCOMPLETE`, the settings page shows a red warning, and `setup`/`configure` refuse to enable authentication (fail-closed).

> **Note (v0.1.2-alpha.2+)**: the core's browser auth requires the browser to first exchange the launch token for the core cookie (the `?token=` URL printed by `dsh web` / DSH Desktop). The plugin performs that exchange automatically; if a browser has never visited that address, open the full URL printed at DSH startup once (or log in via the plugin's login page — the exchange happens automatically).

## Data & Security

- Passwords are hashed with **scrypt** (Node's built-in memory-hard KDF — GPU/ASIC resistant, zero dependencies) and stored in `dsh-webui-auth.json` in the data directory (location depends on install mode, see above); plaintext is never written to disk. Credentials format is v3 (same scrypt encoding as v2 — only the version marker and field semantics changed); **0.2.x v2 credentials still verify**. **Since 0.2.0 only scrypt hashes are accepted**: 0.1.x SHA-256 credentials can no longer be verified — delete the credentials file and recreate the account (see "Forgot password").
- Login rate limiting: **per client IP**, at most 5 failures per minute — a single attacker can no longer lock out other users (or the operator). Behind a reverse proxy the client IP is taken from `CF-Connecting-IP` / the leftmost `X-Forwarded-For`, and the proxy headers are trusted **only when the socket peer is loopback** (local caddy/cloudflared) — remote callers cannot spoof them. Failed verifications also run a dummy scrypt pass so "unknown account" and "wrong password" take the same time, defeating username enumeration via response timing.
- First-run setup requires a **per-boot setup token** (128-bit, printed to the host log and written to `setup-token` in the data directory, mode 0600), preventing account claiming in the "exposed before configured" window.
- Audit log: `audit.jsonl`, client IPs pseudonymized with HMAC (see "Audit log").
- Persisted sessions: `sessions.jsonl` (0600), restored on restart; a write failure never affects authentication — the settings page just warns that a restart will require re-login.
- Security headers on the login page and API responses: strict CSP, `nosniff`, `DENY` framing, `no-referrer`, `noindex`, `no-store`.
- Cookie `HttpOnly + SameSite=Lax`: not readable by JS, not sent on cross-site requests.
- The login/setup endpoints are intentionally public (the entry point of authentication): `/dsh-webui-auth/login` and `/dsh-webui-auth/setup` (the latter protected by the setup token).

## Known limits

- **Inherent runtime-wrapping window**: between a route-object replacement (service hot-reload) and the next rescan (≤10s) there is an unprotected window; the fail-closed check on enabling covers the "initially exposed" case, so this window only affects hot-reload during runtime.
- **WebSocket and `trustedHosts`**: in reverse-proxy / LAN deployments (non-loopback Host), WS downlinks need the public hostname added to `client-connection.trustedHosts` in the DSH config (see "Architecture").
- **Proxy on a different host**: if the reverse proxy is not on the same machine as DSH (non-loopback peer), the proxy headers are not trusted and rate limiting aggregates per proxy IP (degrades to a global bucket).
- **Limits of audit pseudonymization**: the HMAC key lives in the same data directory (0600); a local attacker who can read it can brute-force the IP space — pseudonymization protects against "plaintext IPs at rest", not against an attacker with file access.
- Sessions live in `sessions.jsonl`: they survive restarts (expiry unchanged); uninstalling/disabling the plugin does not affect credentials.
- Threat model is "browser/network clients": local processes that can read/write the host's memory or files are out of scope.
