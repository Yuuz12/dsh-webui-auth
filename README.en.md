# dsh-webui-auth

English | [中文](README.md)

A persistent WebUI authentication plugin for DeepSeek Harness. Once you create an account/password in **Settings → 身份认证 (Authentication)** or via the first-run login page, **unauthenticated browsers cannot load any WebUI resource, call any API, or open any realtime connection** — authentication is enforced at the HTTP/transport layer and cannot be bypassed through browser devtools.

## Architecture

Authentication is enforced in four layers:

| Layer | Mechanism | Unauthenticated behavior |
|---|---|---|
| WebUI resources (index.html, /assets/*, SPA routes) | Plugin registers a `prefix ''` catch-all route; after session validation it hands off to frontend-static | 302 → login page |
| Plugin bundles (/plugins/*) | `dsh-client-modules` patch: checks `webServer.webuiAuthGate` before serving | 302 → login page |
| /api RPC surface | `dsh-client-connection` patch: same gate before routing | 401 |
| WebSocket (/api/events.mux, /api/events.host) | Same package patch: same gate before upgrade handshake | 403 upgrade rejected |

Sessions are **server-side, in-memory**, carried by an `HttpOnly; SameSite=Lax` cookie (`dsh_wua_session`) that JS cannot read; changing the password **revokes every other session**.

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

3. **Apply the core-package patches** (no manual re-patching needed after a DSH upgrade): in
   `node_modules/@deepseek-ai/dsh-client-connection/lib/index.js` and
   `node_modules/@deepseek-ai/dsh-client-modules/lib/index.js`,
   search for `[dsh-webui-auth patch]` comments and confirm the three session-gate blocks exist (already applied in this repository). On every startup the plugin re-checks these markers: if a marker is missing and its anchor matches, the patch is re-inserted automatically (restart after a DSH upgrade is enough to recover); if the core packages were restructured so auto-patching fails, the error is reported loudly both in the host log **and on the WebUI settings page** — never silently.
4. Restart DSH

## Uninstallation

### Method 1: `dsh plugin` command (for method-1 installs)

1. `npx @deepseek-ai/dsh plugin --profile web remove dsh-webui-auth` (removes both the dependency and the bundle layer)
2. **(Optional) Restore the core packages**: delete the code blocks starting with `// [dsh-webui-auth patch]` in `dsh-client-connection/lib/index.js` (2 places) and `dsh-client-modules/lib/index.js` (1 place). **Leaving them is harmless** — once the plugin is gone the gate never triggers (the patched code is a no-op without the plugin), and a DSH upgrade overwrites them anyway.
3. Restart DSH

### Method 2: manual (for method-2 installs)

1. **(Optional) Restore the core packages** (same as above)
2. **Delete the plugin directory** `profiles/web/node_modules/dsh-webui-auth/` (the credentials file `dsh-webui-auth.json` goes with it)
3. **Remove the mount row** from `profiles/web/cordis.patch.yml`:

```yaml
    - id: dsh-webui-auth
      name: 'dsh-webui-auth'
```

   This step is required — otherwise the loader fails at startup because the package is missing.
4. **Restart DSH**

With either method, after the restart authentication is fully disabled. No browser cleanup is needed (sessions live in process memory and disappear with it; cookies become invalid). If you previously used the older pre-hardening build, the leftover `dsh-webui-auth.session` key in browser localStorage is harmless and may be removed optionally.

## Usage

- **First enable**: while no credentials exist, authentication is off (all requests pass). Open WebUI → Settings → 身份认证 (Authentication), create an account/password (≥8 characters, must include uppercase, lowercase, digit and special character) and save; or visit `/dsh-webui-auth/login` directly — the page shows a "Create administrator account" form. Authentication takes effect immediately and the current browser receives a session automatically.
- **Username rule**: 3-32 characters of letters, digits, underscore or hyphen (enforced on create/change; legacy accounts are unaffected and can still log in).
- **Afterwards**: any unauthenticated visit to any path redirects to the login page; after login you stay signed in for the chosen **session lifetime** (browser session / 1 hour / 12 hours (default) / 1 day / 3 days), enforced server-side by expiry. "Browser session" mode: the 30-minute window slides with activity, and closing the browser logs you out.
- **Change / disable / log out**: Settings → 身份认证 (all require the current password); changing the password revokes every other logged-in session.
- **Forgot password**: delete `dsh-webui-auth.json` in the plugin directory — a background check every minute disables authentication within at most 1 minute (no restart needed), then create a new account.

## Audit log

Security events — login success/failure/rate-limit, setup, configure, disable, logout — are **appended as JSONL to `audit.jsonl`** in the plugin directory (timestamp, username, IP, user-agent, detail). Two ways to view:

- **CLI** (recommended): run `node index.js audit [--limit N]` in the plugin directory (last 20 entries by default):
  ```sh
  node index.js audit --limit 50
  ```
- **Settings page**: Settings → 身份认证 → "最近登录记录" (Recent activity) shows the last 8 entries.

Audit write failures never block authentication (only a host-log warning). `audit.jsonl` is excluded via `.gitignore` and never committed.

## Appearance

Both the login page and the "Settings → 身份认证 (Authentication)" settings page follow DSH's **built-in appearance setting** (Settings → General → Appearance: Light / Dark / System); no separate appearance switch is provided. The settings page lives inside the WebUI and consumes DSH's theme tokens directly, so it tracks light/dark automatically. The login page is a standalone page: the server reads the current appearance preference (settings `ui-theme.preference`), injects it into the page, and the page mirrors DSH's boot logic — `System` resolves via `prefers-color-scheme` and reacts live to OS changes. The login response is served with `cache-control: no-store`, so a refresh picks up any appearance change immediately.

## What to do after upgrading DSH

1. Upgrade and restart DSH → the plugin detects the missing core patches and re-inserts them automatically (host log records `re-applied core patch`)
2. At this point the **settings page shows a yellow warning** "已自动恢复，请重启 DSH 使认证完全生效" — the patches were written to disk, but the running process's core modules were already loaded without them (`/api` and WebSocket are temporarily unprotected)
3. **Restart DSH once more** → the patches load with the core modules, the warning disappears, and all four layers are fully enforced
4. If auto-repatching fails (core packages restructured), the settings page shows a **red warning** with the specific reason, and the host log prints `PATCH ANCHOR NOT FOUND` etc.

## Data & Security

- Passwords are hashed with **scrypt** (Node's built-in memory-hard KDF — GPU/ASIC resistant, zero dependencies) and stored in `dsh-webui-auth.json` inside the plugin directory; plaintext is never written to disk. **Since 0.2.0 only scrypt hashes are accepted**: 0.1.x SHA-256 credentials can no longer be verified — delete `dsh-webui-auth.json` and recreate the account (see "Forgot password").
- Login rate limiting: at most 5 failures per minute. Failed verifications also run a dummy scrypt pass so "unknown account" and "wrong password" take the same time, defeating username enumeration via response timing.
- Audit log: security events are appended to `audit.jsonl` (see "Audit log" above).
- Security headers on the login page and API responses: strict CSP, `nosniff`, `DENY` framing, `no-referrer`, `noindex`, `no-store`.
- Cookie `HttpOnly + SameSite=Lax`: not readable by JS, not sent on cross-site requests.
- The login/setup endpoints are intentionally public (the entry point of authentication); pre-registered exact endpoints such as `/dsh-vision-helper/config` are not gated (configuration data only, not WebUI access).

## Known limits

- **Core-patch self-maintenance**: the plugin checks `[dsh-webui-auth patch]` markers at startup and re-patches automatically (when anchors match); a restart after a DSH upgrade restores protection. An auto-repatch does **not** affect the running process (core modules are already loaded) — one more restart is required. Failures surface both in the host log and on the WebUI settings page (yellow/red banner), never silently.
- Sessions live in process memory: restarting DSH invalidates all sessions (login again); the credentials file persists.
- Threat model is "browser/network clients": local processes that can read/write the host's memory or files are out of scope.
