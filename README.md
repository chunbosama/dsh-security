# dsh-security — pluggable security suite for DeepSeek Harness (dsh)

A **everything-is-a-plugin** security suite for dsh. Each capability is an
independent Cordis plugin that can be installed, replaced, upgraded or disabled
on its own. A small **core** plugin provides the shared infrastructure; the
rest are standalone modules that register themselves into the core and are
surfaced together on a Settings **control panel**.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Settings → Security (control panel)                                    │
│  • lists every installed security module                                │
│  • manages the admin password                                           │
│  • manages the trusted-IP allowlist                                     │
└───────────────▲──────────────────────────────▲──────────────────────────┘
                │ registers (module roster)    │ admin password / trusted IPs
┌───────────────┴────────────┐   ┌─────────────┴───────────────────────────┐
│ @dsh-security/core         │   │ shared settings namespace `dsh-security` │
│  ctx.security service:     │   │ (settings.yaml)                          │
│  • module registry         │   └──────────────────────────────────────────┘
│  • admin-password vault    │
│  • IP tracker / verdict    │
│  • alert dispatch ─────────┼──────▶ any module with `handleAlert`
└────────────────────────────┘
        ▲          ▲          ▲          ▲          ▲
   attack-alert file-protect command-protect ip-protect api-protect
   (SMTP email)(md5 checks) (danger gate) (stranger ip)  (/api honeypot)
```

## Modules

| Package | Category | What it does |
|---|---|---|
| `@dsh-security/core` | core | Shared `ctx.security` service: module registry, scrypt-hashed admin-password vault, IP commonity tracker/verdict, and alert dispatch. Persists to the `dsh-security` settings namespace. |
| `@dsh-security/control-panel` | UI | A `settings.section` page named **Security** that lists installed modules, sets/changes the admin password and edits the trusted-IP allowlist. Dual-face package (host stub + browser half). |
| `@dsh-security/attack-alert` | alert | Sends an SMTP email (via a dependency-free `node:net`/`node:tls` client, AUTH LOGIN + optional STARTTLS) to a configured inbox whenever any module calls `ctx.security.alert()`. Registers `handleAlert`. |
| `@dsh-security/file-protect` | file | Periodically recomputes the MD5 of critical dsh files (defaults: `$DSH_HOME/cordis.patch.yml`, the web profile patch/config, `settings.yaml`, `.credentials.yaml`) and emails an alert when a file changes. |
| `@dsh-security/command-protect` | command | Scores every `bash`/`pwsh` command for danger at the `tools/pre-execute` waterfall. Dangerous commands are denied until the admin password is verified (a `security_verify_password` tool prompts for it); verified unlocks run for a short TTL window. Also wraps `ctx.shell` for defense-in-depth. |
| `@dsh-security/ip-protect` | ip | Learns the user's common IPs by observing `/api` traffic on the webserver. When a stranger IP starts a conversation it emails the admin (so they can add the IP in the control panel). |
| `@dsh-security/api-protect` | api | Registers exact `/api/<method>` routes that answer **unauthenticated or strange-IP** callers with random, meaningless `RpcResult` data instead of the real backend, while forwarding legitimate loopback/trusted traffic to the real gateway. |

### Cross-module alerting (requirement 9)

Any time a module's protection is triggered it calls `ctx.security.alert(payload)`.
If the **attack-alert** module is installed it sends an email; otherwise the
core logs a warning. No module has a hard dependency on attack-alert — it is
swappable for any other `handleAlert` provider (e.g. a webhook).

## How each protection works (implementation notes)

### Admin password (core)
Hashed with **scrypt + random salt** (`salt:derived`). Only the hash is ever
stored, in the `dsh-security` settings namespace under a `role("secret")`
field (redacted from the wire). Verification uses `timingSafeEqual`. The
control panel writes a plaintext `adminPasswordPending` field that the core
hashes host-side and then clears, so the plaintext never persists.

### Command protection
- Danger scoring: a ruleset of regex → severity score (0–100); a command is
  dangerous when its best matching rule score ≥ `dangerThreshold` (default 50).
- Enforced at the **`tools/pre-execute`** waterfall (`prepend: true`), the single
  choke point for every tool call. A denied command never spawns a process.
- The model is told to call `security_verify_password`, which prompts the human
  for the admin password and, if correct, unlocks dangerous-command execution
  for `unlockTtlMs` (default 30 min).
- Defense-in-depth: `ctx.shell.run/start` are also wrapped so direct shell
  callers (e.g. the cordis SDK) cannot bypass the gate.

### Critical file protection
- On boot and every `intervalSeconds`, computes each file's MD5 and compares it
  to the stored baseline. First observation establishes the baseline; any
  later change triggers an alert and does **not** auto-update the baseline
  (so it keeps flagging until you deliberately re-baseline by setting
  `rescanBaseline: true`).

### Strange-IP protection
- A webserver `request`/`upgrade` observer records the client IP for every
  `/api` access into the core IP tracker, building a "common IP" model.
- A stranger IP (not trusted, not common, not loopback) that starts a
  conversation (`session.prompt` etc.) triggers `ctx.security.alert(...)` —
  an email tells the admin to add the IP in the control panel.
- Enforcement of "don't reply to strangers" is done by `api-protect`, which
  shares the same `ctx.security.ip` verdict.

### API protection
- For every `/api/<method>`, an exact shadow route runs before the real
  gateway. Stranger/unauthenticated callers receive a fabricated
  `{ type: 'server-response', rpcId, result: { ok: true, value: <random> } }`
  envelope; trusted loopback traffic is forwarded to `toFetchHandler(ctx.apiProxy)`.

## Installation

### 1. Build
Client halves (control-panel) are bundled with `tsdown` like every dsh client
plugin. Host plugins are plain ESM and need no build:

```sh
pnpm install
pnpm --filter @dsh-security/control-panel run bundle   # produces lib/client.js
```

### 2. Install into the web profile
Add the packages as dependencies of the profile and install them into the
profile's `node_modules` (the profile resolves out-of-tree plugins from there):

```sh
cd $DSH_HOME/profiles/web
pnpm add @dsh-security/core @dsh-security/control-panel @dsh-security/attack-alert \
         @dsh-security/file-protect @dsh-security/command-protect \
         @dsh-security/ip-protect @dsh-security/api-protect
```

### 3. Activate them
Append the entries in [`cordis.patch.yml`](./cordis.patch.yml) to
`$DSH_HOME/profiles/web/cordis.patch.yml` (the profile patch is hot-reloaded).
Remove the rows for modules you don't want. Keep `security-core` (the others
depend on it).

### 4. Configure
Edit the module settings in Settings → Security, or directly in the settings
file. The important ones:
- **attack-alert**: set `smtpHost`, `smtpPort`, `smtpUser`/`smtpPass` (secret),
  `from` and `to`.
- **command-protect**: adjust `dangerThreshold` and add custom `rules`
  (`{ name, pattern, score }`).
- **file-protect**: add critical files in `files`; set `rescanBaseline: true`
  after a legitimate upgrade.
- **api-protect**: add LAN hosts to `trustedHosts` for a 0.0.0.0 deployment.

## Known limitations / honest notes

- **No authentication exists in dsh** — the web carrier has no login. "Logged
  in" for `api-protect` is therefore approximated as *loopback or trusted-host
  origin + a non-stranger IP*. A real login/token layer would be a separate
  module.
- **Client UI build**: the control-panel browser half must be produced by the
  dsh client build pipeline (`tsdown`); this repo ships the ES source under
  `packages/control-panel/src/client/`.
- **Command rewriting** is intentionally impossible at `tools/pre-execute`
  (arguments are frozen); gating is deny/allow only. Direct `ctx.terminals`
  writes are not gated (only the `bash`/`pwsh` tools are covered by the
  waterfall).
- **Session unlock** is a process-local, TTL-bounded flag; it is reset on
  restart.
- **SMTP client** is minimal (AUTH LOGIN, one recipient). For exotic servers
  you may need to extend it.

## Development

```sh
pnpm install
for f in packages/*/lib/index.js; do node --check "$f"; done   # syntax sanity
```
