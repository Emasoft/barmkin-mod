# barmkin-mod

**A security layer for Claude Code, shipped as a Claude Code mods plugin.** It redacts secrets, tracks untrusted content, and blocks the tool calls that would let an injected instruction send your data somewhere.

[![CI](https://github.com/samfrmr/barmkin-mod/actions/workflows/ci.yml/badge.svg)](https://github.com/samfrmr/barmkin-mod/actions/workflows/ci.yml)

[Features](#features) · [Quick start](#quick-start) · [Configuration](#configuration) · [How it works](#how-it-works) · [Limits](#limits) · [OpenCode 2.x](#opencode-2x-partial-port) · [Development](#development)

> [!NOTE]
> barmkin-mod only ever tightens. Every hook adds a deny, withhold or warning on top of a decision someone else made. None of them can turn a deny into an allow.

## Features

| Capability | What happens |
|---|---|
| **Secret redaction** | Tool results and outbound messages are scanned for private keys, JWTs and AWS, Anthropic, OpenAI, GitHub, Stripe, Slack, npm and other tokens. Matches become `[REDACTED:<category>#n]`. |
| **Untrusted-content taint** | Web fetches, MCP results, reads outside the working directory, peer messages and skill loads are screened for injection. A hit taints the session. |
| **Rule-of-Two egress gate** | Combines **A** untrusted input, **B** sensitive access and **C** an outward effect. With A alone, each egress class keeps its own posture (warn or deny). With A and B, every class denies. |
| **Destructive and history-rewrite tier** | `rm -rf` on system or secret paths, `git reset --hard`, forced pushes to `main`/`master` and similar. Allowed with a warning in a clean session, denied once the session is tainted. |
| **MCP tool-poisoning guard** | Strips instruction-like sentences from MCP tool descriptions and enforces an optional server allowlist. |
| **Skill guards** | Denies skill inline shell (`` !`command` ``) while mediation applies, and screens skill bodies and the skill listing. |
| **Agent-to-agent firewall** | Screens inbound peer messages, blocks outbound messages that contain secrets, and refuses to spawn subagents while the session is tainted. |
| **Jev System One classifier** | An optional remote classifier with an explanation surface (`/barmkin-mod-status`, the HUD and the permission notice). It can only raise suspicion, never lower it. Production screening enforces three questions: prompt injection, data exfiltration and contains-secrets, in the revised wording. |
| **Shadow screen** | Contrast instrumentation only: the captain's wording of all four questions, plus the destructive-command question in the revised wording. Annotation only. Destructive never taints. |
| **Invisible-text scrub** | Strips ANSI escapes, bidi overrides, zero-width characters and the Unicode Tags block from tool results, descriptions and messages. |

## Quick start

**Requirements:** Claude Code **2.1.287 or later** (the mod checks at session start and warns on older builds), and Node 22 for validation and tests.

barmkin-mod is a Claude Code plugin. Point your plugin install at this repository (`https://github.com/samfrmr/barmkin-mod`), then fill in the [options](#configuration) when prompted.
- Outward-effect shell commands (`shell-outward`): `git push`, `curl` with a body, `scp` to a host, a pipe to `sh`, and similar. *Denies on A alone.*
- Network clients (`net-client`): `curl`/`wget` with a body flag or a `$(…)`/backtick URL substitution, the socket tools `nc`/`ncat`/`socat`/`telnet`/`ftp`, `/dev/tcp` and `/dev/udp`, and `ssh`/`scp`/`sftp`/`rsync` to a remote. `nc -z` port scans and local-only copies are excluded; a `curl`/`wget` to `localhost` without substitution is exempt. *Denies on A alone.*
- DNS/probe exfil (`dns`): `nslookup`/`dig`/`host`/`ping`/`traceroute`/… with a substituted name. *Warns on A alone.*
- Forge writes (`forge`): mutating `gh`/`glab` (`issue`/`pr`/`gist`/`release`/… create/comment/edit/upload/…), and `gh api` with a `POST`/`PUT`/`PATCH`/`DELETE` method or a `-f`/`-F`/`--field` body — the Comment-and-Control channel. Read verbs stay clear. *Warns on A alone.*
- Package/image publishes (`publish`): `npm`/`pnpm`/`yarn`/`bun`/`cargo publish`, `docker`/`podman push`, `twine upload`, `gem push`. `--dry-run` is excluded. *Warns on A alone.*
- Cloud object-store uploads (`cloud`): `aws s3 cp|mv|sync`, `aws s3api put-object`, `gsutil`/`gcloud storage cp|rsync`, `az storage … upload`. Read ops stay clear. *Warns on A alone.*
- Inline interpreter network calls (`interpreter-net`): `python`/`node`/`deno`/`ruby`/`perl`/`php` run with `-c`/`-e`/`--eval` where the inline script makes a network call (`urlopen`, `fetch(`, `requests.get`, a `socket(`/`.connect(` call, `http.request`, `/dev/tcp`, …); a bare URL literal or `socket.gethostname()` is not enough. *Denies on A alone.*
- Shell writes to persistence surfaces (`persist-shell`): a redirection, `tee`/`cp`/`mv`/`install`/`ln`/`rsync`/`dd`, or a `sed -i` whose destination is a persistence path (the last argument for `cp`/`mv`/`install`/`ln`/`rsync`, `of=` for `dd`, so reading one as a source does not warn). *Warns on A alone.*
- Destructive commands (`destructive`): `rm -rf` (or `--recursive --force`) on `/`, the running user's `~`/`$HOME`, a system root (`/etc`, `/usr`, `/var`, `/boot`, `/dev`, `/opt`, `/root`, … including paths beneath them) or a secret path (`~/.ssh`, `~/.aws`, `.env`, …); `chmod`/`chown`/`shred`/in-place `sed -i` on a secret path; a redirect into a secret path or `authorized_keys`; `dd of=` a block device; `mkfs`/`wipefs` on `/dev/…`. *Warns on a clean session, denies on A alone.*
- Git history rewrites (`history-rewrite`): `git reset --hard`, `git push --force`/`-f`/`--force-with-lease` to `main`/`master`, `git clean -fd`, `git branch -D` (the safe `-d` is not matched), `git update-ref -d`. *Warns on a clean session, denies on A alone.*
- Web fetches (`web-fetch`) and web searches (`web-search`), since the URL and the query are each a channel. *Fetch denies, search warns, on A alone.*
- Monitor WebSockets (`monitor-ws`): a `Monitor` call opening an outbound `ws`. *Denies on A alone.*
- MCP write-class tools (`mcp-write`): names containing verbs such as `create`, `send`, `post`, `update`, `delete`, `save`, `set`, `insert` or `upsert`. The ambiguous `run`/`execute`/`request` are not treated as writes.
- Skill loads (`skill-load`).
- File-tool writes to persistence surfaces (`persistence`): `CLAUDE.md`, `AGENTS.md`, `.claude/`, `.mcp.json`, CI workflows, git hooks, shell rc files, `~/.ssh`, `~/.local/bin`, `.vscode/{tasks,settings,launch}.json`, `.devcontainer/`, `package.json`, `Makefile`, `GNUmakefile`, `.envrc`, `.pre-commit-config.yaml` and `.config/fish/`. `package.json`, `Makefile` and `GNUmakefile` are edited constantly, so these only warn (never deny) on A alone. The same paths written from a shell (`persist-shell`) follow the same rule.

The destructive classes are the one place a clean session gets an advisory: a match is allowed with a warning when nothing untrusted has been handled, and denied as soon as the session is tainted (leg A). They never deny unconditionally, so an injection that the detector misses is not blocked by them; the Bash sandbox is the floor for that case. Deep system paths (`rm -rf /opt/app/cache`) are matched on purpose, `/home/<other>/…` is not, and `rm -rf node_modules`, `dist` and `build` are untouched.

The shell classes are a naive tokenizer, not a shell parser: quoting tricks (`c''url`, a `|` inside a quoted string, base64-wrapped binaries) evade them. That is inherent — the Bash sandbox's egress allowlist is the enforcement floor beneath them (see Limits).

The classifier reads untrusted content after redaction, in overlapping windows of 4,000 characters (each window repeats the last 512 characters of the one before), up to five windows, which is enough for the 16 KiB limit. The windows are asked in parallel, a window that failed for a transient reason (a timeout, a network error, a 429 or a 5xx) is asked once more, and each question's highest score over the windows decides, so Jev can still only raise a score. A window that scores taints the session as usual, and a message clears that taint. With Jev configured, content that spans more than one window and has part the classifier could not read (a window that still failed after its retry, the classifier breaker open, or text past the fifth window) taints the session even when nothing in it looks like an injection, because that part was never classified. This taint needs an explicit acknowledgement: a later message, `/clear` or compaction does not clear it, whatever `taint_clear` is set to, and only `/barmkin-mod-clear-taint` from a person does. Length alone does not taint: content every window read raises no acknowledgement, and without Jev configured the classifier is not claimed to have read anything. A screen counts as one classifier-breaker event however many windows it took.

A withheld result tells Claude which screen flagged it and nothing more. The exact probability stays in the status command, the HUD and the permission notice, so a payload cannot be tuned against it.

With Jev configured, each window is put to three enforced questions, in one request: prompt injection, data exfiltration and contains-secrets, under one shared instruction in the revised wording (it names screener-directed text, label laundering and the scope rules). They are the real verdict. Each taints the session at the same per-question line as before (0.5), a question's highest score over the windows decides, and Jev can only raise a score. Injection alone is withheld from 0.85, as it always was. Exfiltration taints only: it never withholds a result and never sets sensitive access, and a hit shows the usual untrusted-content warning. Credentials taints and also sets sensitive access, as before. A screen is still one classifier-breaker event however many windows it took.

A shadow screen runs next to them, for contrast only: the captain's wording of all four questions (the captain's text with the edits that asking each question alone forces), and the destructive-command question in the revised wording. Classifier-scored destructive-command detection was found not to be feasible, so that question is instrumentation, never enforced, and never taints or withholds anywhere; destructive commands are handled by the taint-gated destructive classes above. The shadow answers are recorded and shown in `/barmkin-mod-status` and the permission notice (marked "shadow, not enforced"), merged over the windows by highest score. They never taint the session, withhold a result, set sensitive access or gate a call. The shadow screen has its own breaker, so a shadow failure cannot degrade the real screen or turn the HUD amber. Each request carries one window plus one question set, at most about 5,000 characters: roughly 4.8k to 5k tokens a pass at one character per token (dense or CJK text). The questions are frozen constants (`hooks/lib/jev-questions.ts`) with a SHA-256 pinned in the tests, and no setting, event or screened content reaches them.

Sensitive access (leg B) is set when a call touches a secret path such as `~/.ssh`, `~/.aws`, `.env` or `.git-credentials`, when a redaction rule fires on a tool result, or when the classifier reports credentials in the content, judged from the credentials score itself, not from whichever question drove the verdict (content that scores on both injection and credentials sets both legs).

## Requirements

- Claude Code **2.1.287 or later**. The mod checks at session start and warns on older builds.
- Node 22 for validation and tests.

## Install

barmkin-mod is a Claude Code plugin. Point your Claude Code plugin install at this repository, then fill in the options below when prompted.
> [!IMPORTANT]
> For full coverage, seat the plugin in managed `prependPlugins` and apply the managed-settings floor (see [Seat requirements](#seat-requirements)). Unseated, it cannot see skill text, `CLAUDE.md` or other prompt-assembly content. If `sec-default` is seated ahead of it, it still cannot see `skill.prompt`, `prompt.context` or `prompt.section`.

To try it from a local checkout:

```sh
git clone https://github.com/samfrmr/barmkin-mod.git
cd barmkin-mod
npm ci
npm run validate   # claude plugin validate --strict .
```

At session start the mod runs a posture self-check and emits one line per condition, naming the condition, why it matters and the fix. It warns when:

- the plugin is not seated in managed `prependPlugins`,
- `permissions.defaultMode` is `bypassPermissions`,
- the Bash sandbox is off, which removes the OS-level egress floor,
- `sandbox.failIfUnavailable` is unset, so a sandbox that cannot start lets commands run unsandboxed,
- `sandbox.allowUnsandboxedCommands` is not `false`, so a command can opt out of the sandbox,
- `sandbox.network.allowAllUnixSockets` is on, so sandboxed commands can reach any local Unix socket,
- `sandbox.credentials` has no `mask` entry, so sandboxed commands see real tokens,
- managed `sandbox.network.allowManagedDomainsOnly` is unset, so user or project settings can widen sandbox egress,
- managed `allowManagedMcpServersOnly` and `allowedMcpServers` are not both set, so users can add their own MCP servers,
- `disableSkillShellExecution` is unset, so skill inline shell bypasses every `tool.call` guard,
- `mcp_server_allowlist` is empty.

The seating, `allowManagedDomainsOnly` and managed MCP checks read managed (policy) settings only, because Claude Code honors those keys only there. The rest read the merged settings, whichever source set them. A settings read that fails is reported as unverified, never as passing.

### Seat requirements

The managed-settings floor is in [`packaging/managed-settings.example.json`](packaging/managed-settings.example.json). Claude Code reads managed settings only from the root-owned `/etc/claude-code/managed-settings.json`, so they apply to every session on the machine. Adapt the example, merge it into that file, and restart Claude Code. The floor only tightens. Applied as is, it raises no posture warning; `mcp_server_allowlist` is this plugin's own option and is set separately.

| Setting | Floor | Why |
|---|---|---|
| `prependPlugins` | `["barmkin-mod@<marketplace>", "cc-plugin-sec-default@builtin"]` | Seats the mod ahead of sec-default. List sec-default by that exact builtin id: a seat list without it drops sec-default's protections. |
| `sandbox.enabled` | `true` | The OS sandbox is the enforcement floor under the shell classes, which a quoting trick can evade. |
| `sandbox.failIfUnavailable` | `true` | Claude Code refuses to start when the sandbox cannot start, instead of running commands unsandboxed. |
| `sandbox.allowUnsandboxedCommands` | `false` | Claude Code ignores `dangerouslyDisableSandbox`, so every command runs sandboxed. |
| `sandbox.network.allowAllUnixSockets` | `false` | On Linux, sandboxed commands then cannot open a Unix socket at all, so they cannot reach a local service outside the sandbox. `true` lifts that block. |
| `sandbox.network.allowManagedDomainsOnly` | `true`, with `allowedDomains` | Only the managed domain allowlist applies to sandboxed egress. |
| `sandbox.credentials` | a `mask` entry per token you use | Sandboxed commands see a sentinel, and the sandbox proxy swaps in the real value only for the listed `injectHosts`. On macOS and Windows `mask` degrades to `deny`. |
| `disableSkillShellExecution` | `true` | Skill and slash-command inline shell is replaced with a placeholder instead of run outside the tool guards. |
| `allowManagedMcpServersOnly` | `true`, with `allowedMcpServers` | Only the managed MCP allowlist applies; users can still deny servers for themselves. |

Every `injectHosts` entry must also be in `allowedDomains`. On NixOS, also set managed `sandbox.bwrapPath` and `sandbox.socatPath` to the store paths of `bubblewrap` and `socat`; without them every sandboxed command fails with `bwrap: command not found`, which is fail-closed but unusable.

`claude plugin validate` does not schema-check settings files, so `npm test` holds a copy of the recipe and asserts that it raises no posture warning. `claude doctor` reports any value in it that Claude Code would reject: copy it into an empty `CLAUDE_CONFIG_DIR` as `settings.json` and run `claude doctor`.

A clear session shows one line beneath the mode switcher: green `🏰 Barmkin session guard active` when Jev is configured and its breaker is closed (this does not claim any request succeeded), or amber `🏰 Barmkin session guard degraded` when Jev is not configured or the breaker is open. A tainted session shows a single red `🚨 TAINTED` line above the prompt that names the clear path for the active `taint_clear` posture.

## Configuration

| Option | Default | Purpose |
|---|---|---|
| `jev_base_url` | empty | System One endpoint, OpenRouter or Vercel AI Gateway style. The mod POSTs to `{base_url}/v1/systemone`. Empty disables the classifier and falls back to pattern heuristics. |
| `jev_model` | `jev-1.13.0` | Pinned Jev model id. Must match the `jev-1.13` pattern. |
| `jev_api_key` | none | Bearer credential. Stored in secure credential storage and never logged. |
| `mcp_server_allowlist` | empty | Comma-separated MCP server names allowed to run tools. Empty allows all (audit only). |
| `taint_clear` | `human-origin` | `human-origin`: a person's prompt clears the taint. `sticky`: it holds until `/compact`, `/clear` or `/barmkin-mod-clear-taint`. |
| `sdk_prompts_clear_taint` | `false` | Let SDK prompts clear the taint. For headless lanes (`claude -p`, the Agent SDK) only. |

| Command | Description |
|---|---|
| `/barmkin-mod-status` | Show taint, circuit-breaker state, the last classifier verdict and the last shadow-screen scores. |
| `/barmkin-mod-clear-taint` | Clear the taint, only from a person's prompt. The only way to clear a taint for content the classifier could not read. |

## How it works

### The Rule of Two

Three legs: **A** the session handled untrusted content, **B** it touched sensitive material, **C** the call has an outward effect. Sensitive access (leg B) is set when a call touches a secret path such as `~/.ssh`, `~/.aws`, `.env` or `.git-credentials`, when a redaction rule fires on a tool result, or when the classifier reports credentials in the content (judged from the credentials score itself, so content that scores on both injection and credentials sets both legs).

### Egress classes

Shell classes read the `command` of a `Bash`, `PowerShell` or `Monitor` call. Each identifies the real head binary of every pipeline and subshell segment (past `sudo`, `env VAR=`, inline `VAR=` and a `bash -c '…'` wrapper) and tests the exfil signal (command substitution, body flags, redirection, a remote spec) against the raw command.

| Class | Matches | On A alone |
|---|---|---|
| `shell-outward` | `git push`, `curl` with a body, `scp` to a host, a pipe to `sh` and similar | deny |
| `net-client` | `curl`/`wget` with a body flag or a `$(…)`/backtick URL; `nc`/`ncat`/`socat`/`telnet`/`ftp`; `/dev/tcp` and `/dev/udp`; `ssh`/`scp`/`sftp`/`rsync` to a remote. `nc -z` scans and local-only copies are excluded | deny |
| `interpreter-net` | `python`/`node`/`deno`/`ruby`/`perl`/`php` with `-c`/`-e`/`--eval` whose script makes a network call. A bare URL literal is not enough | deny |
| `monitor-ws` | a `Monitor` call opening an outbound `ws` | deny |
| `web-fetch` | web fetches (the URL is a channel) | deny |
| `web-search` | web searches (the query is a channel) | warn |
| `dns` | `nslookup`/`dig`/`host`/`ping`/`traceroute`/… with a substituted name | warn |
| `forge` | mutating `gh`/`glab` verbs, and `gh api` with a write method or `-f`/`-F`/`--field` body (the Comment-and-Control channel). Read verbs stay clear | warn |
| `publish` | `npm`/`pnpm`/`yarn`/`bun`/`cargo publish`, `docker`/`podman push`, `twine upload`, `gem push`. `--dry-run` is excluded | warn |
| `cloud` | `aws s3 cp\|mv\|sync`, `aws s3api put-object`, `gsutil`/`gcloud storage cp\|rsync`, `az storage … upload`. Read ops stay clear | warn |
| `persist-shell` | a redirection, `tee`/`cp`/`mv`/`install`/`ln`/`rsync`/`dd` or `sed -i` whose destination is a persistence path | warn |
| `persistence` | file-tool writes to `CLAUDE.md`, `AGENTS.md`, `.claude/`, `.mcp.json`, CI workflows, git hooks, shell rc files, `~/.ssh`, `~/.local/bin`, `.vscode/{tasks,settings,launch}.json`, `.devcontainer/`, `package.json`, `Makefile`, `GNUmakefile`, `.envrc`, `.pre-commit-config.yaml`, `.config/fish/` | warn |
| `destructive` | see [below](#destructive-and-history-rewrite-tier) | warn when clean, deny on A |
| `history-rewrite` | see [below](#destructive-and-history-rewrite-tier) | warn when clean, deny on A |
| `mcp-write` | MCP tools whose names contain verbs such as `create`, `send`, `post`, `update`, `delete`, `save`, `set`, `insert`, `upsert`. The ambiguous `run`/`execute`/`request` are not treated as writes | per posture |
| `skill-load` | skill loads | per posture |

`package.json`, `Makefile` and `GNUmakefile` are edited constantly, so they only warn (never deny) on A alone, whether written by a file tool or from a shell.

A `curl` or `wget` aimed only at `localhost` (`127.0.0.1`, `0.0.0.0`, IPv6 loopback) is exempt, unless the URL carries a substitution. The target is judged from the real authority, after the userinfo `@`: `localhost:80@evil.example` targets `evil.example` and is not exempt.

### Destructive and history-rewrite tier

- **`destructive`:** `rm -rf` (or `--recursive --force`) on `/`, the running user's `~`/`$HOME`, a system root (`/etc`, `/usr`, `/var`, `/boot`, `/dev`, `/opt`, `/root`, including paths beneath them) or a secret path (`~/.ssh`, `~/.aws`, `.env`, …); `chmod`/`chown`/`shred`/in-place `sed -i` on a secret path; a redirect into a secret path or `authorized_keys`; `dd of=` a block device; `mkfs`/`wipefs` on `/dev/…`.
- **`history-rewrite`:** `git reset --hard`, `git push --force`/`-f`/`--force-with-lease` to `main`/`master`, `git clean -fd`, `git branch -D` (the safe `-d` is not matched), `git update-ref -d`.

This is the one place a clean session gets an advisory: a match is allowed with a warning when nothing untrusted has been handled, and denied as soon as the session is tainted. They never deny unconditionally, so an injection the detector misses is not blocked by them; the Bash sandbox is the floor for that case. Deep system paths (`rm -rf /opt/app/cache`) are matched on purpose, `/home/<other>/…` is not, and `rm -rf node_modules`, `dist` and `build` are untouched.

### Jev System One classifier

The classifier reads untrusted content after redaction, in overlapping windows of 4,000 characters (each repeats the last 512 characters of the one before), up to five windows, which covers the 16 KiB limit. Windows are asked in parallel, a window that failed transiently (timeout, network error, 429, 5xx) is asked once more, and each question's highest score over the windows decides, so Jev can only raise a score. A window that scores taints the session as usual.

With Jev configured, content that spans more than one window and has a part the classifier could not read (a window that still failed after its retry, the breaker open, or text past the fifth window) taints the session even when nothing in it looks like an injection, because that part was never classified. This taint needs an explicit acknowledgement: a later message, `/clear` or compaction does not clear it, whatever `taint_clear` is set to. Only `/barmkin-mod-clear-taint` from a person does. Length alone does not taint, and without Jev configured the classifier is not claimed to have read anything. A screen counts as one breaker event however many windows it took.

A withheld result tells Claude which screen flagged it and nothing more. The exact probability stays in the status command, the HUD and the permission notice, so a payload cannot be tuned against it.

### Production screening

With Jev configured, each window is put to three enforced questions in one request: prompt injection, data exfiltration and contains-secrets. They share one instruction in the revised wording, which names screener-directed text, label laundering and the scope rules. These are the real verdict.

- Each question taints the session at 0.5, a question's highest score over the windows decides, and Jev can only raise a score.
- Injection alone is withheld, from 0.85.
- Exfiltration taints only. It never withholds a result and never sets sensitive access.
- Contains-secrets taints and also sets sensitive access (leg B).

Destructive commands are not screened by Jev. They stay with the taint-gated [destructive tier](#destructive-and-history-rewrite-tier).

### Shadow screen

A shadow screen runs next to production for contrast only: the captain's wording of all four questions (the captain's text with the edits that asking each question alone forces), and the destructive-command question in the revised wording. Answers are merged over the windows by highest score and shown in `/barmkin-mod-status` and the permission notice, marked as shadow.

> [!NOTE]
> The shadow screen is annotation only. It never taints the session, withholds a result, sets sensitive access or gates a call. The destructive-command question never taints anywhere: classifier-scored destructive detection was found not to be feasible, so that question is instrumentation and destructive stays annotation-only. The shadow screen has its own breaker, so a shadow failure cannot degrade the real screen or turn the HUD amber. The questions are frozen constants (`hooks/lib/jev-questions.ts`) with a SHA-256 pinned in the tests; no setting, event or screened content reaches them.

## Limits

> [!WARNING]
> The shell classes are a naive tokenizer, not a shell parser. Quoting tricks (`c''url`, a `|` inside a quoted string, base64-wrapped binaries) and variable indirection evade them, and so can the destructive classes. Enable the Bash sandbox so its egress allowlist sits underneath as the enforcement floor.

**Fail-open versus fail-closed**

- Guarding hooks fail closed: if one errors, the action is denied or the content withheld. This covers redaction, the egress, MCP, shell-mediation and content-screen guards, and the agent-to-agent screen.
- Advisory hooks, such as the HUD, fail open and leave the result unchanged.
- The shadow screen fails open by design: a failure there never reaches the real screen.

**Size limits**

- Every redaction rule runs in time linear in the text, so a tool result is scanned whole up to 256 KiB per string and 1 MiB per result. Past those limits:
  - A string over 256 KiB in a result that no injection screen covers (Bash, Grep, Glob, a Read inside the working directory) shows a scanned prefix of about 12 KiB, cut at a line or delimiter that no secret match crosses, followed by a note with the shown and total character counts and how to page (`Read` with `offset` and `limit`, or a narrower command). The hidden part is never shown and never matched, and invisible text anywhere in the string still counts toward the taint threshold. If no safe cut exists, the result is withheld.
  - A result whose strings together pass 1 MiB, and a Read image past about 190 KiB, are withheld, since a prefix of either is not useful.
- Untrusted content is withheld over 16 KiB, never cut: web fetches and searches, MCP results, reads outside the working directory, skill bodies, peer messages, your prompts and outbound messages. The withhold message says it is a size limit and tells Claude to fetch the content in smaller pieces rather than ask you.

**Classifier traffic**

- With Jev configured, the endpoint receives up to about 18,000 characters of redacted untrusted content per screen, in up to five requests, plus two more requests per window for the shadow screen.

**Maintenance**

- Secret rules are a hand-maintained copy of barmkin's. Keep them in sync when barmkin changes.

## OpenCode 2.x (partial port)

The second host lives in [`opencode/`](opencode/). It reuses the host-neutral library in `hooks/lib/` and adds an OpenCode plugin, `barmkin-opencode`, that redacts secrets, taints a session on untrusted content, and refuses outward-effect tools while the session is tainted. A separate [`opencode-canary/`](opencode-canary/) plugin reports when the guard is not loaded.

> [!WARNING]
> This is a partial port, not equivalent to barmkin-mod for Claude Code. OpenCode 2 has no administrator-locked plugin seat, so a repository's `opencode.json` can unload the guard unless it is seated as described in the OpenCode README. No posture line means no guard.

See [`opencode/README.md`](opencode/README.md) for the seat recipe, install steps, tested range and the list of what is not covered.

## Development

```text
hooks/register.ts       hook wiring and all runtime ($) calls
hooks/lib/              pure, unit-tested logic
  redaction*.ts         secret rules and redaction
  linear-scanners.ts    linear-time scanners for the four rules whose regexes backtrack
  scanned-prefix.ts     the span-safe prefix shown for an oversize tool result
  taint.ts, egress.ts   injection screen, Rule-of-Two gate
  mcp-guard.ts          tool-description hardening
  skill-guard.ts        skill body and listing guards
  system-one-client.ts  classifier wire format
  jev-questions.ts      the frozen classifier questions and their pinned wording
  classifier-windows.ts classifier windows and score merging
  posture.ts            posture checks
packaging/              managed-settings floor recipe
tests/                  one test file per lib module, plus integration
opencode/               OpenCode 2.x port (Bun)
.claude-plugin/         plugin manifest and option schema
```

```sh
npm ci
npm run validate   # claude plugin validate --strict .
npm test           # claude plugin test
```

CI runs both on every push to `main` and on pull requests, alongside workflow tests, a gitleaks secret scan (`.gitleaks.toml`) and CodeQL. The Claude Code dependency in `package.json` is pinned to the version floor, so CI is the real verification surface.

Pull requests go to this fork, [samfrmr/barmkin-mod](https://github.com/samfrmr/barmkin-mod), not to an upstream repository.

Guarding hooks fail closed: if one errors, the action is denied or the content withheld. Advisory hooks, such as the HUD, fail open and leave the result unchanged.

## Limits

- The shell denylist and the destructive classes can be evaded (obfuscated or variable-indirected commands). Enable the Bash sandbox so its egress allowlist sits underneath it.
- Size limits. Every redaction rule runs in time linear in the text, so a tool result is scanned whole up to 256 KiB per string and 1 MiB per result. Past those limits:
  - A string over 256 KiB in a result that no injection screen covers (Bash, Grep, Glob, a Read inside the working directory) shows a scanned prefix of about 12 KiB, cut at a line or delimiter that no secret match crosses, followed by a note with the shown and total character counts and how to page: `Read` with `offset` and `limit`, or a narrower command. The hidden part is never shown and never matched, and invisible text anywhere in the string still counts toward the taint threshold. If no safe cut exists, the result is withheld.
  - A result whose strings together pass 1 MiB, and a Read image past about 190 KiB, are withheld, since a prefix of either is not useful.
- Untrusted content is withheld over 16 KiB, never cut: web fetches and searches, MCP results, reads outside the working directory, skill bodies, peer messages, your prompts and outbound messages. The classifier reads such content in up to five overlapping 4,000-character windows. The withhold message says it is a size limit and tells Claude to fetch the content in smaller pieces rather than ask you.
- With Jev configured, the classifier endpoint receives up to about 18,000 characters of redacted untrusted content per screen, in up to five requests, plus two more requests per window for the shadow screen (below). Content with a part the classifier could not read taints the session until acknowledged with `/barmkin-mod-clear-taint`.
- Secret rules are a hand-maintained copy of barmkin's. Keep them in sync when barmkin changes.