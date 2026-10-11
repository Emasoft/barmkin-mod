# 🏰  barmkin-session-guard  🏰

A security layer for Claude Code, packaged as a Claude Code mods plugin. It redacts secrets, tracks untrusted content, and blocks the tool calls that would let an injected instruction send your data somewhere.

> [!NOTE]
> barmkin-mod only ever tightens. Every hook adds a deny, withhold or warning on top of a decision someone else made. None of them can turn a deny into an allow.

## What it does

| Capability | What happens |
|---|---|
| **Secret redaction** | Tool results and outbound messages are scanned for private keys, JWTs and AWS, Anthropic, OpenAI, GitHub, Stripe, Slack, npm and other tokens. Matches are replaced with `[REDACTED:<category>#n]`. |
| **Untrusted-content taint** | Web fetches, MCP results, reads outside the working directory, peer messages and skill loads are screened for injection. A hit taints the session. |
| **Rule-of-Two egress gate** | Combines three conditions: **A** untrusted input, **B** sensitive access, **C** an outward effect. With A alone, each egress class keeps its own posture (warn or deny). With A and B, every class denies. |
| **MCP tool-poisoning guard** | Strips instruction-like sentences from MCP tool descriptions and enforces an optional server allowlist. |
| **Skill guards** | Denies skill inline shell (`` !`command` ``) while mediation applies, and screens skill bodies and the skill listing. |
| **Agent-to-agent firewall** | Screens inbound peer messages, blocks outbound messages that contain secrets, and refuses to spawn subagents while the session is tainted. |
| **Jev System One classifier** | An optional remote classifier that can only raise suspicion, never lower it. |
| **Invisible-text scrub** | Strips ANSI escapes, bidi overrides, zero-width characters and the Unicode Tags block from tool results, descriptions and messages. |

### Egress classes

The gate recognises these outward effects. Shell classes read the `command` of a
`Bash`, `PowerShell` or `Monitor` call; each identifies the real head binary of
every pipeline and subshell segment (past `sudo`, `env VAR=`, inline `VAR=` and a
`bash -c '…'` wrapper) and tests the exfil signal — command substitution, body
flags, redirection, a remote spec — against the raw command.

- Outward-effect shell commands (`shell-outward`): `git push`, `curl` with a body, `scp` to a host, a pipe to `sh`, and similar. *Denies on A alone.*
- Network clients (`net-client`): `curl`/`wget` with a body flag or a `$(…)`/backtick URL substitution, the socket tools `nc`/`ncat`/`socat`/`telnet`/`ftp`, `/dev/tcp` and `/dev/udp`, and `ssh`/`scp`/`sftp`/`rsync` to a remote. `nc -z` port scans and local-only copies are excluded; a `curl`/`wget` to `localhost` without substitution is exempt. *Denies on A alone.*
- DNS/probe exfil (`dns`): `nslookup`/`dig`/`host`/`ping`/`traceroute`/… with a substituted name. *Warns on A alone.*
- Forge writes (`forge`): mutating `gh`/`glab` (`issue`/`pr`/`gist`/`release`/… create/comment/edit/upload/…), and `gh api` with a `POST`/`PUT`/`PATCH`/`DELETE` method or a `-f`/`-F`/`--field` body — the Comment-and-Control channel. Read verbs stay clear. *Warns on A alone.*
- Package/image publishes (`publish`): `npm`/`pnpm`/`yarn`/`bun`/`cargo publish`, `docker`/`podman push`, `twine upload`, `gem push`. `--dry-run` is excluded. *Warns on A alone.*
- Cloud object-store uploads (`cloud`): `aws s3 cp|mv|sync`, `aws s3api put-object`, `gsutil`/`gcloud storage cp|rsync`, `az storage … upload`. Read ops stay clear. *Warns on A alone.*
- Inline interpreter network calls (`interpreter-net`): `python`/`node`/`deno`/`ruby`/`perl`/`php` run with `-c`/`-e`/`--eval` where the inline script makes a network call (`urlopen`, `fetch(`, `requests.get`, a `socket(`/`.connect(` call, `http.request`, `/dev/tcp`, …); a bare URL literal or `socket.gethostname()` is not enough. *Denies on A alone.*
- Shell writes to persistence surfaces (`persist-shell`): a redirection, `tee`/`cp`/`mv`/`install`/`ln`/`rsync`/`dd`, or a `sed -i` whose destination is a persistence path (the last argument for `cp`/`mv`/`install`/`ln`/`rsync`, `of=` for `dd`, so reading one as a source does not warn). *Warns on A alone.*
- Web fetches (`web-fetch`) and web searches (`web-search`), since the URL and the query are each a channel. *Fetch denies, search warns, on A alone.*
- Monitor WebSockets (`monitor-ws`): a `Monitor` call opening an outbound `ws`. *Denies on A alone.*
- MCP write-class tools (`mcp-write`): names containing verbs such as `create`, `send`, `post`, `update`, `delete`, `save`, `set`, `insert` or `upsert`. The ambiguous `run`/`execute`/`request` are not treated as writes.
- Skill loads (`skill-load`).
- File-tool writes to persistence surfaces (`persistence`): `CLAUDE.md`, `AGENTS.md`, `.claude/`, `.mcp.json`, CI workflows, git hooks, shell rc files, `~/.ssh`, `~/.local/bin`, `.vscode/{tasks,settings,launch}.json`, `.devcontainer/`, `package.json`, `Makefile`, `.envrc`, `.pre-commit-config.yaml` and `.config/fish/`. `package.json` and `Makefile` are edited constantly, so these only warn (never deny) on A alone.

The shell classes are a naive tokenizer, not a shell parser: quoting tricks (`c''url`, a `|` inside a quoted string, base64-wrapped binaries) evade them. That is inherent — the Bash sandbox's egress allowlist is the enforcement floor beneath them (see Limits).

The classifier reads only the first 4,000 characters of a piece of content, after redaction. With Jev configured, untrusted content longer than that taints the session even when nothing in it looks like an injection, because the rest was never classified. This taint needs an explicit acknowledgement: a later message, `/clear` or compaction does not clear it, whatever `taint_clear` is set to, and only `/barmkin-mod-clear-taint` from a person does. Without Jev configured, the classifier is not claimed to have read anything, so length alone does not taint.

Sensitive access (leg B) is set when a call touches a secret path such as `~/.ssh`, `~/.aws`, `.env` or `.git-credentials`, when a redaction rule fires on a tool result, or when the classifier reports credentials in the content.

## Requirements

- Claude Code **2.1.287 or later**. The mod checks at session start and warns on older builds.
- Node 22 for validation and tests.

## Install

barmkin-mod is a Claude Code plugin. Point your Claude Code plugin install at this repository, then fill in the options below when prompted.

> [!IMPORTANT]
> For full coverage, seat the plugin in managed `prependPlugins`. Unseated, it cannot see skill text, `CLAUDE.md` or other prompt-assembly content. If `sec-default` is seated ahead of it, it still cannot see `skill.prompt`, `prompt.context` or `prompt.section`.

At session start the mod runs a posture self-check and emits one concise line per condition, naming the condition, why it matters and the fix. Each line is its own transcript row (`$.ui.status` holds a single line per plugin and cannot show several). It warns when:

- the plugin is not seated in managed `prependPlugins`,
- `permissions.defaultMode` is `bypassPermissions`,
- the Bash sandbox is off, which removes the OS-level egress floor,
- `disableSkillShellExecution` is unset, so skill inline shell bypasses every `tool.call` guard,
- `mcp_server_allowlist` is empty.

## Configuration

| Option | Default | Purpose |
|---|---|---|
| `jev_base_url` | empty | System One endpoint, OpenRouter or Vercel AI Gateway style. The mod POSTs to `{base_url}/v1/systemone`. Empty disables the classifier and falls back to pattern heuristics. |
| `jev_model` | `jev-1.13.0` | Pinned Jev model id. Must match the `jev-1.13` pattern. |
| `jev_api_key` | none | Bearer credential. Stored in secure credential storage and never logged. |
| `mcp_server_allowlist` | empty | Comma-separated MCP server names allowed to run tools. Empty allows all (audit only). |
| `taint_clear` | `human-origin` | `human-origin`: a person's prompt clears the taint. `sticky`: it holds until `/compact`, `/clear` or `/barmkin-mod-clear-taint`. |
| `sdk_prompts_clear_taint` | `false` | Let SDK prompts clear the taint. For headless lanes (`claude -p`, the Agent SDK) only. |

## Commands

| Command | Description |
|---|---|
| `/barmkin-mod-status` | Show taint, circuit-breaker state and the last classifier verdict. |
| `/barmkin-mod-clear-taint` | Clear the taint, only from a person's prompt. The only way to clear a taint for content past the classifier's 4,000-character window. |

A clear session shows one line directly beneath the mode-switcher line under the prompt: green `🏰 Barmkin session guard active` when Jev is configured and its classifier breaker is closed (this does not claim any request succeeded), or amber `🏰 Barmkin session guard degraded` when Jev is not configured or the breaker is open. A single red line above the prompt (`🚨 TAINTED: untrusted content active · 🚫 outbound actions may be restricted · 🧹 clear: …`) shows when the session is tainted, and names the clear path for the active `taint_clear` posture.

## Layout

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
  posture.ts            posture checks
tests/                  one test file per lib module, plus integration
.claude-plugin/         plugin manifest and option schema
```

## Development

```sh
npm ci
npm run validate   # claude plugin validate --strict .
npm test           # claude plugin test
```

CI runs both on every push to `main` and on pull requests, alongside workflow tests, a gitleaks secret scan (`.gitleaks.toml`) and CodeQL. `@anthropic-ai/claude-code` is pinned in `package.json` to the version floor, so CI is the real verification surface.

Guarding hooks fail closed: if one errors, the action is denied or the content withheld. Advisory hooks, such as the HUD, fail open and leave the result unchanged.

## Limits

- The shell denylist can be evaded. Enable the Bash sandbox so its egress allowlist sits underneath it.
- Size limits. Every redaction rule runs in time linear in the text, so a tool result is scanned whole up to 256 KiB per string and 1 MiB per result. Past those limits:
  - A string over 256 KiB in a result that no injection screen covers (Bash, Grep, Glob, a Read inside the working directory) shows a scanned prefix of about 12 KiB, cut at a line or delimiter that no secret match crosses, followed by a note with the shown and total character counts and how to page: `Read` with `offset` and `limit`, or a narrower command. The hidden part is never shown and never matched, and invisible text anywhere in the string still counts toward the taint threshold. If no safe cut exists, the result is withheld.
  - A result whose strings together pass 1 MiB, and a Read image past about 190 KiB, are withheld, since a prefix of either is not useful.
- Untrusted content is withheld over 16 KiB, never cut: web fetches and searches, MCP results, reads outside the working directory, skill bodies, peer messages, your prompts and outbound messages. The classifier reads 4,000 characters of such content, so more text would be mostly unscreened. The withhold message says it is a size limit and tells Claude to fetch the content in smaller pieces rather than ask you.
- With Jev configured, the classifier sees only the first 4,000 characters of redacted content; longer content taints the session until acknowledged with `/barmkin-mod-clear-taint`.
- Secret rules are a hand-maintained copy of barmkin's. Keep them in sync when barmkin changes.
