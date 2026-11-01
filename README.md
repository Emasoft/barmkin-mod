# barmkin-mod

**A security layer for Claude Code, shipped as a Claude Code mods plugin.** It redacts secrets, tracks untrusted content, and blocks the tool calls that would let an injected instruction send your data somewhere.

[![CI](https://github.com/Emasoft/barmkin-mod/actions/workflows/ci.yml/badge.svg)](https://github.com/Emasoft/barmkin-mod/actions/workflows/ci.yml)

Emasoft fork of [samfrmr/barmkin-mod](https://github.com/samfrmr/barmkin-mod): the Jev key comes from OPENROUTER_API_KEY, the default endpoint is OpenRouter, and the OpenCode host is removed.

[Features](#features) · [Quick start](#quick-start) · [Configuration](#configuration) · [Switches](#switches) · [How it works](#how-it-works) · [Limits](#limits) · [Development](#development)

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
| **Switches and self-protection** | Every protection above has a switch, on by default, set from a panel or `/barmkin-mod-rule`. A switch changes only from your own prompt or the panel, and self-protection denies the calls it recognises that would change the switches, the install, or the settings that enable the mod. See [Switches](#switches) and [Limits](#limits). |

## What this fork changes, and why

This fork keeps autonomous and unattended Claude Code sessions running while you are away, without giving up protection against truly dangerous actions. Each change below serves that goal, and its reason is written next to it so a later session can judge whether the reason still holds.

- **The Jev key comes from the `OPENROUTER_API_KEY` environment variable.** The plugin no longer has a key option. Why: one source for the secret, shared with your other tools, and never written into settings.
- **Default endpoint `https://openrouter.ai/api` and default model `~typesafe/jev-latest`.** Why: the classifier works with no configuration once the key is set, and it follows new Jev versions without an edit.
- **Any Jev version reply is accepted.** The upstream check accepted only Jev 1.13. Why: the `jev-latest` alias moves across versions, and a fixed check would turn every screen into "classifier unavailable", which taints sessions. The questions and the 0.5 taint threshold were calibrated on Jev 1.13, so scores from a later version are uncalibrated; pin `typesafe/jev-1.13-20260917` for calibrated scores.
- **The OpenCode host (`opencode/`, `opencode-canary/`) is removed.** Why: this fork targets Claude Code only.
- **Installs from the marketplace of this fork, `emasoft-barmkin`.** Why: installs and updates come from the fork, not from the upstream marketplace.
- **Every protection can be switched on and off, from a panel or a slash command.** `/barmkin-mod-panel` opens the switch panel, `/barmkin-mod-rule list` lists the switches, and `/barmkin-mod-rule <id> on|off` sets one. Every switch starts on; with every switch on, every check of 0.2.2 runs as before, plus self-protection (below). The mod also opens the panel at session start, without taking the focus: in a terminal at least 144 columns wide it appears beside the chat unasked, and in a narrower one it waits until you widen the terminal or run `/barmkin-mod-panel`. Why: strict rules protect an attended session but block an unattended one, so the posture must be selectable. See [Switches](#switches).
- **Self-protection guards the switches and the mod itself, against the calls it recognises.** While it is on, it denies running the switch command through a tool; writing the switch store, the plugin store folder, the installed copy or the marketplace clone; a Write or Edit of a settings file that changes this plugin's entries or adds, changes or removes `disableAllHooks`, `allowManagedHooksOnly` or `allowManagedModsOnly`; a shell command that writes, moves or removes a Claude Code settings file; and uninstalling or disabling the plugin or removing its marketplace. It reads how a call is spelled, so a call it does not recognise is not stopped: see [Limits](#limits). Why: a switch the model can turn off protects nothing.
- **Upgrading from 0.2.2: calls that 0.2.2 ran and self-protection now denies.** `rm` or `mv` of any folder named `.claude` (a project one too), of its plugins folder, or of plugins/cache, plugins/marketplaces or plugins/store; a shell command that names barmkin-mod and a settings file, even to read it; any shell write of a Claude Code settings file (the Write and Edit tools still work, and are checked); a settings Write over a file larger than 4 MiB, and a settings Edit whose text to replace is not in the file; a command that names the plugin store folder with a glob that could match the switch store, or that changes files there; and an MCP call whose input names a protected path, a settings file beside this plugin, or a Claude Code settings file beside a key that enables plugins or turns hooks off. Turn `self-protection` off to run one of them.

**In progress, NOT built yet.** This section will be updated as each part lands.

- **Jev decides in place of an absent user.** A conservative command gate blocks only blatantly destructive, malicious or exfiltrating commands, reads the recent messages of the agent for context, and allows temporary and cache cleanup. Why: when no person is present to answer a prompt, a classifier should decide, but only for the clear cases.

## Quick start

**Requirements:** Claude Code **2.1.287 or later** (the mod checks at session start and warns on older builds), and Node 22 for validation and tests.

barmkin-mod is a Claude Code plugin. Install it with `claude plugin marketplace add Emasoft/barmkin-mod`, then `claude plugin install barmkin-mod@emasoft-barmkin`, then fill in the [options](#configuration) when prompted. The Jev key comes from the OPENROUTER_API_KEY environment variable.
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
> For full coverage, seat the plugin in managed `prependPlugins`. Unseated, it cannot see skill text, `CLAUDE.md` or other prompt-assembly content. If `sec-default` is seated ahead of it, it still cannot see `skill.prompt`, `prompt.context` or `prompt.section`.

To try it from a local checkout:

```sh
git clone https://github.com/Emasoft/barmkin-mod.git
cd barmkin-mod
npm ci
npm run validate   # claude plugin validate --strict .
```

At session start the mod runs a posture self-check and emits one line per condition, naming the condition, why it matters and the fix. It warns when:

- the plugin is not seated in managed `prependPlugins`,
- `permissions.defaultMode` is `bypassPermissions`,
- the Bash sandbox is off, which removes the OS-level egress floor,
- `disableSkillShellExecution` is unset, so skill inline shell bypasses every `tool.call` guard,
- `mcp_server_allowlist` is empty.

A clear session shows one line beneath the mode switcher: green `🏰 Barmkin session guard active` when Jev is configured and its breaker is closed (this does not claim any request succeeded), or amber `🏰 Barmkin session guard degraded` when Jev is not configured or the breaker is open. A tainted session shows a single red `🚨 TAINTED` line above the prompt that names the clear path for the active `taint_clear` posture.

## Configuration

| Option | Default | Purpose |
|---|---|---|
| `jev_base_url` | `https://openrouter.ai/api` | System One endpoint, OpenRouter style by default. The mod POSTs to `{base_url}/v1/systemone`. An empty value uses this default. |
| `jev_model` | `~typesafe/jev-latest` | Jev model id or alias. Any Jev reply is accepted. The classifier's questions and its 0.5 taint threshold were calibrated on Jev 1.13; on a later version (the default `~typesafe/jev-latest` is 1.14 today) scores are uncalibrated, and `typesafe/jev-1.13-20260917` pins the calibrated version. |
| `OPENROUTER_API_KEY` (environment variable, not a plugin option) | none | Bearer key for the endpoint, read from the environment at each use and never logged. Without it Jev is not configured and the classifier is not called. |
| `mcp_server_allowlist` | empty | Comma-separated MCP server names allowed to run tools. Empty allows all (audit only). |
| `taint_clear` | `human-origin` | `human-origin`: a person's prompt clears the taint. `sticky`: it holds until `/compact`, `/clear` or `/barmkin-mod-clear-taint`. |
| `sdk_prompts_clear_taint` | `false` | Let SDK prompts clear the taint. For headless lanes (`claude -p`, the Agent SDK) only. |

| Command | Description |
|---|---|
| `/barmkin-mod-status` | Show taint, circuit-breaker state, the last classifier verdict and the last shadow-screen scores. |
| `/barmkin-mod-clear-taint` | Clear the taint, only from a person's prompt. The only way to clear a taint for content the classifier could not read. |
| `/barmkin-mod-rule list` | List every switch with its state. |
| `/barmkin-mod-rule <id> on\|off` | Turn one switch on or off, only from a person's prompt. |
| `/barmkin-mod-panel` | Open the switch panel and give it the focus. |

## Switches

Each protection has a switch. Every switch starts **on**: with every switch on, every check of 0.2.2 runs as before, plus self-protection, which is new in 0.3.0 and denies some calls 0.2.2 ran (listed under [What this fork changes](#what-this-fork-changes-and-why)). A switch that is off skips its check; it never turns a deny into an allow, and it cannot loosen a decision made by Claude Code or another plugin.

- **The panel.** `/barmkin-mod-panel` opens a pane that lists every switch and gives it the keyboard. In a wide fullscreen terminal it docks beside the chat; otherwise it opens above the prompt. The mod also opens it at session start without taking the focus, but Claude Code places a pane nobody asked for only in a terminal at least 144 columns wide; in a narrower one it waits until the terminal is widened or you run `/barmkin-mod-panel`. Click a row in the Desktop app to flip it. In the terminal, Tab moves from row to row (Up and Down also do while the whole list fits, and scroll it when it does not), Enter flips the focused row, and Esc closes the panel.
- **The command.** `/barmkin-mod-rule list` prints every switch with its state. `/barmkin-mod-rule <id> on` or `/barmkin-mod-rule <id> off` sets one.
- **Who may change a switch.** Only a person: a prompt typed in the composer or sent through the bridge, or a click or key press on the panel. A plugin (even one acting as the user), the SDK, a task notification, a scheduled trigger and a peer session are refused, and the refusal names the origin it saw. Another plugin cannot make its run look like yours: Claude Code skips a hook that rewrites the origin (measured with the test kit). Which origin the Desktop app gives a command typed there is not measured yet; if it is neither the composer nor the bridge, the command refuses there, and the panel still works. While self-protection is on, it denies the calls it recognises that would reach the command through the Skill tool, or the switch store through a file tool, an MCP tool or the shell.
- **Where they are kept.** The switches are saved user-wide in the store of the mod, so they hold for every session and project. Each session keeps a fingerprint of what it last wrote or saw, in its state and in the loaded mod, so the fingerprint lasts through `/clear`, `/resume` and `/branch`. If the store changes from outside the session, the session writes its own values back at its next check (session start, those three commands, a switch change, or `/barmkin-mod-rule`) and shows a notice. A new session, a `claude -p` child or a scheduled run has no fingerprint and takes the store as written, so a store edited through a call self-protection does not recognise takes effect in every later session. The log at session start, and after each of those three commands, names every switch that is off.
- **What you see.** While a protection is off, one amber line above the prompt names every switch that is off, and the guard label turns amber. `/barmkin-mod-status` lists them too. The shadow screen is annotation only, so turning it off draws no warning.

`self-protection` is new in 0.3.0. `web-screen`, `skill-shell-mediation` and `a2a-outbound` are new switches for checks that 0.2.2 ran as part of a larger guard.

| Switch | When on | When off |
|---|---|---|
| `egress-gate` | Outward-effect calls (shell, network, web, MCP writes, persistence writes) are denied or warned on by taint and Rule of Two. | No egress class is checked, except the destructive tier, which has its own switch. |
| `destructive-tier` | `rm -rf` of roots, home or secret paths, disk wipes and git history rewrites warn, and deny while tainted. | The destructive and history-rewrite classes are not checked. |
| `taint` | Screened content that scores as injection, a skill load or hidden text marks the session tainted. | Nothing marks the session tainted, and a taint already held is ignored by every gate. |
| `taint-blocks-egress` | While tainted, each egress class keeps its posture (deny or warn), and a skill load is refused. | A taint alone changes no egress decision; the destructive tier warns as on a clean session. |
| `rule-of-two` | Tainted plus sensitive access denies every egress class. | Sensitive access never escalates an egress decision. |
| `skill-load-taints` | Every Skill tool load taints the session. | A skill load does not taint the session. |
| `spawn-blocked-when-tainted` | A subagent spawn is refused while the session is tainted. | Subagents spawn whatever the taint. |
| `classifier-gap-needs-ack` | Content Jev could not fully read taints until a person runs `/barmkin-mod-clear-taint`. | Such content taints like any screen hit, and a message clears it. |
| `outside-cwd-read-taints` | A Read of a file outside the working directory is screened as untrusted content. | Reads outside the working directory are not screened. |
| `heuristic-only-taint` | The local injection heuristics can taint without a Jev score. | Only a Jev score taints on the injection question. |
| `consume-own-notifications` | Task notifications and scheduled triggers are screened like peer messages, and can be withheld. | Task notifications and scheduled triggers are delivered unscreened. |
| `jev-screening` | Jev System One screens untrusted content (needs `OPENROUTER_API_KEY`). | Only the local heuristics screen; no classifier request is sent. |
| `shadow-screen` | Shadow questions are asked beside the real screen, for contrast only. | No shadow request is sent. |
| `web-screen` | WebFetch and WebSearch results are screened for injection. | Web results are not screened. |
| `mcp-guard` | Server allowlist, description hardening and MCP result screening. | No MCP allowlist, description hardening or result screening. |
| `skill-guard` | Skill bodies and the skill listing are screened. | Skill bodies and the skill listing are not screened. |
| `skill-shell-mediation` | The inline shell of a skill may not run outward-effect commands or read credential paths. | Inline skill shell is left to the permission layer. |
| `a2a-firewall` | Inbound agent messages are screened, and withheld on a hit or over 16 KiB. | Inbound messages are delivered unscreened. |
| `a2a-outbound` | Outbound agent messages over 16 KiB or holding a secret are not sent. | Outbound messages are sent unchecked. |
| `redaction` | Secrets are redacted in tool results and prompts, with the scan-size limits. | Tool results, prompts and skill bodies pass unredacted and unscrubbed, nothing is withheld for size, and a credential in a result no longer counts as sensitive access. |
| `posture-check` | Session-start check of version, seating, bypass mode, sandbox, skill shell and MCP allowlist. | No posture line is shown at session start. |
| `self-protection` | The switch store and the plugin store folder, the install and marketplace folders, the settings entries of this plugin, the settings keys that turn hooks off, and its uninstall are guarded against the calls it recognises (see [Limits](#limits)). | Those calls are not checked, and an edited switch store is accepted. |

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

**Switches and self-protection**

- Two sessions open at once each write their own values back when the other changes a switch. Change switches in one session at a time, then start the others again.
- A new session, a `claude -p` child and a scheduled run start with no fingerprint and take the switch store as written. The mod has nowhere to keep a fingerprint that the model could not rewrite too: whatever the account can write on disk, a shell can write. So a store edited through a call self-protection does not recognise takes effect in every later session. The session-start log names every switch that is off.
- Self-protection judges how a call is spelled. It follows the working directory and symbolic links, but not a path assembled from variables or `cd`. In a configuration folder not named `.claude` (`CLAUDE_CONFIG_DIR`) it still recognises the switch store, the installed copy, the marketplace clone and the files only Claude Code uses (`installed_plugins.json`, `known_marketplaces.json`, `managed-settings.json`), but not removing the folder, its plugins folder or the plugin cache, a `find` over the folder, or a shell write of its `settings.json` that names no key enabling plugins or turning hooks off.
- Shell writes are recognised by their usual shapes: a redirection, `tee`, `cp`, `mv`, `rm`, `dd`, an in-place `sed`, `perl` or `yq`, an interpreter's inline code (`python3 -c`, `node -e`), `find -exec` or `xargs`. A script file that writes a settings file or the store is not recognised, nor a write of a bare `settings.json` after a `cd` that names no settings key, nor a `find` over the whole configuration folder that changes files without a name pattern. For the store, the tamper check still writes the session's values back at its next check.
- An MCP call that writes a settings file is denied only when its input names the file together with this plugin or its marketplace, or names it under `.claude` together with a key that enables plugins or turns hooks off. A write that drops the `enabledPlugins` entry without naming any of them is not recognised.
- A copy loaded with `--plugin-dir` is not protected by path: its folder is your working tree. An installed copy is protected under the marketplace it came from and under `emasoft-barmkin`.
- The model can start a child session with `claude --safe-mode -p ...` or `claude --bare -p ...`, which runs with no installed mod at all. Self-protection does not stop that; a permission rule that denies those commands can.
- It errs on the side of denying. The calls 0.2.2 ran that it denies while it is on are listed under [What this fork changes](#what-this-fork-changes-and-why).
- The panel has no keyboard shortcuts, on purpose: a shortcut bound to a row could flip a switch by accident.

**Maintenance**

- Secret rules are a hand-maintained copy of barmkin's. Keep them in sync when barmkin changes.

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
  switches.ts           the switch registry, the store tamper check and the switch command
  self-protection.ts    guards for the switch store, the install, the settings entries and the keys that turn hooks off
tests/                  one test file per lib module, plus integration
.claude-plugin/         plugin manifest and option schema
```

```sh
npm ci
npm run validate   # claude plugin validate --strict .
npm test           # claude plugin test
```

CI runs both on every push to `main` and on pull requests, alongside workflow tests, a gitleaks secret scan (`.gitleaks.toml`) and CodeQL. The Claude Code dependency in `package.json` is pinned to the version floor, so CI is the real verification surface.

Pull requests for this fork go to [Emasoft/barmkin-mod](https://github.com/Emasoft/barmkin-mod). The original project is [samfrmr/barmkin-mod](https://github.com/samfrmr/barmkin-mod).

Guarding hooks fail closed: if one errors, the action is denied or the content withheld. Advisory hooks, such as the HUD, fail open and leave the result unchanged.

## Limits

- The shell denylist and the destructive classes can be evaded (obfuscated or variable-indirected commands). Enable the Bash sandbox so its egress allowlist sits underneath it.
- Size limits. Every redaction rule runs in time linear in the text, so a tool result is scanned whole up to 256 KiB per string and 1 MiB per result. Past those limits:
  - A string over 256 KiB in a result that no injection screen covers (Bash, Grep, Glob, a Read inside the working directory) shows a scanned prefix of about 12 KiB, cut at a line or delimiter that no secret match crosses, followed by a note with the shown and total character counts and how to page: `Read` with `offset` and `limit`, or a narrower command. The hidden part is never shown and never matched, and invisible text anywhere in the string still counts toward the taint threshold. If no safe cut exists, the result is withheld.
  - A result whose strings together pass 1 MiB, and a Read image past about 190 KiB, are withheld, since a prefix of either is not useful.
- Untrusted content is withheld over 16 KiB, never cut: web fetches and searches, MCP results, reads outside the working directory, skill bodies, peer messages, your prompts and outbound messages. The classifier reads such content in up to five overlapping 4,000-character windows. The withhold message says it is a size limit and tells Claude to fetch the content in smaller pieces rather than ask you.
- With Jev configured, the classifier endpoint receives up to about 18,000 characters of redacted untrusted content per screen, in up to five requests, plus two more requests per window for the shadow screen (below). Content with a part the classifier could not read taints the session until acknowledged with `/barmkin-mod-clear-taint`.
- Secret rules are a hand-maintained copy of barmkin's. Keep them in sync when barmkin changes.