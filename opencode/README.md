# 🏰 barmkin-opencode 🏰

A partial port of barmkin-mod to **OpenCode 2.x**. It reuses the host-neutral library in `hooks/lib/` and adds an OpenCode plugin, `barmkin-opencode`, that redacts secrets, taints a session on untrusted content, and refuses outward-effect tools while the session is tainted.

> [!WARNING]
> **This is a partial port, not equivalent to barmkin-mod for Claude Code. OpenCode 2 has no administrator-locked plugin seat.** Read [What this is not](#what-this-is-not) before relying on it.

## What this is not

barmkin-opencode ships as a **user-owned seat, not administrator-enforced**. OpenCode 2.x has no machine-level or managed plugin seat: no `/etc/opencode`, no MDM path, no root-owned file. "Managed" on 2.x means policy only, and OpenCode's own threat model protects policy, not third-party plugins. A repository's `opencode.json` can unload this guard with one line unless project config is disabled or the guard is seated through `OPENCODE_CONFIG_CONTENT`.

Outward-effect tools (shell, web fetch, file writes) are refused while the session is tainted, **provided this guard is loaded**. The refusal is re-checked at OpenCode's permission step against the final command, URL or path, so another plugin cannot rewrite its way past it. It does **not** cover MCP tool arguments, Code Mode `fetch`, or command-template shell. **OpenCode 2 has no administrator-locked plugin seat:** a repository's `opencode.json` can unload this guard unless project config is disabled or the guard is seated through `OPENCODE_CONFIG_CONTENT`. **No posture line means no guard.**

### Not covered

These four are named so nobody assumes them:

1. **Evidence stays in stored transcripts.** Redaction rewrites what the model reads and what tool results store, but a tool call's `input` is stored raw, every shell command's full output is spilled raw to disk for 7 days before any hook runs, and background-shell and other synthetic messages reach the transcript raw. Secrets are not absent from the stored transcript.
2. **MCP tool descriptions are not screened by default.** The description neutraliser (`mcp-guard`) is optional (phase C-mcp). Unless it is shipped and enabled, an MCP server's poisoned tool description or server instructions reach the model unchanged.
3. **No protection when the guard is absent.** There is no `--pure` flag on 2.x, but nothing locks the guard in either. It is gone, silently, if a repository config removes it (`"plugins": ["-barmkin-opencode"]`), if the process runs without the seat's environment (a different `OPENCODE_CONFIG_CONTENT`, `--standalone` or `--server` against another environment, `opencode plugin remove`), or if its `setup` throws (the plugin is dropped with one WARN line and the session runs unguarded). A transform that throws later disables every hook of the plugin mid-session. Removal by config leaves no log line and no failed entry.
4. **The repo-plugin surround.** Code in a cloned repository that runs beside the guard (repository plugins, `.opencode/` plugins in the repository or any ancestor directory, repository commands and skills) is outside what this guard governs. Only the plugin allowlist and project config off keep it from loading, and both are operator choices, not defaults.

### Documented limitations

- **Human-origin clearing.** OpenCode 2's `session.prompt` hook carries no origin and synthetic user-role messages exist, so the guard cannot tell a person's message from an injected one. A taint is cleared only by the plugin's `/barmkin-mod-clear-taint` command, which the model's tool list cannot call. In background-service mode the local server URL and password sit in user files; whether a tainted model can reach that local API is unverified.
- **Command-template shell.** `` !`cmd` `` in a command template runs with no tool hook, no shell hook and no permission check. It cannot be mediated. Disabling project config removes repository command templates.
- **Shell layer.** OpenCode 2 does not give plugins the session identity of a shell call, so a session taint can restrict shell commands in unrelated sessions on the same instance, and a shell not launched through a tool call bypasses the shell gate entirely. (`shell.create.before` carries no session in its inputs.)

### Posture line

The plugin prints one line at startup naming the seat it found. Its wording is fixed:

```
🏰 barmkin-opencode 0.1.0 (core <git-sha>) · partial port, not equivalent to barmkin-mod for Claude Code · OpenCode 2 has no administrator-locked plugin seat · not covered: <per-seat gaps>
```

No line means the guard is not running.

## The seat recipe

The supported deployment has three parts. All three were verified together against a hostile repository (a repository that shipped its own plugins, `-barmkin-opencode` and `-*` removals, and a counter-policy): only the guard loaded and the outward command was refused.

1. **Seat the guard through `OPENCODE_CONFIG_CONTENT`.** It is the last third-party plugin in OpenCode's chain, and a repository's config cannot remove it. For the default background service, store it in the service environment (`opencode service set env OPENCODE_CONFIG_CONTENT '<json>'`); for `--standalone`, set it in the launcher's environment.
2. **Put a plugin allowlist in your user-global `opencode.json`.** Under `experimental.policies`, deny `plugin:*` and allow only `barmkin-opencode`. Then a repository cannot add its own plugins, and a repository policy cannot override yours. `experimental.policies` is an experimental key; recheck it on every release.
3. **Set `OPENCODE_DISABLE_PROJECT_CONFIG=1`** in the same environment. This drops repository and ancestor-directory config, including `AGENTS.md`-style config, commands and skills.

The inline-config seat and project config off each keep the guard loaded against a repository's removal entries on their own; the allowlist does not (a repository `-barmkin-opencode` still removes a guard seated in a file). Only the combination also stops repository plugins from running beside the guard. All three are **user-owned**: an environment variable or the user's `service.json`, plus the user's config file. The user, and any process running as the user, can change them.

A guard seated any other way (global `plugins/` directory, global `opencode.json`, `OPENCODE_CONFIG`) can be unloaded by one line in a cloned repository, and a later repository plugin can re-insert what the guard redacted.

## Install

1. Install OpenCode at an exact tested version (see [Tested range](#tested-range)). Do not run on an untested release.
2. Build the plugin (see [Build the bundle](RELEASE-CHECKLIST.md#build-the-bundle)) into a directory named `barmkin-opencode` containing `server.js` (a configured plugin must be a directory; a bare file path in `plugins[]` is rejected). Keep it outside OpenCode's auto-discovered `plugins/` directories so the seat, not discovery, loads it.
3. Seat it: set `OPENCODE_CONFIG_CONTENT='{"plugins":["/absolute/path/to/barmkin-opencode"]}'` for the service or the launcher.
4. Add the allowlist to the user-global `opencode.json` (deny `plugin:*`, allow `plugin:barmkin-opencode`).
5. Set `OPENCODE_DISABLE_PROJECT_CONFIG=1` in the same environment.
6. Start OpenCode and confirm the posture line appears. If it does not, the guard is not running.

The optional `opencode-canary/` package is a separate plugin that names the guard's state in the TUI, because a guard whose setup failed cannot report its own failure.

## Tested range

- **Starts at OpenCode 2.0.27** (the Linux x64 binary, embedded Bun 1.4.2). Nothing earlier is supported, and 1.x is not supported at all: a 1.x plugin does not load on 2.x.
- 2.0.28 changed the plugin context additively (source diff only; not run). It is not in the tested range until the checklist is run against it.
- OpenCode ships about seven stable releases a week and `experimental.policies` is still experimental. **Pin an exact version** and follow [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) on every upgrade.
- Linux only so far. The lab used a scripted model, not a real one.

## Tests

The T-SEAT contract suite lives in `tests/` as `*.spec.ts` (so `claude plugin test` does not pick up these Bun-only files) and runs on Bun 1.4.2:

```
cd opencode && bun test --tsconfig-override ./tsconfig.json
```

It checks, against a model of the 2.x host built from the verified behaviour: removal by `-id` and `-x.*`, the plugin allowlist, the inline-config seat, `permission.evaluate`-throw finality, tool-rename detection and shell-layer rewrite detection. It also checks that this README keeps its non-equivalence wording. It does **not** run the OpenCode binary; the per-release checklist does.

A contract test is skipped when its module is missing. Set `BARMKIN_CONTRACT_STRICT=1` (integration and release runs) to make a missing module fail instead. The shared library suites run with the same command plus `./tests ../tests`; see [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md).
