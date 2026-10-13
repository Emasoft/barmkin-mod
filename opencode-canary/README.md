# barmkin-opencode canary

**This is a canary, not a mitigation.** It protects nothing. It does not redact, screen, gate or block anything, and installing it does not make a session safer. Its only job is to tell you, in the terminal UI, when the `barmkin-opencode` guard is **not** loaded, so that an unguarded session does not look like a guarded one.

## Why it exists

OpenCode 2.x has no administrator-locked plugin seat. A guard can be missing without any sign:

- A repository's `opencode.json` containing `"plugins": ["-barmkin-opencode"]` unloads the guard silently: no warning, no failed entry in the plugin list.
- A guard whose `setup` throws is dropped with one log line and the session runs unguarded.
- A guard whose transform throws later is disabled mid-session.

The guard's own TUI half cannot report any of this, because OpenCode loads a plugin's TUI half only after its server half has set up. A guard that is not running shows nothing at all, and "nothing" looks the same as "fine". The canary is a separate plugin with no dependency on the guard, so it is still running when the guard is not.

## What you see

| Plugin list says | Footer chip | Banner above the prompt | Toast |
|---|---|---|---|
| no `barmkin-opencode` entry | `BARMKIN GUARD ABSENT` (red) | `BARMKIN GUARD ABSENT: this session is UNGUARDED…` | yes |
| `barmkin-opencode` failed to load, or reports any status other than active | `BARMKIN GUARD FAILED` (red) | `BARMKIN GUARD FAILED: this session is UNGUARDED.` plus the first line of the error | yes |
| `barmkin-opencode` listed as active | `barmkin guard listed (canary cannot verify it works)` (muted) | none | none |

"Listed" is the best the canary can say. It reads the plugin inventory, which says the guard is loaded; it cannot say the guard works. For the guard's own posture, use `/barmkin-mod-status` from the guard's TUI half.

The banner sits in the `session.composer.top` slot, which OpenCode renders directly above a "Permission required" prompt, so an unguarded session is flagged at the moment a person is asked to approve something. The state is re-read every 10 seconds and whenever the plugin list changes.

## What it does not cover

- **Headless runs** (`opencode run`, `serve` with no TUI attached). There is no terminal UI to render into, so the canary says nothing. The only trace is the log line OpenCode writes when a plugin fails to load.
- **The canary can be removed too.** A project config's `-barmkin-opencode-canary` entry unloads it with the same silence as the guard. Seat the canary the same way as the guard (see the seat recipe in `opencode/README.md`); a canary seated more weakly than the guard proves little.
- **A guard that is loaded and broken.** The canary cannot tell a guard that registered its hooks from one that is listed and inert.
- **A guard that was never meant to be there.** On a machine that does not use barmkin-opencode the canary reports `ABSENT`, correctly: nothing is guarding the session.

This does not change the non-equivalence contract in the main README: the barmkin-opencode port is partial, is not equivalent to barmkin-mod for Claude Code, and OpenCode 2 has no administrator-locked plugin seat.

## Install

The canary is a plugin directory with a server entry (`server.ts`, empty by design) and a TUI entry (`tui.tsx`). Add it to the plugin list next to the guard, for example in `OPENCODE_CONFIG_CONTENT`:

```json
{ "plugins": ["/path/to/barmkin-opencode", "/path/to/opencode-canary"] }
```

If you use the plugin allowlist from the seat recipe (`experimental.policies`), allow the canary's directory as well as the guard's, or the allowlist blocks it.

## Options

Passed as plugin options in config, using the object form of a `plugins` entry:

```json
{ "plugins": [{ "package": "/path/to/opencode-canary", "options": { "quiet": true } }] }
```

| Option | Default | Meaning |
|---|---|---|
| `guardId` | `barmkin-opencode` | Plugin id to look for. |
| `quiet` | `false` | Hide the muted "listed" chip. The red states are always shown. |

## Files

- `server.ts` - server half; registers nothing.
- `tui.tsx` - the check, the footer chip, the banner and the toast. It imports nothing from `opencode/`, so it ships and is seated separately.
