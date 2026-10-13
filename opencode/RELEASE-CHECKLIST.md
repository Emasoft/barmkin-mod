# Release checklist: barmkin-opencode on OpenCode 2.x

OpenCode 2.x ships about seven stable releases a week, and `experimental.policies` is still experimental. The T-SEAT suite in `tests/` runs against a model of the host, so only a run against the real binary shows that a new release still behaves the way the model says. Do this for **every** OpenCode version the port claims to support.

## 1. Pin the exact version

- [ ] Name one exact OpenCode version (for example `2.0.27`), never a range or `latest`. Record it in the release notes and in the README's tested range.
- [ ] Install exactly that `@opencode/cli` build, and note the Bun version it embeds (`strings <binary> | grep 'Bun v'`). The port targets that Bun, currently 1.4.2.
- [ ] The tested range starts at 2.0.27. Do not claim anything earlier, and do not claim a version that has not passed section 2.
- [ ] If the version is new, diff the plugin-relevant paths against the last tested tag (plugin runtime, supervisor, hook runner, config discovery and precedence, permission, tool, shell, policy). A non-additive change is a stop: re-scout before continuing.

## 2. Per-release subset re-run

Run against the real binary with an isolated HOME and every XDG directory inside a scratch directory, `--standalone`, a scripted model, and `< /dev/null` for headless runs. Never use the shared background service. The check ids are from the 2.x re-scout.

Seat and removal (the T-SEAT claims):

- [ ] **V1** Seven seats load in the documented order, with `OPENCODE_CONFIG_CONTENT` last.
- [ ] **V10, V12, V13** A repo `"-barmkin-opencode"` and `"-<x>.*"` unload a file-seated guard; they do not unload the `OPENCODE_CONFIG_CONTENT` guard.
- [ ] **V14** `OPENCODE_DISABLE_PROJECT_CONFIG=1` keeps every file seat against repo removals.
- [ ] **V15, V16** The user-global allowlist blocks repo and global-dir plugins and ignores a repo counter-policy; a repo `-id` still removes an allowlisted guard from a file seat. Confirm the exact `experimental.policies` key names and the `plugin:<id>` resource spelling on this version.
- [ ] **V38** The full recipe against a hostile repo: only the guard loads, the outward command is refused.
- [ ] **V41** Removal still leaves no log line and no failed entry (the canary and posture line are the only signal).

Deny and rewrite finality:

- [ ] **V2** A throw in `execute.before` refuses the tool; later before-hooks do not run.
- [ ] **V6, V7** `effect = "deny"` at `permission.evaluate` is still overridable by a later plugin; a throw is still final.
- [ ] **V8** A later plugin renaming `read` to `shell` is stopped at evaluate.
- [ ] **V9** A command rewritten in `shell.create.before` is stopped at evaluate, and evaluate sees the rewritten command.
- [ ] **V17, V19** A setup throw still drops the plugin with one WARN; a transform throw still disables the plugin mid-session. (The guard must never throw in a transform.)

Guard-specific:

- [ ] **V20, V21, V28** Redaction reaches the model on the completed and error paths and at `session.context` and `session.title`.
- [ ] **V23** The MCP description neutraliser, if shipped, still reaches both direct and Code Mode tool descriptions.
- [ ] **V24, V25, V32** The not-covered paths (MCP arguments at evaluate, Code Mode `fetch`, command-template shell) still behave as the README says. A path that becomes covered, or one that newly leaks, is a README change.
- [ ] **V34, V35** Toast, the three slots, and the canary still render; the native "plugin failed" indicator still appears.
- [ ] The shell-layer limitation in the README still holds: `shell.create.before` has no session in its inputs.

Suites:

- [ ] `cd opencode && BARMKIN_CONTRACT_STRICT=1 bun test` on the pinned Bun: every contract module present, nothing skipped.
- [ ] The shared library suites (`bun test` on the 16 library files, and `claude plugin test` for the Claude side) are green.

## 3. Posture-line snapshot gate

- [ ] Start the guard in the supported seat on the pinned version and capture the startup posture line verbatim.
- [ ] Compare it with the committed snapshot. The prefix is fixed text:
      `🏰 barmkin-opencode 0.1.0 (core <git-sha>) · partial port, not equivalent to barmkin-mod for Claude Code · OpenCode 2 has no administrator-locked plugin seat · not covered: <per-seat gaps>`
- [ ] Any change to the fixed wording needs captain approval. Only `<git-sha>` and `<per-seat gaps>` may vary between releases.
- [ ] Repeat in each seat the release claims (inline-config seat with and without the allowlist and project config off) and confirm the `not covered:` list names the gaps for that seat.
- [ ] Remove the seat and start again: confirm **no** posture line appears.
- [ ] `opencode/README.md` still carries the section 2.2 wording verbatim (`tests/docs-contract.spec.ts` checks this).

## 4. Sign-off

- [ ] README tested range updated to the pinned version.
- [ ] The release notes copy the four NOT-covered items and the sentence "OpenCode 2 has no administrator-locked plugin seat".
- [ ] Anything that failed above is either fixed or written into the README as a limitation before release.
