---
trdd-id: QAT87NRF
title: Every security function switchable, with a side panel
column: testing
status: tasked
created: 2026-10-30T02:42:43+0100
updated: 2026-11-01T04:44:14+0100
current-owner: main-agent@barmkin-mod
created-by: main-agent@barmkin-mod
task-type: feature
min-approval-requirement: none
assignee: main-agent@barmkin-mod
mandate: true
mandated-by: none
approved: true
approval-judge: main-agent@barmkin-mod
approval-datetime: 2026-10-30T02:42:43+0100
release-via: none
implementation-commits: [d7c6a64, ecb8e61, 18842cf, 569d387, a38c037, e2d144f, 87de54e, dce355a, 771fbb3, 36f3b67, 6602d9a, 517a97b, 5a3635a, 12b2f2b, b2e7409, dc429a1, b5cfee6, f374056, 291880c]
---

# Every security function switchable, with a side panel

## ⏵ STATE — READ THIS FIRST ON RESUME (authoritative; supersedes the body) — 2026-11-01

- Released: 0.3.0 is pushed to main at 9a2fb98 (a fast-forward) and installed at user scope, 0.2.2 to 0.3.0; a Claude Code restart applies it.
- The step-1 review (REVISE: 2 major, 5 minor, 3 nit) is answered by the commits dce355a to 9a2fb98, listed in implementation-commits.
- Open: acceptance box 4, the panel on the terminal and in the Desktop app at a narrow and a wide width. It is the owner's Desktop check, and it also settles which origin the Desktop app gives a /barmkin-mod-rule typed there (Known limits). Nothing else is open.
- NEXT ACTION: the owner runs the Desktop check and ticks box 4; the card can then close.

## Goal

Every security function barmkin-mod has today gets its own named switch, on by default (today's behaviour), changeable only by the person: from their own prompt (`/barmkin-mod-rule <id> on|off`, composer or Remote Control bridge origin) or from a side panel (`/barmkin-mod-panel`) that lists every switch and toggles one on a click (Desktop) or on Enter (terminal). This is step 1 of the continuity plan: later steps (cards for code rules, the Jev command gate and Jev autonomy) add their own switches to the same registry.

## Owner directives (verbatim)

- "continuity is ensured when the user is away by making jev decide on the questions, evaluating if a command is malicious or exfiltrate data or install malicious software, or change the configuration to allow an exploit or an easy attack. the instructions must tell jev to block only what is truly dangerous, destructive or malicious. deleting a folder with rm -rf on the temp folder, cache folder or any folder/subfolder inside the tmp, or the quivalent for windows, is not dangerous and should not be blocked. make some smart rules that jev must follow to decide, but be conservative. it must be blatantly destructive, dangerous or malicious to be stopped. otherwise jev must approve it. make jev prompt to include also the transcript of the agent messages just before the command to get a better idea of the context and to judge better."
- "continuity must be ensured by also prevent other blocking behaviours, making jev acting as the decider in place of the user."
- "make some rules that you think are too strict to be switc" / "switchable off and on with a command/skill."
- "remember that all individual security functionalities must be switchable on/off. so even the jev auto mode must be switchable on off."
- "add a panel with the list of all features and all rules state on/off, with the option to click on them to switch them on or off. it must be a panel that is visible on the right both on the tui and the desktop."
- Jev outage: "Retry, then stall (Recommended)". Autonomy: "always on". Go-ahead: "go on".

## Plan (step 1)

1. Switch registry `hooks/lib/switches.ts`: one switch per existing security function, each with an id, a one-line description and default on. Every gate checks its switch; off means that check does not run, never an allow of something another guard denied.
2. Storage in `$.store` (user-wide, kept between sessions), mirrored into `$.state` for the gates and the panel. Tamper check: a hash of the last value the mod wrote is kept in `$.state`; a store value that does not match is ignored, the last known value is written back, and a notice is shown.
3. Only a prompt of origin `composer` or `bridge` changes a switch (never `plugin`, even with `asUser`), plus presses in the panel.
4. Panel `/barmkin-mod-panel`: beside the transcript in a wide fullscreen terminal, above the prompt otherwise; opened at session start without taking focus.
5. Self-protection switch (default on, deny only): writes and shell commands that target the mod's own store file, its install or marketplace directory, `claude plugin disable|uninstall barmkin-mod`, `claude plugin marketplace remove emasoft-barmkin`, and edits of the barmkin-mod entries in the settings files.
6. Tests in the repo style; `claude plugin validate --strict` and `claude plugin test` with and without OPENROUTER_API_KEY.
7. README and version 0.3.0.

## Known limits (decided, not discovered)

- Every session of a user shares one `$.store`. A switch changed in another running session is, to this session, indistinguishable from an external edit: this session keeps its own values and writes them back when it next checks. A fresh session has no earlier hash, so a store edited while no session ran is accepted as it is.
- Self-protection reads the command text: a path assembled from pieces (a `cd` first, a variable, an encoding) is not recognised. The tamper check is the second line for the store file.
- Found in step 1, live check on Claude Code 2.1.314: Claude Code places a pane nobody asked for only at 144 columns or more ("waits unplaced (unasked below 144 columns ...)"), so in a narrower terminal the panel opens at session start only once widened or on /barmkin-mod-panel.
- Found in step 1: in an 80x30 terminal the 26-row list does not fit, so Up and Down scroll the pane; Tab moves from row to row and Enter flips the focused row. With the panel open there, the amber "switched off" line was not on screen; the bands of the other mods left the screen at the same moment, so the pane appears to take the band rows at that height (inferred, not settled).
- Found in step 1: the harness itself refuses a Skill tool call of /barmkin-mod-rule ("a built-in CLI command, not a skill"), so the origin check in the command is reached by a person or by a child session; a headless `claude -p "/barmkin-mod-rule ..."` arrives with origin sdk and is refused.
- Found in step 1: self-protection errs toward denying. Denied while it is on: rm or mv of any folder named .claude (a project one too), a shell command naming barmkin-mod and a settings file even to read it, a settings Write over a file larger than 4 MiB, and an MCP call whose input names a protected path. Not covered then: mv or rm of settings.json or installed_plugins.json without naming the plugin (covered since the review round: a shell write, move or removal of a Claude Code settings file is denied whatever it names), and a configuration folder not named .claude (partly covered since the review round: the store, the installed copy, the marketplace clone and the Claude-only file names are recognised in any folder; removing the folder, its plugins folder or the plugin cache, a find over it, and a shell write of its settings.json naming no protected key are not).
- Found in step 1: command replies show the plugin name twice ("barmkin-mod: barmkin-mod: ..."), because Claude Code prefixes the plugin name and the texts start with it too, as the 0.2.2 status and clear-taint texts already did. Cosmetic, left for a later card.
- Found in the step-1 review (round 2): within one process the switch fingerprint now lasts through /clear, /resume and /branch, but a new session, a `claude -p` child or a scheduled run takes the switch store as written. No mod-side fingerprint can close that: whatever the account can write on disk, a shell can write too. So a store edited through a call self-protection does not recognise takes effect in every later session.
- Found in the step-1 review (round 2): shell writes of settings files are recognised by their usual shapes (a redirection, tee, cp, mv, rm, dd, an in-place sed, perl or yq, an interpreter's inline code, find -exec, xargs). A script file that writes one, a write of a bare settings.json after a cd that names no settings key, and a find over the whole configuration folder that changes files without a name pattern are not recognised.
- Found in the step-1 review (round 2): an MCP write of a settings file is denied only when its input names the file with this plugin or its marketplace, or under .claude with a key that enables plugins or turns hooks off; a write that drops enabledPlugins without naming any of them is not recognised.
- Found in the step-1 review (round 2): a child session started with `claude --safe-mode -p` or `claude --bare -p` runs no installed mod; self-protection does not stop it (a permission rule that denies those commands can).
- Found in the step-1 review (round 2): which origin the Desktop app gives a command typed there is not measured (owner's Desktop check, box 4). Another plugin cannot rewrite the origin: the engine skips a hook that passes on an origin it did not set (measured with the test kit).
- Found in the step-1 review (round 2): a --plugin-dir copy is not protected by path, since its folder is the developer's working tree. An installed copy is protected under the marketplace its folder names and under emasoft-barmkin.

## Acceptance

- [x] Every existing gate checks its own switch; off skips only that check.
- [x] Switches persist in `$.store`; tamper check restores and notices.
- [x] Only composer or bridge origins change a switch from the command; the model cannot change one through the Skill tool or any other tool call.
- [ ] Panel lists every switch and toggles on click and Enter, on terminal and desktop, narrow and wide.
- [x] Self-protection denies the listed targets.
- [x] `claude plugin validate --strict` and `claude plugin test` pass with OPENROUTER_API_KEY unset and set to a placeholder.
- [x] README updated, version 0.3.0.

## Approval log

- 2026-10-30T02:42:43+0100 — MANDATE issued by main-agent@barmkin-mod (min-approval-requirement: none). Pre-approved: issuer authority >= required approver. No approval request was sent.
