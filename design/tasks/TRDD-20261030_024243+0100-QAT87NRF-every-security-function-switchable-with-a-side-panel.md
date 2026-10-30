---
trdd-id: QAT87NRF
title: Every security function switchable, with a side panel
column: dev
status: tasked
created: 2026-10-30T02:42:43+0100
updated: 2026-10-30T02:42:43+0100
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
---

# Every security function switchable, with a side panel

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

## Acceptance

- [ ] Every existing gate checks its own switch; off skips only that check.
- [ ] Switches persist in `$.store`; tamper check restores and notices.
- [ ] Only composer or bridge origins change a switch from the command; the model cannot change one through the Skill tool or any other tool call.
- [ ] Panel lists every switch and toggles on click and Enter, on terminal and desktop, narrow and wide.
- [ ] Self-protection denies the listed targets.
- [ ] `claude plugin validate --strict` and `claude plugin test` pass with OPENROUTER_API_KEY unset and set to a placeholder.
- [ ] README updated, version 0.3.0.

## Approval log

- 2026-10-30T02:42:43+0100 — MANDATE issued by main-agent@barmkin-mod (min-approval-requirement: none). Pre-approved: issuer authority >= required approver. No approval request was sent.
