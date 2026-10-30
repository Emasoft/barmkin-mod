---
trdd-id: ZY1XM7HX
title: Deterministic allow and deny rules for unattended sessions
column: todo
status: tasked
created: 2026-10-30T02:43:19+0100
updated: 2026-10-30T02:43:19+0100
current-owner: main-agent@barmkin-mod
created-by: main-agent@barmkin-mod
task-type: feature
min-approval-requirement: none
assignee: main-agent@barmkin-mod
mandate: true
mandated-by: none
approved: true
approval-judge: main-agent@barmkin-mod
approval-datetime: 2026-10-30T02:43:19+0100
release-via: none
---

# Deterministic allow and deny rules for unattended sessions

## Plan (step 2 of the continuity plan; card QAT87NRF is step 1)

Code rules, no Jev.

- Allow deletes whose every target in every segment is strictly inside /tmp, /private/tmp, /var/folders/*/*/T, $TMPDIR, ~/Library/Caches, ~/.cache, /var/tmp, %TEMP%, %LOCALAPPDATA%\Temp, or project node_modules, dist, build, target, __pycache__, .pytest_cache, .mypy_cache, .next, coverage (checked before the destructive tier; unresolvable targets never count).
- Always deny rm of /, ~, system folders, the project root, home depth 1-2, another git work tree, mkfs, dd onto a disk, force-push of the default branch in every form, gh repo/release delete, adding broad allow rules (Bash(*), *, bypassPermissions) or hooks keys in settings.
- git reset --hard and git clean -fd only when the owner typed that exact command.
- Code-approve pushes to remotes present at session start, gh on the own repo, installs of packages already in the lockfile, only when a secret scan finds nothing and no untrusted content was read.
- New packages and npx/uvx/bunx/pipx run go to Jev.
- Commands matching no class pass with no Jev call.
- Each rule group gets its own switch in the registry of card QAT87NRF.

## Approval log

- 2026-10-30T02:43:19+0100 — MANDATE issued by main-agent@barmkin-mod (min-approval-requirement: none). Pre-approved: issuer authority >= required approver. No approval request was sent.
