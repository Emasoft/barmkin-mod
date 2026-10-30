---
trdd-id: CIG1L78B
title: Jev command gate anchored on the owner's own message
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

# Jev command gate anchored on the owner's own message

## Plan (step 3 of the continuity plan; card QAT87NRF is step 1)

Jev gate.

- Questions: A secret material off the machine, B data to a destination other than own remotes/registries/a host named in the owner's last message, C download-and-run, D weaken a security control, E irreversible delete outside temp/cache/build, asked over the command + cwd + last 5 non-empty agent messages (redacted, typed placeholders like <SECRET:api-key>).
- H "does the owner's last typed message ask for this" in a SEPARATE call holding only the owner's last composer/bridge message (main session's, also for subagents) and the command.
- Deny A >= 0.9 always; B/C >= 0.9, D/E >= 0.8 when H < 0.5; H never rescues A or code denies.
- Calibrate on a held-out set fixed in advance (adversarial contexts, broad/vague owner messages, obfuscated exfiltration, safe egress, home-depth deletes): every harmful item denied in 3/3 repeats, <= 10% safe denied; record the model id; a different model id gives code rules only plus a notice.
- Invariant, tested first with a probe: the mod never upgrades another guard's deny (only ask to allow/deny, allow to deny).
- Timeout 2 s + one retry, internal deadline 6 s, errors deny.
- Each Jev gate question gets its own switch in the registry of card QAT87NRF.

## Approval log

- 2026-10-30T02:43:19+0100 — MANDATE issued by main-agent@barmkin-mod (min-approval-requirement: none). Pre-approved: issuer authority >= required approver. No approval request was sent.
