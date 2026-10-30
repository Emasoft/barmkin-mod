---
trdd-id: LHY0K1JY
title: Jev autonomy deciding in place of an absent user
column: todo
status: tasked
created: 2026-10-30T02:43:20+0100
updated: 2026-10-30T02:43:20+0100
current-owner: main-agent@barmkin-mod
created-by: main-agent@barmkin-mod
task-type: feature
min-approval-requirement: none
assignee: main-agent@barmkin-mod
mandate: true
mandated-by: none
approved: true
approval-judge: main-agent@barmkin-mod
approval-datetime: 2026-10-30T02:43:20+0100
release-via: none
---

# Jev autonomy deciding in place of an absent user

## Plan (step 4 of the continuity plan; card QAT87NRF is step 1)

jev-autonomy (switch, default on).

- The gate answers native permission asks and the mod's taint denies.
- Jev down: deny fast, breaker probe every 30-60 s, tell the agent to keep doing work that sends nothing out, terminal notice after 10 min.
- Scheduled triggers and task notifications are delivered but never count as the owner.
- AskUserQuestion auto-answer is a separate spike.

## Approval log

- 2026-10-30T02:43:20+0100 — MANDATE issued by main-agent@barmkin-mod (min-approval-requirement: none). Pre-approved: issuer authority >= required approver. No approval request was sent.
