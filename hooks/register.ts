// barmkin-mod: a Claude Code mods security layer. See README.md for the
// capability list and the posture this mod does and doesn't cover.
//
// Fail-closed convention: a hook that guards (can deny/consume/withhold)
// gets a `.catch` that denies on failure. A hook that's purely advisory
// (the HUD) has none, so the documented no-catch default applies: fail
// before `next()` skips the hook (the action proceeds without our
// annotation), fail after `next()` leaves the result as `next()` produced
// it. Neither path can loosen a decision someone else already made --
// these hooks only ever add a deny/consume/withhold on top, never an allow.
//
// `$` is only ever used as `$.namespace.method(...)` and only ever passed
// to a function declared at this file's top level (never into an imported
// file or a function nested inside a hook), per `claude plugin validate`'s
// static-analysis rules for the mods API.
import { atom, read, update } from 'claude-code'
import { REDACTION_RULES } from './lib/redaction-rules'
import {
  redactText,
  redactInEitherView as redactInEitherViewLib,
  classifierInput,
  WITHHELD_TEXT,
  containsAnySecret,
  containsSecretInEitherView,
  measureResult,
  exceedsScanLimit,
  exceedsScreenedLimit,
  SCREENED_LIMIT_REASON,
  PAGING_ADVICE,
} from './lib/redaction'
import { scannedPrefix, prefixNotice } from './lib/scanned-prefix'
import { scrubInvisible } from './lib/scrub'
import {
  composeScreen,
  isOutsideCwd,
  heuristicInjectionScore,
  parseTaintClearPosture,
  promptClearsTaintUnder,
  compactClearsTaint,
  sessionEndClearsTaint,
  commandMayClearTaint,
  classifierGapReason,
  credentialScoreReason,
  DEFAULT_TAINT_THRESHOLDS,
  describeTaintClear,
  describeTaintBanner,
  UNTRUSTED_CONTENT_WARNING,
  type HeldTaint,
  type ScoreSource,
  type ScreenOutcome,
  type TaintClearPosture,
} from './lib/taint'
import {
  classifyEgress,
  decideEgressWith,
  COMMAND_TOOLS,
  touchesSecretPath,
  isInlineSkillShell,
  inlineShellDenyReason,
  type EgressCall,
  type EgressVerdict,
  type TrifectaLegs,
} from './lib/egress'
import { planWindows, unclassifiedChars, mergeWindowScores, mergeWindowAnswers } from './lib/classifier-windows'
import {
  PRODUCTION_QUESTIONS,
  SHADOW_ARMS,
  shadowQuestions,
  type ShadowArm,
} from './lib/jev-questions'
import {
  buildSystemOneRequest,
  parseSystemOneResponse,
  JEV_MODEL_PATTERN,
  type NoulQuestion,
  type SystemOneParseResult,
} from './lib/system-one-client'
import { neutralizeDescription, parseMcpServerName, isAllowedServer } from './lib/mcp-guard'
import { extractResultText, appendContext, withholdResult } from './lib/tool-result'
import { meetsMinimumVersion, MIN_CLAUDE_CODE_VERSION } from './lib/version'
import { checkPosture } from './lib/posture'
import { skillBodyWithheldText, skillListingWithheldText, neutralizeSkillListing } from './lib/skill-guard'
import {
  SWITCH_DEFS,
  SWITCH_STORE_KEY,
  defaultSwitches,
  normalizeSwitches,
  toStoreValue,
  storeFingerprint,
  checkStore,
  parseRuleArgs,
  originMayChangeSwitches,
  originKindOf,
  describeSwitchList,
  describeSwitchChange,
  switchesOff,
  protectionsOff,
  egressClassEnabled,
  TAMPER_NOTICE,
  ACCEPT_NOTICE,
  type SwitchId,
  type SwitchMap,
} from './lib/switches'
import {
  shellSelfProtectionReason,
  fileSelfProtectionReason,
  isSettingsFile,
  writeChangesProtectedEntries,
  isSwitchCommandSkill,
  inputStrings,
  SETTINGS_WRITE_REASON,
  SWITCH_COMMAND_REASON,
  mcpSelfProtectionReason,
} from './lib/self-protection'

// ---------------------------------------------------------------------------
// $.state atoms. Declared values must match types/index.d.ts, and plugin/key
// must be string literals so `claude plugin validate` can read them.
// ---------------------------------------------------------------------------

interface Verdict {
  toolUseId: string
  question: string
  probability: number
  decision: 'pass' | 'escalate' | 'deny'
  model: string
  at: number
}

interface ShadowArmRecord {
  arm: string
  // Windows that answered, out of the windows asked.
  answered: number
  windows: number
  model: string | null
  // Each question's highest probability over the windows that answered.
  scores: Record<string, number>
}

interface ShadowRecord {
  toolUseId: string
  label: string
  arms: ShadowArmRecord[]
  at: number
}

interface EgressRecord {
  tool: string
  classIds: string[]
  decision: 'deny' | 'warn'
  rule: string
  at: number
}

const tainted = atom({ plugin: 'barmkin-mod', key: 'tainted' }, false)
const taintReason = atom({ plugin: 'barmkin-mod', key: 'taintReason' }, null as string | null)
// Set when the taint needs a person's /barmkin-mod-clear-taint (the classifier
// gap): holds why. A prompt, compaction or /clear leaves the taint standing
// while this is set; only the command clears it.
const taintAckReason = atom({ plugin: 'barmkin-mod', key: 'taintAckReason' }, null as string | null)
// Trifecta leg B (sensitive access); leg A is `tainted`, leg C is evaluated per call.
const sensitiveAccess = atom({ plugin: 'barmkin-mod', key: 'sensitiveAccess' }, false)
const sensitiveReason = atom({ plugin: 'barmkin-mod', key: 'sensitiveReason' }, null as string | null)
const lastEgress = atom({ plugin: 'barmkin-mod', key: 'lastEgress' }, null as EgressRecord | null)
const lastVerdict = atom({ plugin: 'barmkin-mod', key: 'lastVerdict' }, null as Verdict | null)
const breakerOpenUntil = atom({ plugin: 'barmkin-mod', key: 'breakerOpenUntil' }, 0)
const breakerFailureCount = atom({ plugin: 'barmkin-mod', key: 'breakerFailureCount' }, 0)
// The shadow screen's own breaker. A shadow failure never opens the classifier
// breaker above, so it can neither flip the HUD to degraded nor push the
// production screen back to the heuristics. The shadow screen is contrast
// instrumentation only (the captain wording's four questions, and
// destructive_command under the revised wording): never enforced, and the
// destructive question never taints anywhere.
const shadowBreakerOpenUntil = atom({ plugin: 'barmkin-mod', key: 'shadowBreakerOpenUntil' }, 0)
const shadowBreakerFailureCount = atom({ plugin: 'barmkin-mod', key: 'shadowBreakerFailureCount' }, 0)
// What the shadow screen answered for the last piece of content. Annotation
// only: nothing reads it to taint, withhold or gate.
const lastShadow = atom({ plugin: 'barmkin-mod', key: 'lastShadow' }, null as ShadowRecord | null)
// The security switches as this session last wrote or loaded them, the
// fingerprint of that store value (the tamper check), and the last switch
// notice. One source: every gate and the switch panel read `switches`; a null
// (not loaded yet, or reset by /clear, /resume, /branch) reads as all on.
const switchesAtom = atom({ plugin: 'barmkin-mod', key: 'switches' }, null as Record<string, boolean> | null)
const switchesHashAtom = atom({ plugin: 'barmkin-mod', key: 'switchesHash' }, null as string | null)
const switchesNoticeAtom = atom({ plugin: 'barmkin-mod', key: 'switchesNotice' }, null as string | null)

// Redaction placeholder counters. Not security state (no secret value is
// ever kept, only a per-category count for unique labels), so a plain
// module variable is fine; it resets on reload like any other.
const redactionCounters: Record<string, number> = {}

const BREAKER_FAILURE_THRESHOLD = 3
const BREAKER_COOLDOWN_MS = 60_000
const JEV_TIMEOUT_MS = 700
// More than this many invisible-text carriers (scrubInvisible's
// `hiddenCount`, which leaves out ANSI/C0 terminal formatting and the
// ZWNJ/ZWJ of ordinary Persian/Indic text and ZWJ emoji) stripped from one
// piece of content taints the session: a payload smuggled one invisible code
// point per byte runs well past this.
const INVISIBLE_CHAR_TAINT_THRESHOLD = 32
// This plugin's own manifest name, as it appears before the `@marketplace`
// suffix in a managed prependPlugins entry (the session.start posture check).
const PLUGIN_NAME = 'barmkin-mod'

let pluginOptions: Record<string, unknown> = {}

// ---------------------------------------------------------------------------
// Jev System One client. Provider-neutral: base_url is always operator
// config pointing at an OpenRouter- or Vercel-AI-Gateway-style endpoint
// that speaks the same /v1/systemone wire format as barmkin's jev.go.
// Never barmkin's internal gateway. Jev only ever tightens a verdict
// (pass -> escalate -> deny); see composeScreen in lib/taint.ts.
// ---------------------------------------------------------------------------

interface JevOptions {
  baseUrl: string
  model: string
  apiKey: string
}

// The OpenRouter key comes ONLY from the OPENROUTER_API_KEY environment variable,
// read where it is used (each screen and each HUD render), never from a plugin
// option. Why not once at session start: session.start alone would set it, so a
// screen that runs without that event would silently see no key. The literal
// name is required: the mods analyser refuses a variable.
async function readOpenRouterKey($: any): Promise<string> {
  const key = await $.env.get('OPENROUTER_API_KEY')
  return typeof key === 'string' ? key : ''
}

// The defaults send Jev to OpenRouter, whose ~typesafe/jev-latest alias follows the
// newest Jev 1.x. Why the key is a parameter: it is read from the environment only
// (readOpenRouterKey), so an empty key means Jev is not configured.
function getJevOptions(options: Record<string, unknown>, apiKey: string): JevOptions {
  const rawBase = typeof options.jev_base_url === 'string' ? options.jev_base_url.trim() : ''
  return {
    baseUrl: (rawBase || 'https://openrouter.ai/api').replace(/\/+$/, ''),
    model: typeof options.jev_model === 'string' && options.jev_model ? options.jev_model : '~typesafe/jev-latest',
    apiKey,
  }
}

// Jev counts as configured only with a key: without one every request would fail
// with 401, so a missing OPENROUTER_API_KEY must read as not configured here.
function jevConfigured(jev: JevOptions): boolean {
  return jev.apiKey !== ''
}

function parseAllowlist(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((v): v is string => typeof v === 'string' && v.length > 0)
  if (typeof raw === 'string' && raw.length > 0) {
    return raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  }
  return []
}

// Top-level so it may receive `$` directly (validator rule). `text` is one
// window of the redacted payload (classifierInput, then planWindows), so no
// secret leaves for the third-party endpoint. Never throws: every failure path
// returns { ok: false, reason }, which screenContent treats as "classifier
// unavailable" for that window -- never as a pass. `$.http.fetch` takes no abort
// signal, so the timeout races the request instead of cancelling it; a late
// answer is dropped.
async function callJevSystemOne(
  $: any,
  jev: JevOptions,
  text: string,
  questions: Record<string, NoulQuestion>,
): Promise<SystemOneParseResult> {
  let timer: { cancel: () => void } | null = null
  const timeout = new Promise<SystemOneParseResult>((resolve) => {
    try {
      timer = $.clock.after(JEV_TIMEOUT_MS, () => resolve({ ok: false, reason: 'timeout' }))
    } catch {
      // A host that refuses timers degrades to an untimed call.
    }
  })
  try {
    return await Promise.race([requestJevSystemOne($, jev, text, questions), timeout])
  } finally {
    timer?.cancel()
  }
}

async function requestJevSystemOne(
  $: any,
  jev: JevOptions,
  text: string,
  questions: Record<string, NoulQuestion>,
): Promise<SystemOneParseResult> {
  const body = buildSystemOneRequest(jev.model, { content: text }, questions)
  try {
    const response = await $.http.fetch(jev.baseUrl + '/v1/systemone', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(jev.apiKey ? { Authorization: 'Bearer ' + jev.apiKey } : {}),
      },
      body: JSON.stringify(body),
    })
    if (!response.ok) {
      return { ok: false, reason: 'http_' + response.status }
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(response.text)
    } catch {
      return { ok: false, reason: 'malformed_response: not JSON' }
    }
    return parseSystemOneResponse(parsed, Object.keys(questions), JEV_MODEL_PATTERN)
  } catch (error) {
    return { ok: false, reason: 'network: ' + String(error) }
  }
}

// A failure worth one more try: the endpoint was slow, unreachable, rate
// limited or erroring. A malformed or refused answer would fail the same way.
function isTransient(reason: string): boolean {
  return reason === 'timeout' || reason.startsWith('network') || reason === 'http_429' || /^http_5\d\d$/.test(reason)
}

// Asks every window at once, then once more for each window that failed for a
// transient reason. The calls' time is outside the hook's budget, and each is
// bounded by JEV_TIMEOUT_MS, so the screen waits at most twice that.
async function classifyWindows(
  $: any,
  jev: JevOptions,
  text: string,
  windows: { start: number; end: number }[],
): Promise<SystemOneParseResult[]> {
  const calls: Promise<SystemOneParseResult>[] = []
  for (const w of windows) calls.push(callJevSystemOne($, jev, text.slice(w.start, w.end), PRODUCTION_QUESTIONS))
  const results = await Promise.all(calls)
  const retries: Promise<void>[] = []
  results.forEach((r, i) => {
    if (r.ok || !isTransient(r.reason)) return
    retries.push(retryWindow($, jev, text.slice(windows[i].start, windows[i].end), results, i))
  })
  await Promise.all(retries)
  return results
}

async function retryWindow(
  $: any,
  jev: JevOptions,
  text: string,
  results: SystemOneParseResult[],
  i: number,
): Promise<void> {
  results[i] = await callJevSystemOne($, jev, text, PRODUCTION_QUESTIONS)
}

// The shadow screen: every window, once per wording arm (the captain wording's
// four questions; the revised wording's destructive_command), in parallel with
// the production calls and bounded by the same timeout. Contrast data only,
// never enforced. No retry: a shadow answer is never worth a second request.
// Results are indexed by arm, then by window.
async function classifyShadowWindows(
  $: any,
  jev: JevOptions,
  text: string,
  windows: { start: number; end: number }[],
): Promise<SystemOneParseResult[][]> {
  return Promise.all(
    SHADOW_ARMS.map((arm) =>
      Promise.all(windows.map((w) => callJevSystemOne($, jev, text.slice(w.start, w.end), shadowQuestions(arm)))),
    ),
  )
}

function redactInEitherView(text: string): { text: string; redactedCount: number } {
  return redactInEitherViewLib(text, REDACTION_RULES, redactionCounters)
}

// ---------------------------------------------------------------------------
// Security switches (hooks/lib/switches.ts). $.state holds the switches this
// session uses; $.store keeps them between sessions. Gates read $.state only,
// so a gate never waits on the store, and a store edit reaches a running
// session only through the tamper check below.
// ---------------------------------------------------------------------------

// The switches every gate reads. A null ($.state not loaded yet, or reset by
// /clear, /resume or /branch) reads as all on: the behaviour the mod had before
// switches existed, so a missing load can only leave a protection running.
async function readSwitches($: any): Promise<SwitchMap> {
  const held = await read($, switchesAtom)
  return held === null ? defaultSwitches() : normalizeSwitches({ switches: held })
}

let switchWrites: Promise<unknown> = Promise.resolve()

// Switch reads of the store and switch writes run one at a time, so a panel
// press and a command cannot interleave between the tamper check and the write.
function serializeSwitchWrite<T>(write: () => Promise<T>): Promise<T> {
  const run = switchWrites.then(write)
  switchWrites = run.catch(() => {})
  return run
}

// Shows a switch notice in the transcript, as a toast, and at the top of the panel.
async function noteSwitches($: any, text: string): Promise<void> {
  await update($, switchesNoticeAtom, () => text)
  try {
    $.ui.log(text)
  } catch {
    // no log surface; the panel still shows the notice
  }
  try {
    $.ui.toast(text)
  } catch {
    // no toast surface (headless); the log line stands
  }
}

// The tamper check over one read of the store (checkStore in switches.ts), with
// its outcome written: a restore puts this session's last known value back into
// the store, and every outcome but 'unchanged' records the map and fingerprint
// in $.state. Returns the switches this session now uses. Runs at session start,
// after /clear, /resume and /branch, before every switch write, and on
// /barmkin-mod-rule and /barmkin-mod-panel; never inside a gate.
async function checkSwitchStoreNow($: any): Promise<SwitchMap> {
  const stored = await $.store.get(SWITCH_STORE_KEY)
  const held = await read($, switchesAtom)
  const known = held === null ? null : normalizeSwitches({ switches: held })
  const check = checkStore(known, await read($, switchesHashAtom), stored)
  if (check.kind === 'restore') await $.store.set(SWITCH_STORE_KEY, check.storeValue)
  if (check.kind !== 'unchanged') {
    await update($, switchesAtom, () => check.map)
    await update($, switchesHashAtom, () => check.hash)
  }
  if (check.kind === 'restore') await noteSwitches($, TAMPER_NOTICE)
  if (check.kind === 'accept') await noteSwitches($, ACCEPT_NOTICE)
  return check.map
}

function checkSwitchStore($: any): Promise<SwitchMap> {
  return serializeSwitchWrite(() => checkSwitchStoreNow($))
}

// Sets one switch (or flips it, for a panel press) and saves the whole map. The
// tamper check runs first, so a store someone else edited is never the base the
// change is built on; the new value is this session's map with one switch changed.
function setSwitch($: any, id: SwitchId, on: boolean | 'toggle'): Promise<SwitchMap> {
  return serializeSwitchWrite(async () => {
    const current = await checkSwitchStoreNow($)
    const changed: SwitchMap = { ...current, [id]: on === 'toggle' ? !current[id] : on }
    const value = toStoreValue(changed)
    await $.store.set(SWITCH_STORE_KEY, value)
    await update($, switchesAtom, () => changed)
    await update($, switchesHashAtom, () => storeFingerprint(value))
    return changed
  })
}

let taintWrites: Promise<unknown> = Promise.resolve()

// Taint writes run one at a time, in call order, so a fire-and-forget scrub
// cannot interleave with another write or land after a prompt.submit reset.
function serializeTaintWrite<T>(write: () => Promise<T>): Promise<T> {
  const run = taintWrites.then(write)
  taintWrites = run.catch(() => {})
  return run
}

function markTainted($: any, reason: string): Promise<void> {
  return serializeTaintWrite(async () => {
    // The taint switch off: nothing marks the session tainted.
    if (!(await readSwitches($)).taint) return
    await update($, tainted, () => true)
    await update($, taintReason, (current: string | null) => current ?? reason)
  })
}

// Taints the session and records that only a person's /barmkin-mod-clear-taint
// clears it. The first acknowledgement reason recorded for a session wins.
function markTaintedNeedingAck($: any, reason: string, ackReason: string): Promise<void> {
  return serializeTaintWrite(async () => {
    if (!(await readSwitches($)).taint) return
    await update($, tainted, () => true)
    await update($, taintReason, (current: string | null) => current ?? reason)
    await update($, taintAckReason, (current: string | null) => current ?? ackReason)
  })
}

// What a denied call tells Claude about getting unblocked.
function askAgainHint(ackReason: string | null): string {
  return ackReason === null
    ? 'Ask again after a new message.'
    : 'Ask the user to run /barmkin-mod-clear-taint to acknowledge it; a new message does not clear this taint.'
}

// The taint as every gate sees it. With the taint switch off a held taint
// reads as clear, so no gate acts on it; /barmkin-mod-status and
// /barmkin-mod-clear-taint read the held values through readHeldTaint.
async function readTaint($: any): Promise<{ tainted: boolean; reason: string | null; ackReason: string | null }> {
  const held = await readHeldTaint($)
  if ((await readSwitches($)).taint) return held
  return { tainted: false, reason: null, ackReason: null }
}

async function readHeldTaint($: any): Promise<{ tainted: boolean; reason: string | null; ackReason: string | null }> {
  await taintWrites
  return { tainted: await read($, tainted), reason: await read($, taintReason), ackReason: await read($, taintAckReason) }
}

// Clears both legs (taint and sensitive access) in one queued write and
// returns what they held. Every clearing path goes through here: a human
// prompt in human-origin posture, a compaction or /clear in sticky posture,
// and /barmkin-mod-clear-taint in either. Only the command is an explicit
// acknowledgement (`acknowledge`): while a taint requires one, every other
// path leaves both legs held and returns null.
function clearTaintLegs($: any, acknowledge: boolean): Promise<HeldTaint | null> {
  return serializeTaintWrite(async () => {
    const ackReason = await read($, taintAckReason)
    if (ackReason !== null && !acknowledge) return null
    const held: HeldTaint = {
      tainted: await read($, tainted),
      taintReason: await read($, taintReason),
      sensitive: await read($, sensitiveAccess),
      sensitiveReason: await read($, sensitiveReason),
      ackReason,
    }
    await update($, tainted, () => false)
    await update($, taintReason, () => null)
    await update($, taintAckReason, () => null)
    await update($, sensitiveAccess, () => false)
    await update($, sensitiveReason, () => null)
    return held
  })
}

function taintClearPosture(): TaintClearPosture {
  return parseTaintClearPosture(pluginOptions.taint_clear)
}

// Leg B of the trifecta. Written through the same queue as the taint so a
// human prompt's reset cannot interleave with it. The first reason recorded
// for a session wins, as it does for the taint.
function markSensitive($: any, reason: string): Promise<void> {
  return serializeTaintWrite(async () => {
    await update($, sensitiveAccess, () => true)
    await update($, sensitiveReason, (current: string | null) => current ?? reason)
  })
}

async function readLegs($: any): Promise<TrifectaLegs> {
  const { tainted: untrusted, reason: untrustedReason, ackReason } = await readTaint($)
  return {
    untrusted,
    untrustedReason,
    sensitive: await read($, sensitiveAccess),
    sensitiveReason: await read($, sensitiveReason),
    ackRequired: ackReason !== null,
  }
}

// Marks leg B when a call names a secret-bearing path.
async function noteSensitiveAccess($: any, call: EgressCall): Promise<void> {
  if (touchesSecretPath(call)) await markSensitive($, 'a ' + call.tool + ' call named a credential path')
}

// The egress gate for one call: notes any sensitive access in it, classifies
// it against the egress classes, and decides over the trifecta legs. A deny or
// warn is recorded for the status surface. Never answers allow.
async function egressGate($: any, call: EgressCall): Promise<EgressVerdict> {
  await noteSensitiveAccess($, call)
  const sw = await readSwitches($)
  // A class whose switch is off is not checked, and an escalation whose switch
  // is off is decided as if its leg were not held: off drops a check, it never
  // answers allow, so another guard's deny still stands.
  const classes = classifyEgress(call).filter((c) => egressClassEnabled(c.id, sw))
  const verdict = decideEgressWith(classes, await readLegs($), {
    taintBlocksEgress: sw['taint-blocks-egress'],
    ruleOfTwo: sw['rule-of-two'],
  })
  if (verdict.kind !== 'pass') {
    await update($, lastEgress, () => ({
      tool: call.tool,
      classIds: verdict.classIds,
      decision: verdict.kind,
      rule: verdict.kind === 'deny' ? verdict.rule : 'untrusted',
      at: Date.now(),
    }))
  }
  return verdict
}

// Checks and reserves the taint in one queued write, so two Skill calls
// dispatched together cannot both see an untainted session. Returns the
// standing reason when the session is already tainted (the load is denied),
// or null once this load holds the reservation. The reservation is not released
// when the load fails, so a failed or denied load leaves the session tainted.
function reserveSkillLoad(
  $: any,
  loadReason: string,
): Promise<{ standingReason: string | null; ackReason: string | null } | null> {
  return serializeTaintWrite(async () => {
    let wasTainted = false
    await update($, tainted, (current: boolean) => {
      wasTainted = current
      return true
    })
    if (wasTainted) return { standingReason: await read($, taintReason), ackReason: await read($, taintAckReason) }
    await update($, taintReason, () => loadReason)
    return null
  })
}

// Shared by every scrubInvisible call site (the outermost redaction pass, tool.describe,
// and session.receive): taints the session when a scrub stripped more than
// INVISIBLE_CHAR_TAINT_THRESHOLD characters.
// The first reason recorded for a session wins, so a later taint never
// replaces the evidence the deny message and the verdict already show.
async function taintForScrub($: any, hiddenCount: number, source: string): Promise<void> {
  if (hiddenCount <= INVISIBLE_CHAR_TAINT_THRESHOLD) return
  try {
    await markTainted($, 'stripped ' + hiddenCount + ' invisible character(s) from ' + source)
  } catch {
    $.ui.log('barmkin-mod: could not record taint for ' + source + ' (' + hiddenCount + ' invisible character(s) stripped)')
  }
}

async function recordBreakerFailure($: any): Promise<void> {
  // update() retries on a version miss, so failures from screens running in
  // parallel are each counted.
  const failures = await update($, breakerFailureCount, (n: number) => n + 1)
  if (failures >= BREAKER_FAILURE_THRESHOLD) {
    await update($, breakerOpenUntil, () => Date.now() + BREAKER_COOLDOWN_MS)
  }
}

// Records what the shadow screen answered and counts one shadow breaker event
// for the whole screen. Returns the human-surface note for answers worth
// reading (a score at or above the taint line on any question), or null.
// Annotation only: nothing here taints, withholds or marks a leg, and a failure
// here must never reach the production screen, so the caller catches.
async function recordShadow(
  $: any,
  label: string,
  toolUseId: string | undefined,
  results: SystemOneParseResult[][],
): Promise<string | null> {
  const arms: ShadowArmRecord[] = SHADOW_ARMS.map((arm: ShadowArm, i: number) => {
    const merged = mergeWindowAnswers(results[i], Object.keys(shadowQuestions(arm)))
    return {
      arm,
      answered: merged === null ? 0 : merged.answered,
      windows: results[i].length,
      model: merged === null ? null : merged.model,
      scores: merged === null ? {} : merged.answers,
    }
  })
  const allAnswered = results.every((armResults) => armResults.every((r) => r.ok))
  if (allAnswered) {
    await update($, shadowBreakerFailureCount, () => 0)
  } else {
    const failures = await update($, shadowBreakerFailureCount, (n: number) => n + 1)
    if (failures >= BREAKER_FAILURE_THRESHOLD) {
      await update($, shadowBreakerOpenUntil, () => Date.now() + BREAKER_COOLDOWN_MS)
    }
  }
  await update($, lastShadow, () => ({ toolUseId: toolUseId ?? '', label, arms, at: Date.now() }))
  $.ui.log('barmkin-mod: shadow screen for ' + label + ': ' + arms.map(describeShadowArm).join(' | '), { to: 'debug' })
  const flagged: string[] = []
  for (const record of arms) {
    for (const [id, p] of Object.entries(record.scores)) {
      if (p >= DEFAULT_TAINT_THRESHOLDS.taintAt) flagged.push(record.arm + ' ' + id + ' ' + p.toFixed(2))
    }
  }
  return flagged.length > 0 ? 'shadow, not enforced: ' + flagged.join(', ') : null
}

function describeShadowArm(record: ShadowArmRecord): string {
  const windows = record.answered + '/' + record.windows + ' windows'
  if (record.answered === 0) return '[' + record.arm + '] no window answered (' + windows + ')'
  return (
    '[' + record.arm + '] ' + windows + ': ' + Object.entries(record.scores).map(([id, p]) => id + '=' + p.toFixed(2)).join(' ')
  )
}

// The screen's outcome with the exfiltration question folded in. composeScreen
// knows injection and credentials only; exfiltration joins the real verdict
// here, on the same taintAt line, and can only raise it.
type ScreenResult = Omit<ScreenOutcome, 'question' | 'scores'> & {
  question: ScreenOutcome['question'] | 'exfiltration'
  scores: ScreenOutcome['scores'] & { exfiltration: number }
}

// Taints on an exfiltration score at or above taintAt, as the injection and
// credentials questions do. Raise-only: an outcome already tainted keeps its
// driving question and reason (the first evidence wins), a pass becomes an
// escalate, and exfiltration alone never withholds. Jev is its only source: no
// local heuristic exists for it.
function withExfiltration(screened: ScreenOutcome, exfiltration: number, jevModel: string | null): ScreenResult {
  const scores = { ...screened.scores, exfiltration }
  if (screened.tainted || jevModel === null || exfiltration < DEFAULT_TAINT_THRESHOLDS.taintAt) return { ...screened, scores }
  return {
    ...screened,
    decision: 'escalate',
    tainted: true,
    reason: `content scored ${exfiltration.toFixed(2)} on the data-exfiltration question (>= ${DEFAULT_TAINT_THRESHOLDS.taintAt})`,
    question: 'exfiltration',
    probability: exfiltration,
    model: jevModel,
    scores,
    withholdReason: 'the exfiltration screen flagged it',
  }
}

// Screens one piece of untrusted content (a fetched page, an MCP result, a
// file read from outside cwd, an inbound peer message) and, as a side
// effect, updates the taint and explanation-surface state. Top-level so it
// can receive `$` directly.
async function screenContent(
  $: any,
  text: string,
  label: string,
  toolUseId: string | undefined,
): Promise<ScreenResult> {
  const raw = text
  if (exceedsScreenedLimit(raw)) {
    return {
      decision: 'deny',
      tainted: false,
      reason: SCREENED_LIMIT_REASON,
      question: 'injection',
      probability: 0,
      model: 'heuristic',
      scores: { injection: 0, exfiltration: 0, credentials: 0 },
      withholdReason: SCREENED_LIMIT_REASON,
    }
  }
  text = scrubInvisible(raw).text
  const jev = getJevOptions(pluginOptions, await readOpenRouterKey($))
  const now = Date.now()
  const breakerUntil = await read($, breakerOpenUntil)
  const sw = await readSwitches($)
  // The jev-screening switch off: no classifier request is sent, and the screen
  // runs as if Jev were not configured (local heuristics only).
  const jevOn = jevConfigured(jev) && sw['jev-screening']
  const canUseJev = jevOn && breakerUntil <= now

  const local: ScoreSource = {
    model: 'heuristic',
    // The heuristic-only-taint switch off: only a Jev score counts on the injection question.
    injection: sw['heuristic-only-taint'] ? heuristicInjectionScore(text) : 0,
    credentials: containsSecretInEitherView(raw, REDACTION_RULES) ? 0.9 : 0,
  }

  // What the classifier would be sent, cut into its windows. Computed whenever
  // Jev is configured and switched on (even with the breaker open) to tell how much of the
  // content was classified.
  const jevInput = jevOn ? classifierInput(raw, REDACTION_RULES, redactionCounters) : null
  const plan = jevInput === null ? null : planWindows(jevInput)
  let results: (SystemOneParseResult | null)[] = plan ? plan.windows.map(() => null) : []
  let shadowNote: string | null = null

  if (canUseJev && plan && jevInput !== null) {
    // The shadow screen (contrast instrumentation: the captain wording, and
    // destructive_command under the revised wording) asks the same windows its
    // own questions, in parallel with the production calls, so it adds no wall
    // time. Its own breaker gates it, and nothing it returns reaches the
    // decision below.
    // Skipped while its breaker is open, and always with the shadow-screen switch off.
    const skipShadow = !sw['shadow-screen'] || (await read($, shadowBreakerOpenUntil)) > now
    const [production, shadow] = await Promise.all([
      classifyWindows($, jev, jevInput, plan.windows),
      skipShadow ? Promise.resolve(null) : classifyShadowWindows($, jev, jevInput, plan.windows),
    ])
    results = production
    // One breaker event per screen, however many windows it took.
    if (results.every((r) => r?.ok)) await update($, breakerFailureCount, () => 0)
    else await recordBreakerFailure($)
    if (shadow !== null) {
      try {
        shadowNote = await recordShadow($, label, toolUseId, shadow)
      } catch {
        // The shadow screen is annotation only; it never fails the real one.
      }
    }
  }

  // The production screen's three questions. Injection and credentials compose
  // with the local scores (Jev only raises); exfiltration is Jev's alone and is
  // folded in on top, so all three taint on the same per-question taintAt.
  const jevScores = mergeWindowScores(results)
  const screened = withExfiltration(composeScreen(local, jevScores), jevScores?.exfiltration ?? 0, jevScores?.model ?? null)
  // A withheld (deny) result never reaches Claude, so only content that does
  // is held to what the classifier read.
  const unclassified =
    plan && jevInput !== null ? unclassifiedChars(jevInput.length, plan.windows, results.map((r) => r?.ok === true)) : 0
  const gap =
    screened.decision === 'deny' ? null : classifierGapReason(jevOn, jevInput === null ? null : jevInput.length, unclassified)
  const composed: ScreenResult = gap
    ? { ...screened, tainted: true, decision: 'escalate', reason: screened.tainted ? screened.reason : gap }
    : screened

  await update($, lastVerdict, () => ({
    toolUseId: toolUseId ?? '',
    question: label + ' (' + composed.question + ')',
    probability: composed.probability,
    decision: composed.decision,
    model: composed.model,
    at: now,
  }))

  // The classifier-gap-needs-ack switch off: a gap taints like any screen hit,
  // and a message clears it.
  if (gap && sw['classifier-gap-needs-ack']) await markTaintedNeedingAck($, composed.reason, gap)
  else if (composed.tainted) await markTainted($, composed.reason)
  // Leg B follows the credentials score itself, not the question that drove the
  // decision: content that scores on injection and on credentials leaks the
  // secret all the same.
  if (screened.scores.credentials >= DEFAULT_TAINT_THRESHOLDS.taintAt) {
    await markSensitive($, credentialScoreReason(screened.scores.credentials))
  }

  if (toolUseId) {
    try {
      // $.ui.notice's exact id field on a tool.call event is unverified
      // against this build's generated types (see README's Phase 0
      // checklist); never let a signature mismatch break the screen.
      $.ui.notice(
        toolUseId,
        'barmkin-mod: ' + composed.model + ' scored this ' + composed.decision + ' (' + composed.reason + ')' + (shadowNote ? '; ' + shadowNote : ''),
      )
    } catch {
      // best-effort annotation only
    }
  }

  return composed
}

// ---------------------------------------------------------------------------
// session.start: load the switches, posture check, open the switch panel, register commands.
// ---------------------------------------------------------------------------

async function sessionStartHook($: any, e: any, next: any) {
  // The switches load first, so every gate reads them from here on. A store
  // that cannot be read leaves $.state null, which every gate reads as all on.
  let sw = defaultSwitches()
  try {
    sw = await checkSwitchStore($)
  } catch {
    logLine($, 'barmkin-mod: could not read the switch store, so every switch is on for this session')
  }
  // A switch turned off in an earlier session, or in the store file between
  // sessions, is named here, so it never goes unseen.
  const off = switchesOff(sw)
  if (off.length > 0) logLine($, 'barmkin-mod: these switches are off: ' + off.join(', ') + ' (/barmkin-mod-panel to change them)')

  if (sw['posture-check']) {
    for (const line of await postureLines($)) logLine($, line)
  }

  // The switch panel opens unasked and without focus, so it never takes the
  // person's keystrokes; the surface places it only where there is room (a
  // wide terminal, or the Desktop app) and keeps it waiting otherwise.
  try {
    await $.ui.open({ id: SWITCH_PANE_ID, title: SWITCH_PANE_TITLE, rows: SWITCH_PANE_ROWS })
  } catch {
    // no pane surface (headless); /barmkin-mod-rule still lists and sets switches
  }

  // Commands register last, each on its own, so one name collision costs only
  // that command. Literal calls, so the validator sees which commands are ours.
  try {
    await $.command.register({ name: 'barmkin-mod-status', description: 'Show barmkin-mod taint, breaker, and last classifier verdict' })
  } catch {
    // the name collided with another plugin's command; the mod still works
  }
  try {
    await $.command.register({
      name: 'barmkin-mod-clear-taint',
      description: 'Clear the barmkin-mod taint and sensitive-access flags and re-enable egress',
    })
  } catch {
    // as above
  }
  try {
    await $.command.register({
      name: 'barmkin-mod-rule',
      description: 'List the barmkin-mod security switches, or turn one on or off',
      argumentHint: '[list | <id> on|off]',
      immediate: true,
    })
  } catch {
    // as above
  }
  try {
    await $.command.register({ name: 'barmkin-mod-panel', description: 'Open the barmkin-mod security switch panel', immediate: true })
  } catch {
    // as above
  }
  return next(e)
}

// $.ui.status holds one line per plugin and draws a newline as U+FFFD, so each
// line is its own transcript row via $.ui.log.
function logLine($: any, line: string): void {
  try {
    $.ui.log(line)
  } catch {
    // no log surface on this build
  }
}

// The posture-check switch's lines: the Claude Code version and checkPosture's warnings.
async function postureLines($: any): Promise<string[]> {
  const statusLines: string[] = []
  try {
    const version = await $.session.version()
    if (typeof version === 'string' && !meetsMinimumVersion(version)) {
      statusLines.push(
        'barmkin-mod needs Claude Code >= ' + MIN_CLAUDE_CODE_VERSION + ' (running ' + version + '); some protections may not apply',
      )
    }
  } catch {
    // $.session.version() unavailable on this build; nothing to warn about
  }

  let merged: Record<string, unknown> | null = null
  try {
    merged = await $.settings.read()
  } catch {
    // $.settings.read() unavailable or refused on this build; checkPosture reports it as unverified
  }
  if (typeof merged !== 'object') merged = null
  let policy: Record<string, unknown> | null = null
  try {
    policy = await $.settings.read({ source: 'policy' })
  } catch {
    // the policy source refused or unavailable; checkPosture reports seating as unverified
  }
  if (typeof policy !== 'object') policy = null
  const mcpAllowlist = parseAllowlist(pluginOptions.mcp_server_allowlist)
  for (const warning of checkPosture({ merged, policy }, PLUGIN_NAME, mcpAllowlist)) {
    statusLines.push('barmkin-mod posture: ' + warning)
  }
  return statusLines
}

const SWITCH_PANE_ID = 'barmkin-mod-switches'
const SWITCH_PANE_TITLE = 'Barmkin switches'
// One row per switch plus the header and notice rows, so the whole list fits
// and Up and Down move between switches instead of scrolling.
const SWITCH_PANE_ROWS = SWITCH_DEFS.length + 4

// ---------------------------------------------------------------------------
// prompt.submit: redact secrets the user pasted, clear taint when a human sent it.
// ---------------------------------------------------------------------------

async function promptSubmitHook($: any, e: any, next: any) {
  // In human-origin posture only a person's prompt clears the taint and the
  // sensitive-access leg: the composer or the bridge, plus an SDK prompt when
  // the headless-lane option is on. In sticky posture no prompt clears them.
  if (promptClearsTaintUnder(taintClearPosture(), e.origin, pluginOptions.sdk_prompts_clear_taint === true)) {
    await clearTaintLegs($, false)
  }

  if (typeof e.text !== 'string') return next(e)
  if (!(await readSwitches($)).redaction) return next(e)
  if (exceedsScreenedLimit(e.text)) {
    return { drop: 'barmkin-mod: your message is longer than the 16 KiB scan limit, so it was withheld' }
  }
  // Detection runs on the scrubbed view; the original text is forwarded unless a secret is redacted.
  const { text, redactedCount } = redactInEitherView(e.text)
  if (redactedCount === 0) return next(e)
  if (text === WITHHELD_TEXT) {
    return { drop: 'barmkin-mod: your message could not be fully scanned after redaction, so it was withheld' }
  }
  $.ui.log('barmkin-mod: redacted ' + redactedCount + ' likely secret(s) from your message before sending it')
  return next({ ...e, text })
}

// ---------------------------------------------------------------------------
// Sticky taint: the events that break the context the taint guards. Both only
// clear in sticky posture, and both only ever clear after the event stood, so
// a hook that fails leaves the taint held.
// ---------------------------------------------------------------------------

async function compactHook($: any, e: any, next: any) {
  const result = await next(e)
  if (taintClearPosture() === 'sticky' && compactClearsTaint(e.trigger, e.agentId, result)) await clearTaintLegs($, false)
  return result
}

async function sessionEndHook($: any, e: any, next: any) {
  if (taintClearPosture() === 'sticky' && sessionEndClearsTaint(e.reason)) await clearTaintLegs($, false)
  return next(e)
}

// ---------------------------------------------------------------------------
// MCP tool-poisoning guard: harden descriptions, per-server allowlist.
// ---------------------------------------------------------------------------

async function toolDescribeHook($: any, e: any, next: any) {
  if (!(await readSwitches($))['mcp-guard']) return next(e)
  const current = await next(e)
  const description = typeof current?.description === 'string' ? current.description : e.description
  if (typeof description !== 'string') return current

  const scrubbed = scrubInvisible(description)
  void taintForScrub($, scrubbed.hiddenCount, 'an MCP tool description')

  const { description: cleaned, flagged } = neutralizeDescription(scrubbed.text)
  if (!flagged) {
    return scrubbed.text === description ? current : { ...current, description: scrubbed.text }
  }
  $.ui.log('barmkin-mod: flagged instruction-like text in a tool description (' + e.tool + ')', { to: 'debug' })
  if (cleaned === description) return current
  return { ...current, description: cleaned }
}

// What a withheld untrusted result tells Claude. A withhold for size alone is
// not a danger, so it points to paging; any other reason sends Claude back to
// the person.
function withheldMessage(what: string, reason: string): string {
  return 'barmkin-mod: withheld ' + what + ' (' + reason + '). ' + (reason === SCREENED_LIMIT_REASON ? PAGING_ADVICE : 'Ask the user before retrying.')
}

async function mcpGuardHook($: any, e: any, next: any) {
  const serverName = parseMcpServerName(e.tool)
  // The mcp-guard switch off: no allowlist and no result screen. The egress
  // gate still runs, under its own switches.
  const guard = (await readSwitches($))['mcp-guard']
  if (guard && serverName) {
    const allowlist = parseAllowlist(pluginOptions.mcp_server_allowlist)
    if (!isAllowedServer(serverName, allowlist)) {
      return { deny: 'barmkin-mod: MCP server "' + serverName + '" is not on the allowlist' }
    }
  }

  const egress = await egressGate($, { tool: e.tool, input: e })
  if (egress.kind === 'deny') return { deny: egress.message }

  const result = await next(e)
  if (!guard || !result || result.deny || result.isError) return result

  const text = extractResultText(result)
  if (!text) return result
  const verdict = await screenContent($, text, 'mcp:' + (serverName ?? e.tool), e.tool_use_id)
  if (verdict.decision === 'deny') {
    return withholdResult(result, withheldMessage('this MCP result', verdict.withholdReason))
  }
  if (verdict.tainted) return appendContext(result, UNTRUSTED_CONTENT_WARNING)
  return result
}

async function mcpGuardCatch($: any, e: any, next: any) {
  return { deny: 'barmkin-mod: the MCP guard failed (' + next.error.kind + '), so this call was not run' }
}

// ---------------------------------------------------------------------------
// Untrusted-content taint + injection screen.
// ---------------------------------------------------------------------------

// One gate for every egress class that is not an MCP call or a skill load:
// shell commands (Bash/PowerShell and Monitor's `command`), web fetches and
// searches, Monitor WebSockets, and persistence-surface writes. A deny answers
// before the tool runs; a warn lets it run and tells Claude.
async function egressGuardHook($: any, e: any, next: any) {
  const egress = await egressGate($, { tool: e.tool, input: e })
  if (egress.kind === 'deny') return { deny: egress.message }
  const result = await next(e)
  if (egress.kind === 'warn' && result && !result.deny && !result.isError) return appendContext(result, egress.message)
  return result
}

async function egressGuardCatch($: any, e: any, next: any) {
  return { deny: 'barmkin-mod: the egress guard failed (' + next.error.kind + '), so this call was not run' }
}

// ---------------------------------------------------------------------------
// Mediation guard. A skill's inline shell (`!`command``) runs the command
// through the permission check but never through the mods' tool.call chain, so
// none of the tool.call guards above see it; tool.check is the one event it
// does fire, with an empty tool_use_id. This hook only ever answers deny or
// returns what the permission layer decided, never allow or ask.
// ---------------------------------------------------------------------------

async function toolCheckGuardHook($: any, e: any, next: any) {
  const decided = await next(e)
  if (decided && decided.decision === 'deny') return decided
  const input = e.input && typeof e.input === 'object' ? (e.input as Record<string, unknown>) : null
  if (!input || typeof input.command !== 'string') return decided

  const sw = await readSwitches($)
  // Self-protection here too: a skill's inline shell never reaches the
  // tool.call guard, and a command rewritten after it is judged again.
  if (sw['self-protection']) {
    const protectedReason = shellSelfProtectionReason(input.command)
    if (protectedReason) return { decision: 'deny', reason: protectedReason }
  }
  const call: EgressCall = { tool: e.tool, input }
  if (sw['skill-shell-mediation'] && isInlineSkillShell(e.tool_use_id)) {
    const reason = inlineShellDenyReason(call)
    if (reason) return { decision: 'deny', reason }
  }
  // Second line for an ordinary call: the same egress verdict the tool.call
  // guard reached, in case the command was rewritten after it.
  const egress = await egressGate($, call)
  if (egress.kind === 'deny') return { decision: 'deny', reason: egress.message }
  return decided
}

async function toolCheckGuardCatch($: any, e: any, next: any) {
  return { decision: 'deny', reason: 'barmkin-mod: the shell mediation guard failed (' + next.error.kind + '), so this command was not run' }
}

async function webFetchTaintHook($: any, e: any, next: any) {
  if (!(await readSwitches($))['web-screen']) return next(e)
  const result = await next(e)
  if (!result || result.deny || result.isError) return result
  const text = extractResultText(result)
  if (!text) return result
  const verdict = await screenContent($, text, 'fetch:' + e.tool, e.tool_use_id)
  if (verdict.decision === 'deny') {
    return withholdResult(result, withheldMessage('this result', verdict.withholdReason))
  }
  if (verdict.tainted) return appendContext(result, UNTRUSTED_CONTENT_WARNING)
  return result
}

async function readTaintHook($: any, e: any, next: any) {
  // Leg B is noted whatever the switch: only the screen below is switchable.
  const screens = (await readSwitches($))['outside-cwd-read-taints']
  await noteSensitiveAccess($, { tool: e.tool, input: e })
  const result = await next(e)
  if (!result || result.deny || result.isError) return result
  if (!screens || typeof e.file_path !== 'string') return result

  let cwd = ''
  try {
    cwd = await $.session.cwd()
  } catch {
    return result
  }
  if (!isOutsideCwd(e.file_path, cwd)) return result

  const text = extractResultText(result)
  if (!text) return result
  const verdict = await screenContent($, text, 'read:' + e.file_path, e.tool_use_id)
  if (verdict.decision === 'deny') {
    return withholdResult(result, withheldMessage("this file's content", verdict.withholdReason))
  }
  // appendContext only adds a sibling `context` array alongside whatever
  // `result` already is -- it never touches `result`'s own shape -- so this
  // stays schema-valid for Read's `{ file: { content, ... } }` record the
  // same way it already is for every other tool here.
  if (verdict.tainted) return appendContext(result, UNTRUSTED_CONTENT_WARNING)
  return result
}

async function taintScreenCatch($: any, e: any, next: any) {
  return { deny: 'barmkin-mod: the content screen failed (' + next.error.kind + '), so this result was withheld' }
}

// ---------------------------------------------------------------------------
// Secret redaction. Outermost tool.call hook (registered first, so it wraps
// every other hook above and redacts the final composed result -- including
// any context a later hook in this file added -- before Claude reads it).
// ---------------------------------------------------------------------------

// Read's image variant carries its payload as base64 at result.result.base64
// (flat) or result.result.file.base64 (file record). Gated on the Read tool so
// an MCP result cannot hide plaintext there.
function readImageBase64(e: any, result: any): string | undefined {
  const payload = result.result
  if (e.tool !== 'Read' || !payload || typeof payload !== 'object' || payload.type !== 'image') return undefined
  const base64 = typeof payload.base64 === 'string' ? payload.base64 : payload.file?.base64
  return typeof base64 === 'string' ? base64 : undefined
}

// Decodes an image payload that already passed the per-string cap and runs the
// rules over its bytes, so a secret in a plaintext file with an image extension
// is caught. The base64 text itself also goes through the normal redaction pass.
function imagePayloadWithholdReason(base64: string): string | null {
  let bytes: string
  try {
    bytes = atob(base64)
  } catch {
    return 'this Read image payload is not valid base64'
  }
  return containsAnySecret(bytes, REDACTION_RULES) ? 'this Read image payload contains a secret-shaped value' : null
}

// A result shows a scanned prefix only when its payload is text: cutting a
// base64 image or PDF leaves something that is not one. A result with no
// `result` has nothing to cut.
function prefixable(result: any): boolean {
  if (!('result' in result)) return false
  const payload = result.result
  if (!payload || typeof payload !== 'object') return true
  const binary = payload.type === 'image' || payload.type === 'pdf' || 'base64' in payload || (!!payload.file && typeof payload.file === 'object' && 'base64' in payload.file)
  return !binary
}

// Whether an injection screen covers this tool's result: an MCP tool, WebFetch,
// WebSearch, and a Read outside cwd. Each withholds at the 16 KiB screened limit
// inside `next(e)`, so a result that reaches the redaction hook over that limit
// came from a tool with no screen, or from a Read whose screen could not run
// (the cwd lookup failed, which is treated as outside). This hook keeps those
// at the screened limit too, so raising the redaction cap never lets unscreened
// untrusted text in.
async function screenedSurface($: any, e: any): Promise<boolean> {
  if (typeof e.tool !== 'string') return true
  if (parseMcpServerName(e.tool) || e.tool === 'WebFetch' || e.tool === 'WebSearch') return true
  if (e.tool !== 'Read' || typeof e.file_path !== 'string') return false
  try {
    return isOutsideCwd(e.file_path, await $.session.cwd())
  } catch {
    return true
  }
}

async function redactionHook($: any, e: any, next: any) {
  if (!(await readSwitches($)).redaction) return next(e)
  const result = await next(e)
  if (!result || result.deny) return result
  // Within the screened limits nothing depends on which tool this is. Over them,
  // only a tool that no screen covers gets the larger redaction limits.
  let size = measureResult(result, true)
  if (size !== 'within' && !(await screenedSurface($, e))) size = measureResult(result)
  const showPrefix = size === 'long-string' && prefixable(result)
  if (size === 'over-total' || (size === 'long-string' && !showPrefix)) {
    return { deny: 'barmkin-mod: this tool result is larger than the redaction scan budget, so it was withheld. ' + PAGING_ADVICE }
  }

  const imageBase64 = readImageBase64(e, result)
  const imageReason = imageBase64 === undefined ? null : imagePayloadWithholdReason(imageBase64)
  if (imageReason) return { deny: 'barmkin-mod: ' + imageReason + ', so it was withheld' }

  let changed = false
  let hiddenCount = 0
  let redactionHits = 0
  let noSafeCut = false
  const cuts = new Map<string, string>()
  const next_: any = { ...result }

  // Every string inside the result is rewritten in place, whatever its
  // shape: a plain string, an MCP content-block array, or a built-in tool's
  // typed record (Bash `{stdout, stderr, ...}`, Read `{file: {content}}`).
  // The record keeps its shape so core's output-schema validation passes.
  // Core's model-visible rendering in `text` is redacted the same way.
  // Scrubbed before redaction: a zero-width character spliced into a
  // token shouldn't be able to help it dodge a secret pattern either.
  // A string over the per-string cap, in a result that may show one, is
  // replaced by its scanned prefix, and its invisible-text count covers the
  // whole string.
  const redactValue = (value: unknown): unknown => {
    if (typeof value === 'string') {
      if (showPrefix && exceedsScanLimit(value)) {
        const prefix = scannedPrefix(value, REDACTION_RULES, redactionCounters)
        if (prefix === null) {
          noSafeCut = true
          return value
        }
        hiddenCount += prefix.hiddenCount
        redactionHits += prefix.redactedCount
        cuts.set(prefix.cut + '/' + prefix.total, prefixNotice(prefix.cut, prefix.total))
        changed = true
        return prefix.shown
      }
      const scrubbed = scrubInvisible(value)
      hiddenCount += scrubbed.hiddenCount
      const { text: redacted, redactedCount } = redactInEitherView(value)
      redactionHits += redactedCount
      if (redactedCount === 0 && scrubbed.strippedCount === 0) return value
      changed = true
      return redacted
    }
    if (Array.isArray(value)) return value.map(redactValue)
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactValue(v)]))
    }
    return value
  }
  if ('result' in result) next_.result = redactValue(result.result)
  const hiddenInResult = hiddenCount
  hiddenCount = 0
  if (typeof result.text === 'string') next_.text = redactValue(result.text)
  hiddenCount = Math.max(hiddenInResult, hiddenCount)

  if (Array.isArray(result.context)) {
    const redactedContext = result.context.map((c: unknown) => {
      if (typeof c !== 'string') return c
      const scrubbed = scrubInvisible(c)
      hiddenCount += scrubbed.hiddenCount
      const { text: redacted, redactedCount } = redactInEitherView(c)
      redactionHits += redactedCount
      if (redactedCount > 0 || scrubbed.strippedCount > 0) changed = true
      return redacted
    })
    next_.context = redactedContext
  }

  if (noSafeCut) {
    return { deny: 'barmkin-mod: this tool result is larger than the redaction scan budget and has no safe place to cut it, so it was withheld. ' + PAGING_ADVICE }
  }

  // A redaction hit means a credential-shaped value just passed through this
  // session: leg B of the trifecta. Written before returning (and queued with
  // the taint writes) so the very next egress call sees it.
  if (redactionHits > 0) {
    await markSensitive($, 'a ' + (parseMcpServerName(e.tool) ? 'tool' : e.tool) + ' result held a credential-shaped value')
  }

  void taintForScrub($, hiddenCount, 'tool:' + (typeof e.tool === 'string' && parseMcpServerName(e.tool) ? 'mcp' : e.tool))

  if (!showPrefix) return changed ? next_ : result

  // A fresh answer, without core's `ref` and `text`: core then validates the
  // record against the tool's output schema and maps it for the model itself,
  // rather than reusing its own rendering of the full output. An errored
  // result has no output schema, so it keeps its error text.
  const fresh: any = { result: next_.result, context: [...(next_.context ?? []), ...cuts.values()] }
  if (result.isError) {
    fresh.isError = true
    if ('text' in next_) fresh.text = next_.text
  }
  // Read's line count describes the content it now carries.
  const file = fresh.result?.file
  if (cuts.size > 0 && file && typeof file.content === 'string' && typeof file.numLines === 'number') {
    fresh.result = { ...fresh.result, file: { ...file, numLines: file.content.split('\n').length } }
  }
  return fresh
}

async function redactionCatch($: any, e: any, next: any) {
  // Fail closed regardless of whether the tool already ran (next.called):
  // we can't un-run a command, but we can stop an unredacted result from
  // reaching the model or the transcript.
  return { deny: 'barmkin-mod: secret redaction failed (' + next.error.kind + '); the result was withheld to avoid leaking an unredacted secret' }
}

// ---------------------------------------------------------------------------
// Agent-to-agent firewall.
// ---------------------------------------------------------------------------

async function sessionReceiveHook($: any, e: any, next: any) {
  if (typeof e.text !== 'string' || e.text.length === 0) return next(e)
  const sw = await readSwitches($)
  if (!sw['a2a-firewall']) return next(e)
  // A task notification or a scheduled trigger is this session's own work coming back.
  const kind = e.origin?.kind
  if ((kind === 'task-notification' || kind === 'scheduled-trigger') && !sw['consume-own-notifications']) return next(e)

  const scrubbed = scrubInvisible(e.text)
  void taintForScrub($, scrubbed.hiddenCount, 'an inbound peer message')
  if (exceedsScreenedLimit(e.text)) {
    return { consumed: 'barmkin-mod: withheld an inbound message (it is longer than the 16 KiB scan limit)' }
  }

  const verdict = await screenContent($, e.text, 'peer:' + (e.origin?.kind ?? 'unknown'), undefined)
  if (verdict.decision === 'deny') {
    return { consumed: 'barmkin-mod: withheld an inbound message (' + verdict.withholdReason + ')' }
  }
  return next(scrubbed.text === e.text ? e : { ...e, text: scrubbed.text })
}

async function sessionReceiveCatch($: any, e: any, next: any) {
  return { consumed: 'barmkin-mod: the a2a screen failed (' + next.error.kind + '); message withheld' }
}

async function sessionSendHook($: any, e: any, next: any) {
  if (!(await readSwitches($))['a2a-outbound']) return next(e)
  if (typeof e.text !== 'string') return next(e)
  if (exceedsScreenedLimit(e.text)) {
    return { isDelivered: false, reason: 'barmkin-mod: message withheld, it is longer than the 16 KiB scan limit' }
  }
  // Detection runs on the scrubbed view; the original text is delivered when no secret is found.
  if (containsSecretInEitherView(e.text, REDACTION_RULES)) {
    return { isDelivered: false, reason: 'barmkin-mod: message withheld, it appears to contain a secret' }
  }
  return next(e)
}

async function sessionSendCatch($: any, e: any, next: any) {
  return { isDelivered: false, reason: 'barmkin-mod: the DLP screen failed (' + next.error.kind + '); message not sent' }
}

async function agentSpawnHook($: any, e: any, next: any) {
  if (!(await readSwitches($))['spawn-blocked-when-tainted']) return next(e)
  const { tainted: isTainted, reason, ackReason } = await readTaint($)
  if (isTainted) {
    return {
      deny:
        'barmkin-mod: subagent spawn blocked while this session is tainted (' +
        (reason ?? 'unspecified') +
        '). ' +
        askAgainHint(ackReason),
    }
  }
  return next(e)
}

async function agentSpawnCatch($: any, e: any, next: any) {
  return { deny: 'barmkin-mod: the a2a spawn guard failed (' + next.error.kind + '); subagent spawn blocked' }
}

// ---------------------------------------------------------------------------
// Skill content. skill.prompt fires with each skill body, after inline-shell
// output is substituted, for inline, context: fork and agent-preloaded skills.
// Its payload is { skill: <name string>, text }; the dispatcher rejects a
// changed `skill`, so only `text` is ever rewritten. Org seat only: sec-default
// forwards skill.prompt past the user tier, so this fires only when the mod is
// seated in managed prependPlugins ahead of sec-default (README "Seat
// requirements"). Like toolDescribeHook, it calls next first and screens and
// redacts the text that came out, so redaction sees the final body last.
// ---------------------------------------------------------------------------

async function skillPromptHook($: any, e: any, next: any) {
  const current = await next(e)
  const text = typeof current?.text === 'string' ? current.text : e.text
  if (typeof text !== 'string') return current ?? e

  const sw = await readSwitches($)
  let tainted = false
  if (sw['skill-guard']) {
    void taintForScrub($, scrubInvisible(text).hiddenCount, 'a skill body')
    const verdict = await screenContent($, text, 'skill:' + e.skill, undefined)
    if (verdict.decision === 'deny') {
      return { ...(current ?? e), text: skillBodyWithheldText(verdict.withholdReason) }
    }
    tainted = verdict.tainted
  }
  const warned = (body: string) => (tainted ? body + '\n\n' + UNTRUSTED_CONTENT_WARNING : body)
  if (!sw.redaction) return tainted ? { ...(current ?? e), text: warned(text) } : current ?? e

  const { text: redacted, redactedCount } = redactInEitherView(text)
  if (redacted === WITHHELD_TEXT) {
    return { ...(current ?? e), text: skillBodyWithheldText('the redacted body exceeds the 256 KiB scan limit') }
  }
  if (redactedCount > 0) {
    $.ui.log('barmkin-mod: redacted ' + redactedCount + ' likely secret(s) from skill ' + e.skill)
  }
  return { ...(current ?? e), text: warned(redacted) }
}

async function skillPromptCatch($: any, e: any, next: any) {
  return { skill: e.skill, text: skillBodyWithheldText('the skill screen failed (' + next.error.kind + ')') }
}

// A skill listing is `prompt.attachment{type:'skill_listing', text}`, one per
// session and one per spawned subagent. The hook is registered for that type
// only, so other attachments never reach it or its catch. The dispatcher honours
// a rewritten `text` and rejects a change to `type`, `origin`, `agentId` or `detail`.
async function skillListingHook($: any, e: any, next: any) {
  if (!(await readSwitches($))['skill-guard']) return next(e)
  const current = await next(e)
  const text = typeof current?.text === 'string' ? current.text : e.text
  if (typeof text !== 'string') return current ?? e

  const { text: neutralized, withheld } = neutralizeSkillListing(scrubInvisible(text).text)
  if (withheld > 0) $.ui.log('barmkin-mod: withheld ' + withheld + ' skill listing entr' + (withheld === 1 ? 'y' : 'ies') + ' with instruction-like text', { to: 'debug' })
  if (neutralized === text) return current ?? e
  return { ...(current ?? e), text: neutralized }
}

async function skillListingCatch($: any, e: any, next: any) {
  return { ...e, text: skillListingWithheldText('the listing screen failed (' + next.error.kind + ')') }
}

// Gates the Skill tool itself. A loaded skill is untrusted content in its own
// right: its body is screened by skillPromptHook, and the load taints the
// session so later outward-effect Bash and further skill loads are held until
// the user's next message. The taint is reserved before the load runs, so
// concurrent calls serialise on it, and the reservation stays on failure or
// denial, so a failed or denied load leaves the session tainted.
async function skillToolGuardHook($: any, e: any, next: any) {
  const name = typeof e.skill === 'string' ? e.skill : 'unnamed'
  const sw = await readSwitches($)
  let standing: { standingReason: string | null; ackReason: string | null } | null = null
  if (sw.taint && sw['skill-load-taints']) {
    standing = await reserveSkillLoad($, 'skill "' + name + '" was loaded')
  } else {
    // The load does not taint, but a session already tainted still refuses it.
    const held = await readTaint($)
    if (held.tainted) standing = { standingReason: held.reason, ackReason: held.ackReason }
  }
  // The taint-blocks-egress switch off: a taint alone refuses no skill load.
  if (standing && sw['taint-blocks-egress']) {
    await update($, lastEgress, () => ({ tool: 'Skill', classIds: ['skill-load'], decision: 'deny' as const, rule: 'untrusted', at: Date.now() }))
    return {
      deny:
        'barmkin-mod: loading a skill is blocked while this session is handling untrusted content (' +
        (standing.standingReason ?? 'unspecified') +
        '). ' +
        askAgainHint(standing.ackReason),
    }
  }
  return next(e)
}

async function skillToolGuardCatch($: any, e: any, next: any) {
  return { deny: 'barmkin-mod: the skill guard failed (' + next.error.kind + '), so this skill was not loaded' }
}

// ---------------------------------------------------------------------------
// Classifier explanation surface: HUD band.
// ---------------------------------------------------------------------------

// The tainted-session panel's color: the theme's error key, red in every
// theme, so the panel matches how the session draws its own errors.
const TAINT_COLOR = 'error'

// The clear-session labels: the theme's success key (green) and warning key
// (amber); both labels lead with a castle emoji. Green means Jev is
// configured and its breaker is closed; it does not claim any request
// succeeded. Amber means Jev is not configured or its breaker is open.
const CLEAR_ACTIVE = { color: 'success', label: '🏰 Barmkin session guard active' }
const CLEAR_DEGRADED = { color: 'warning', label: '🏰 Barmkin session guard degraded' }

// Green needs every protection switch on as well: a session with one switched
// off is not the guarded session the green label claims.
// `jevOn`: Jev configured and its switch on. Green also needs every protection
// switch on: a session with one switched off is not the guarded session the
// green label claims.
function clearLabelFor(breakerOpen: boolean, jevOn: boolean, sw: SwitchMap) {
  return jevOn && !breakerOpen && protectionsOff(sw).length === 0 ? CLEAR_ACTIVE : CLEAR_DEGRADED
}

async function hudHook($: any, e: any, next: any) {
  const { tainted: isTainted, ackReason } = await readTaint($)
  const isSensitive = await read($, sensitiveAccess)
  const verdict = await read($, lastVerdict)
  const off = protectionsOff(await readSwitches($))

  const { Box, Text } = $.ui.resolve(e)
  const breakerUntil = await read($, breakerOpenUntil)
  const breakerOpen = breakerUntil > Date.now()
  const parts = ['barmkin-mod', 'taint:' + (isTainted ? 'ON' : 'off'), breakerOpen ? 'classifier:degraded' : 'classifier:ok']
  if (isSensitive) parts.splice(2, 0, isTainted ? 'sensitive:ON (egress locked)' : 'sensitive:ON')
  if (verdict) {
    parts.push(verdict.decision + ' p=' + verdict.probability.toFixed(2) + ' (' + verdict.model + ')')
  }

  // One red line for as long as the taint is held: untrusted content is
  // active, what it restricts, and the clear path that works under the
  // active posture.
  let banner = null
  if (isTainted) {
    banner = Box({
      key: 'barmkin-mod-taint',
      children: [Text({ color: TAINT_COLOR, bold: true, children: [describeTaintBanner(taintClearPosture(), isSensitive, ackReason !== null)] })],
    })
  }

  // One amber line naming every protection that is switched off, for as long as one is.
  const offLine =
    off.length > 0
      ? Text({ key: 'barmkin-mod-off', color: 'warning', children: ['barmkin-mod: switched off: ' + off.join(', ') + ' (/barmkin-mod-panel)'] })
      : null

  // next(e) may resolve to nothing if no other mod draws in the band, so
  // filter out a falsy child rather than assume an engine placeholder.
  // The state line below appears only when there is state to report.
  const stateLine = isTainted || isSensitive || verdict ? Text({ children: [parts.join(' · ')] }) : null
  const theirs = await next(e)
  return Box({ flexDirection: 'column', children: [theirs, banner, offLine, stateLine].filter(Boolean) })
}

// The clear-session label draws as a second child of the PromptHint footer,
// directly beneath the engine's own line (mode switcher included). While
// tainted the red banner in AbovePrompt speaks instead, so the engine's
// drawing is returned unchanged.
async function hintHook($: any, e: any, next: any) {
  const theirs = await next(e)
  const { tainted: isTainted } = await readTaint($)
  if (isTainted) return theirs
  const { Box, Text } = $.ui.resolve(e)
  const breakerUntil = await read($, breakerOpenUntil)
  const sw = await readSwitches($)
  // The jev-screening switch off reads as Jev not configured, as the screen does.
  const jevOn = jevConfigured(getJevOptions(pluginOptions, await readOpenRouterKey($))) && sw['jev-screening']
  const clear = clearLabelFor(breakerUntil > Date.now(), jevOn, sw)
  const label = Text({ key: 'barmkin-mod-active', color: clear.color, children: [clear.label] })
  return Box({ flexDirection: 'column', children: [theirs, label].filter(Boolean) })
}

async function clearTaintCommandHook($: any, e: any) {
  const posture = taintClearPosture()
  // What is held, whatever the taint switch: the command clears the held values.
  const { ackReason } = await readHeldTaint($)
  if (!commandMayClearTaint(e.origin, pluginOptions.sdk_prompts_clear_taint === true, ackReason !== null)) {
    return { text: 'barmkin-mod: taint posture is ' + posture + '; /barmkin-mod-clear-taint was not run from a person\'s prompt, so nothing was cleared.' }
  }
  const held = await clearTaintLegs($, true)
  return { text: held ? describeTaintClear(posture, held) : 'barmkin-mod: nothing was cleared.' }
}

async function statusCommandHook($: any) {
  const { tainted: isTainted, reason, ackReason } = await readHeldTaint($)
  const sw = await readSwitches($)
  const taintCounts = isTainted && sw.taint
  const isSensitive = await read($, sensitiveAccess)
  const sensitiveWhy = await read($, sensitiveReason)
  const egress = await read($, lastEgress)
  const verdict = await read($, lastVerdict)
  const breakerUntil = await read($, breakerOpenUntil)
  const shadow = await read($, lastShadow)
  const shadowBreakerUntil = await read($, shadowBreakerOpenUntil)
  const off = switchesOff(sw)
  const lines = [
    'barmkin-mod status',
    'switches: ' + (off.length === 0 ? 'all on' : 'off: ' + off.join(', ') + ' (/barmkin-mod-panel or /barmkin-mod-rule <id> on)'),
    'taint clear posture: ' + taintClearPosture(),
    'taint: ' + (isTainted ? 'ON (' + (reason ?? 'unspecified') + ')' + (sw.taint ? '' : ', ignored: the taint switch is off') : 'off'),
    ...(ackReason !== null
      ? ['acknowledgement required: ' + ackReason + '; run /barmkin-mod-clear-taint (a message, /clear or /compact does not clear it)']
      : []),
    'sensitive access: ' + (isSensitive ? 'ON (' + (sensitiveWhy ?? 'unspecified') + ')' : 'off'),
    'egress: ' +
      (!sw['egress-gate']
        ? 'egress gate switched off'
        : taintCounts && isSensitive && sw['rule-of-two']
          ? 'all classes denied (Rule of Two)'
          : taintCounts && sw['taint-blocks-egress']
            ? 'gated per class (taint)'
            : 'open') +
      (egress ? '; last ' + egress.decision + ': ' + egress.classIds.join(', ') + ' via ' + egress.tool + ' (' + egress.rule + ')' : ''),
    'classifier breaker: ' + (breakerUntil > Date.now() ? 'open (degraded, using heuristics)' : 'closed'),
    verdict
      ? 'last verdict: ' + verdict.decision + ' p=' + verdict.probability.toFixed(2) + ' model=' + verdict.model + ' question=' + verdict.question
      : 'last verdict: none yet',
    'shadow screen (contrast only: captain wording x4, revised destructive_command; annotation only, never enforced, never taints): ' +
      (shadowBreakerUntil > Date.now() ? 'breaker open, not asking' : 'breaker closed'),
    ...(shadow ? shadow.arms.map((record) => '  ' + shadow.label + ' ' + describeShadowArm(record)) : ['  no shadow answers yet']),
  ]
  return { text: lines.join('\n') }
}

// ---------------------------------------------------------------------------
// Self-protection: deny only. A call it does not recognise goes on to every
// other guard (hooks/lib/self-protection.ts names what it recognises).
// ---------------------------------------------------------------------------

const FILE_TOOLS: readonly string[] = ['Write', 'Edit', 'MultiEdit', 'NotebookEdit']

function isAbsoluteSpelling(path: string): boolean {
  return path.startsWith('/') || path.startsWith('~') || /^[A-Za-z]:[\\/]/.test(path)
}

// Every spelling a file tool's target is judged under: as written; against the
// working directory when relative; and where it leads through a symbolic link
// (the file's, or for a file not there yet its folder's). A lookup that fails
// drops only its own spelling: the written path is always judged.
async function targetSpellings($: any, raw: string): Promise<string[]> {
  const spellings = [raw]
  if (!isAbsoluteSpelling(raw)) {
    try {
      const cwd = await $.session.cwd()
      if (typeof cwd === 'string' && cwd !== '') spellings.push(cwd.replace(/[\\/]+$/, '') + '/' + raw)
    } catch {
      // no working directory to resolve against
    }
  }
  const cut = Math.max(raw.lastIndexOf('/'), raw.lastIndexOf('\\'))
  const probes: [string, string][] = [[raw, '']]
  if (cut > 0) probes.push([raw.slice(0, cut), raw.slice(cut)])
  for (const [probe, rest] of probes) {
    try {
      const stat = await $.fs.stat(probe, { resolve: true })
      if (typeof stat?.realPath === 'string') {
        spellings.push(stat.realPath + rest)
        break
      }
    } catch {
      // not there (yet), or not resolvable
    }
  }
  return spellings
}

// The current text of a settings file a Write would replace, or null when there
// is none. A read that fails throws, so the hook's catch denies the write.
async function currentText($: any, path: string): Promise<string | null> {
  if (!(await $.fs.exists(path))) return null
  return await $.fs.read(path)
}

async function selfProtectionReason($: any, e: any): Promise<string | null> {
  const tool = typeof e.tool === 'string' ? e.tool : ''
  if (COMMAND_TOOLS.includes(tool)) return typeof e.command === 'string' ? shellSelfProtectionReason(e.command) : null
  if (tool === 'Skill') return isSwitchCommandSkill(e.skill) ? SWITCH_COMMAND_REASON : null
  if (FILE_TOOLS.includes(tool)) {
    const raw = typeof e.file_path === 'string' ? e.file_path : typeof e.notebook_path === 'string' ? e.notebook_path : null
    if (raw === null) return null
    const spellings = await targetSpellings($, raw)
    for (const path of spellings) {
      const reason = fileSelfProtectionReason(tool, e, path)
      if (reason) return reason
    }
    // A Write replaces the whole file, so whether it changes this plugin's
    // settings entries is told against the text it replaces.
    if (tool === 'Write' && spellings.some((p) => isSettingsFile(p)) && typeof e.content === 'string') {
      if (writeChangesProtectedEntries(await currentText($, raw), e.content)) return SETTINGS_WRITE_REASON
    }
    return null
  }
  if (/^mcp__/.test(tool)) return mcpSelfProtectionReason(inputStrings(e))
  return null
}

async function selfProtectionHook($: any, e: any, next: any) {
  if ((await readSwitches($))['self-protection']) {
    const reason = await selfProtectionReason($, e)
    if (reason) return { deny: reason }
  }
  return next(e)
}

async function selfProtectionCatch($: any, e: any, next: any) {
  return { deny: 'barmkin-mod: the self-protection guard failed (' + next.error.kind + '), so this call was not run' }
}

// ---------------------------------------------------------------------------
// The switch command, the switch panel, and the reload after /clear, /resume
// and /branch (which reset $.state, so the switches are read back from the store).
// ---------------------------------------------------------------------------

async function ruleCommandHook($: any, e: any) {
  const request = parseRuleArgs(e.args)
  if (request.kind === 'error') return { text: request.message }
  try {
    if (request.kind === 'list') return { text: describeSwitchList(await checkSwitchStore($)) }
    // Only the person changes a switch: their own Enter, or the Remote Control
    // bridge. A plugin's run (even asUser), the SDK, a notification, a schedule
    // or a peer is refused, so no model or code path turns a protection off.
    if (!originMayChangeSwitches(e.origin)) {
      return {
        text:
          'barmkin-mod: no switch was changed: /barmkin-mod-rule came from ' +
          originKindOf(e.origin) +
          ', not from your own prompt. Run it yourself, or use /barmkin-mod-panel.',
      }
    }
    const map = await setSwitch($, request.id, request.on)
    return { text: describeSwitchChange(request.id, map[request.id]) }
  } catch (error) {
    return { text: 'barmkin-mod: the switch store could not be read or written (' + String(error) + '), so no switch was changed.' }
  }
}

async function panelCommandHook($: any) {
  try {
    await checkSwitchStore($)
  } catch {
    // the panel still opens, with the switches this session holds
  }
  await $.ui.open({ id: SWITCH_PANE_ID, title: SWITCH_PANE_TITLE, rows: SWITCH_PANE_ROWS, focus: true, closeOnEscape: true })
  return {}
}

// Descriptions show beside the switches only where they have room.
const SWITCH_PANE_WIDE_COLUMNS = 72
const SWITCH_ID_WIDTH = Math.max(...SWITCH_DEFS.map((d) => d.id.length))

// The switch panel: one button per switch, flipped by a click or by Enter on
// the focused row (Tab moves between rows; Up and Down do too while the list
// fits, and scroll it when it does not). No hotkeys: one stray
// key would turn a protection off. One render path for every surface.
async function switchPaneHook($: any, e: any, next: any) {
  if (e.requestId !== SWITCH_PANE_ID) return next(e)
  const { Box, Text, Button } = $.ui.resolve(e)
  const sw = await readSwitches($)
  const notice = await read($, switchesNoticeAtom)
  const off = switchesOff(sw)
  const wide = (e.props?.bodyColumns ?? 0) >= SWITCH_PANE_WIDE_COLUMNS
  const rows = SWITCH_DEFS.map((def) => {
    const on = sw[def.id]
    const button = Button({
      key: 'switch-' + def.id,
      label: (on ? '✓ on  ' : '✗ OFF ') + def.id.padEnd(SWITCH_ID_WIDTH),
      plain: true,
      // Awaited, so the press resolves once the switch is saved and $.state holds it.
      onPress: async () => {
        await setSwitch($, def.id, 'toggle').catch((error: unknown) =>
          noteSwitches($, 'barmkin-mod: the ' + def.id + ' switch could not be saved (' + String(error) + '), so it is unchanged.'),
        )
      },
    })
    if (!wide) return Box({ key: 'row-' + def.id, children: [button] })
    return Box({
      key: 'row-' + def.id,
      flexDirection: 'row',
      columnGap: 1,
      children: [button, Text({ dimColor: true, wrap: 'truncate-end', children: [def.description] })],
    })
  })
  return Box({
    flexDirection: 'column',
    children: [
      Text({ key: 'header', bold: true, children: ['Barmkin security switches · ' + (off.length === 0 ? 'all on' : off.length + ' off')] }),
      Text({ key: 'help', dimColor: true, wrap: 'wrap', children: ['A click, or Enter on a row, flips that switch.'] }),
      notice ? Text({ key: 'notice', color: 'warning', wrap: 'wrap', children: [notice] }) : null,
      ...rows,
    ].filter(Boolean),
  })
}

async function sessionResetHook($: any, e: any, next: any) {
  try {
    await checkSwitchStore($)
  } catch {
    logLine($, 'barmkin-mod: could not read the switch store; the switches this session holds stay in force (all on if it holds none)')
  }
  return next(e)
}

// ---------------------------------------------------------------------------
// Registration. Order matters for tool.call: the first hook registered is
// outermost (sees the result last), so redaction is registered first to
// redact whatever every other hook below it produced.
// ---------------------------------------------------------------------------

export function register(on: any, options: Record<string, unknown>) {
  pluginOptions = options ?? {}

  on('session.start', sessionStartHook)
  // /clear, /resume and /branch reset $.state; the switches are read back from the store.
  on('classic.SessionStart', sessionResetHook)
  on('prompt.submit', promptSubmitHook)
  on('session.compact', compactHook)
  on('session.end', sessionEndHook)
  on('tool.describe', { tool: /^mcp__/ }, toolDescribeHook)

  on('tool.call', redactionHook).catch(redactionCatch)
  // Second outermost: a self-protection deny answers before any other guard
  // runs, and before skillToolGuardHook reserves a taint for the load.
  on('tool.call', { tool: ['Bash', 'PowerShell', 'Monitor', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'Skill'] }, selfProtectionHook).catch(
    selfProtectionCatch,
  )
  on('tool.call', { tool: /^mcp__/ }, selfProtectionHook).catch(selfProtectionCatch)
  on('tool.call', { tool: /^mcp__/ }, mcpGuardHook).catch(mcpGuardCatch)
  on('tool.call', { tool: ['Bash', 'PowerShell', 'WebFetch', 'WebSearch', 'Monitor', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit'] }, egressGuardHook).catch(egressGuardCatch)
  on('tool.call', { tool: ['WebFetch', 'WebSearch'] }, webFetchTaintHook).catch(taintScreenCatch)
  on('tool.call', { tool: 'Read' }, readTaintHook).catch(taintScreenCatch)

  on('tool.call', { tool: 'Skill' }, skillToolGuardHook).catch(skillToolGuardCatch)
  on('tool.check', { tool: ['Bash', 'PowerShell', 'Monitor'] }, toolCheckGuardHook).catch(toolCheckGuardCatch)

  on('skill.prompt', skillPromptHook).catch(skillPromptCatch)
  on('prompt.attachment', { type: 'skill_listing' }, skillListingHook).catch(skillListingCatch)

  on('session.receive', sessionReceiveHook).catch(sessionReceiveCatch)
  on('session.send', sessionSendHook).catch(sessionSendCatch)
  on('agent.spawn', agentSpawnHook).catch(agentSpawnCatch)
  on('ui.render', { component: 'AbovePrompt' }, hudHook)
  on('ui.render', { component: 'PromptHint' }, hintHook)
  on('ui.render', { component: 'Pane' }, switchPaneHook)
  on('command.run', { command: 'barmkin-mod-status' }, statusCommandHook)
  on('command.run', { command: 'barmkin-mod-clear-taint' }, clearTaintCommandHook)
  on('command.run', { command: 'barmkin-mod-rule' }, ruleCommandHook)
  on('command.run', { command: 'barmkin-mod-panel' }, panelCommandHook)
}
