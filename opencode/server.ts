// barmkin-opencode: the OpenCode 2.x server plugin (partial port of barmkin-mod).
//
// `export default { id, setup(ctx) }` is OpenCode 2's Promise-API plugin entry
// (re-scout section 2.1). Everything host-neutral is called from hooks/lib; this
// file is only the host adapter: it wires the 2.x hooks, keeps the per-session
// state, and composes the lib's pure functions the way hooks/register.ts does
// for Claude Code. NOT equivalent to barmkin-mod for Claude Code: see the posture
// line this file emits and the contract in opencode/README.md.
//
// Rules this file follows (CONTRACT.md, re-scout V-set):
//  - Deny = throw. A throw in `tool.execute.before` stops the tool and the model
//    reads the thrown text (V2). A throw in `permission.evaluate` is final even
//    when a later plugin forces "allow" (V7); setting `effect = "deny"` is NOT
//    final (V6), so it is never used.
//  - Never throw inside a `*.transform` callback (V19): OpenCode disables the
//    whole plugin mid-session. Transform callbacks here are try/caught.
//  - Hooks that guard fail closed: any internal failure refuses the call (before
//    hooks, evaluate, prompt) or withholds the result (after hook).
//  - `setup` itself only throws for a guard hook that could not be registered;
//    everything optional (rpc, command, the plugin-inventory probe) is isolated.
//
// State atoms. 2.x has no `atom()`; the equivalent is the in-process store below,
// keyed `{ plugin: 'barmkin-opencode', key }`. Taint, sensitive access, the last
// egress/verdict/shadow records are per ROOT session (a subagent's session shares
// its parent's taint). The two breakers are plugin-wide, like the Jev endpoint.
// Updates are synchronous, so the serialised write queue register.ts needs for
// Claude's async state is not needed here.
//
// Taint-clear posture is always `sticky` here: the 2.x prompt event carries no
// origin (V27), so a person's prompt cannot be told from a synthetic user-role
// message (V30). Only the `/barmkin-mod-clear-taint` command clears (V37); the
// model has no command tool. Compaction and session end do not clear either,
// because the 2.x compaction hook runs before the summary exists. Both are the
// documented human-origin limitation in the contract.
//
// ---------------------------------------------------------------------------
// Composition. The host-neutral pieces live beside this file:
//   ./src/egress-normaliser  re-keys 2.x tool ids and arguments to the names
//                            hooks/lib/egress.ts matches on, and gates them
//   ./src/result-shapes      the 2.x wire shapes and the string traversals
//   ./src/tool-result        read, redact, withhold and annotate an after event
//   ./src/mcp-guard          the MCP description neutraliser (installMcpGuard)
//   ./src/status-rpc         the one channel to the TUI half (tui.tsx)
// ---------------------------------------------------------------------------
import { REDACTION_RULES } from '../hooks/lib/redaction-rules'
import {
  redactInEitherView as redactInEitherViewLib,
  classifierInput,
  WITHHELD_TEXT,
  containsSecretInEitherView,
  measureResult,
  exceedsScreenedLimit,
  SCREENED_LIMIT_REASON,
  PAGING_ADVICE,
} from '../hooks/lib/redaction'
import { scrubInvisible } from '../hooks/lib/scrub'
import {
  composeScreen,
  isOutsideCwd,
  heuristicInjectionScore,
  classifierGapReason,
  credentialScoreReason,
  describeTaintClear,
  DEFAULT_TAINT_THRESHOLDS,
  UNTRUSTED_CONTENT_WARNING,
  type HeldTaint,
  type ScoreSource,
  type ScreenOutcome,
  type TaintClearPosture,
} from '../hooks/lib/taint'
import { touchesSecretPath, type EgressCall, type EgressVerdict, type TrifectaLegs } from '../hooks/lib/egress'
import { planWindows, unclassifiedChars, mergeWindowScores, mergeWindowAnswers } from '../hooks/lib/classifier-windows'
import { PRODUCTION_QUESTIONS, SCREEN_QUESTION_IDS, SHADOW_ARMS, shadowQuestions, type ShadowArm } from '../hooks/lib/jev-questions'
import {
  buildSystemOneRequest,
  parseSystemOneResponse,
  JEV_MODEL_PATTERN,
  type NoulQuestion,
  type SystemOneParseResult,
} from '../hooks/lib/system-one-client'
import { skillBodyWithheldText, neutralizeSkillListing } from '../hooks/lib/skill-guard'
import { gateEgress, normaliseEgressCalls, normaliseEvaluate, type NormaliseOptions } from './src/egress-normaliser'
import { installMcpGuard, isServerAllowed, mcpNamespace, parseAllowlist, type McpGuardHandle, type McpGuardHost } from './src/mcp-guard'
import { mapPromptStrings, mapRequestStrings, mapToolDescriptions, mapCompactionResult, promptText, type SessionCompactionShape, type SessionContextShape, type SessionPromptShape, type ToolAfterEvent as WireAfterEvent } from './src/result-shapes'
import { statusRpc, type StatusReport } from './src/status-rpc'
import { afterEventText, noticeAfterEvent, redactAfterEvent, withholdAfterEvent } from './src/tool-result'

// ---------------------------------------------------------------------------
// Identity and the shipping text.
// ---------------------------------------------------------------------------

// Plugin id. Exactly this, never 'barmkin-mod' (that is the Claude plugin).
export const PLUGIN_ID = 'barmkin-opencode'
export const PLUGIN_VERSION = '0.1.0'

// The git sha of hooks/lib the bundle was built from. The build injects it
// (`bun build --define BARMKIN_CORE_SHA='"<sha>"'`); an unbuilt checkout says so.
declare const BARMKIN_CORE_SHA: string | undefined
const CORE_SHA = typeof BARMKIN_CORE_SHA === 'string' && BARMKIN_CORE_SHA !== '' ? BARMKIN_CORE_SHA : 'unbuilt'

// Whether the MCP description neutraliser (src/mcp-guard) installed every hook it
// needs. Set in setup from the guard's own report; when it is false (the guard
// failed to install or an earlier step errored), the posture line says MCP tool
// descriptions are not covered.
let mcpDescriptionGuard = false
let mcpGuard: McpGuardHandle | null = null

function refreshMcpDescriptionGuard(): void {
  const status = mcpGuard?.status()
  mcpDescriptionGuard = status !== undefined && mcpGuard!.healthy() && status.installed.toolTransform && status.installed.contextHook
  if (status !== undefined && !mcpDescriptionGuard) debugLog('barmkin-opencode: the MCP guard is not fully installed: ' + status.errors.join('; '))
}

const TAINT_POSTURE: TaintClearPosture = 'sticky'

const BREAKER_FAILURE_THRESHOLD = 3
const BREAKER_COOLDOWN_MS = 60_000
const JEV_TIMEOUT_MS = 700
const INVISIBLE_CHAR_TAINT_THRESHOLD = 32
// The inventory probe may wait on plugin activation, so it never blocks setup.
const INVENTORY_TIMEOUT_MS = 5_000

// ---------------------------------------------------------------------------
// The slice of the 2.x Promise-API context this file uses (OpenCode 2.0.27,
// @opencode/plugin promise/*.d.ts). Structural and local, so the bundle has no
// import from @opencode/*.
// ---------------------------------------------------------------------------

interface ToolBeforeEvent {
  tool: string
  readonly sessionID: string
  readonly agent: string
  readonly messageID: string
  readonly id: string
  input: unknown
}

type ToolAfterEvent = WireAfterEvent & { readonly agent: string; readonly messageID: string; readonly id: string }

interface PermissionEvaluation {
  readonly sessionID: string
  readonly action: string
  readonly resources: ReadonlyArray<string>
  readonly metadata?: Record<string, unknown>
  effect: string
  message?: string
}

interface ShellCreateBefore {
  command: string
  cwd: string
}

interface SessionPromptEvent {
  readonly sessionID: string
  prompt: unknown
}

interface SessionRequestEvent {
  readonly sessionID: string
}

interface CommandInvocation {
  readonly sessionID: string
}

interface CommandEditor {
  add(definition: { name: string; description?: string; execute: (input: CommandInvocation) => Promise<void> }): void
}

interface PluginInfo {
  id?: string
  source: { type: string; path?: string; target?: string }
  state: { status: string; error?: string }
}

interface PluginContext {
  readonly options: Readonly<Record<string, any>>
  readonly location: { readonly directory: string }
  readonly tool: {
    hook(name: 'execute.before', callback: (event: ToolBeforeEvent) => Promise<void> | void): Promise<unknown>
    hook(name: 'execute.after', callback: (event: ToolAfterEvent) => Promise<void> | void): Promise<unknown>
    list(): Promise<ReadonlyArray<{ readonly id: string; readonly options?: { readonly namespace?: string } }>>
  }
  readonly permission: { hook(name: 'evaluate', callback: (event: PermissionEvaluation) => Promise<void> | void): Promise<unknown> }
  readonly shell: { hook(name: 'create.before', callback: (event: ShellCreateBefore) => Promise<void> | void): Promise<unknown> }
  readonly session: {
    hook(name: 'prompt', callback: (event: SessionPromptEvent) => Promise<void> | void): Promise<unknown>
    hook(name: 'context' | 'compaction' | 'generate' | 'title', callback: (event: SessionRequestEvent) => Promise<void> | void): Promise<unknown>
    get(input: { sessionID: string }): Promise<unknown>
    synthetic(input: { sessionID: string; text: string; description?: string; resume?: boolean }): Promise<unknown>
  }
  readonly command: { transform(callback: (editor: CommandEditor) => void): Promise<unknown> }
  readonly plugin: { list(): Promise<unknown> }
  readonly rpc: { register(definition: unknown, handlers: unknown): Promise<unknown> }
}

// ---------------------------------------------------------------------------
// State atoms: { plugin: 'barmkin-opencode', key }, per root session or plugin-wide.
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

interface Atom<T> {
  readonly plugin: typeof PLUGIN_ID
  readonly key: string
  readonly initial: T
  readonly scope: 'session' | 'plugin'
}

function atom<T>(key: string, initial: T, scope: 'session' | 'plugin'): Atom<T> {
  return { plugin: PLUGIN_ID, key, initial, scope }
}

const tainted = atom('tainted', false, 'session')
const taintReason = atom('taintReason', null as string | null, 'session')
// Set when the taint needs a person's /barmkin-mod-clear-taint (the classifier
// gap): holds why. Only the command clears it.
const taintAckReason = atom('taintAckReason', null as string | null, 'session')
// Trifecta leg B (sensitive access); leg A is `tainted`, leg C is evaluated per call.
const sensitiveAccess = atom('sensitiveAccess', false, 'session')
const sensitiveReason = atom('sensitiveReason', null as string | null, 'session')
const lastEgress = atom('lastEgress', null as EgressRecord | null, 'session')
const lastVerdict = atom('lastVerdict', null as Verdict | null, 'session')
// What the four-question shadow screen answered for the last piece of content.
// Annotation only: nothing reads it to taint, withhold or gate.
const lastShadow = atom('lastShadow', null as ShadowRecord | null, 'session')
const breakerOpenUntil = atom('breakerOpenUntil', 0, 'plugin')
const breakerFailureCount = atom('breakerFailureCount', 0, 'plugin')
// The shadow screen's own breaker. A shadow failure never opens the classifier
// breaker above, so it can neither degrade the status nor push the production
// screen back to the heuristics.
const shadowBreakerOpenUntil = atom('shadowBreakerOpenUntil', 0, 'plugin')
const shadowBreakerFailureCount = atom('shadowBreakerFailureCount', 0, 'plugin')

const PLUGIN_SCOPE = '*'
const store = new Map<string, Map<string, unknown>>()

function scopeOf<T>(a: Atom<T>, root: string): string {
  return a.scope === 'plugin' ? PLUGIN_SCOPE : root
}

function read<T>(a: Atom<T>, root: string): T {
  const values = store.get(scopeOf(a, root))
  return values !== undefined && values.has(a.key) ? (values.get(a.key) as T) : a.initial
}

function update<T>(a: Atom<T>, root: string, change: (current: T) => T): T {
  const scope = scopeOf(a, root)
  let values = store.get(scope)
  if (values === undefined) {
    values = new Map()
    store.set(scope, values)
  }
  const next = change(read(a, root))
  values.set(a.key, next)
  return next
}

// Redaction placeholder counters. Not security state (no secret value is ever
// kept, only a per-category count for unique labels). The model-boundary hooks
// use a fresh set on every pass instead: they re-run over the whole history each
// request, and a counter that keeps climbing would change the history's text
// between requests and defeat prompt caching.
const redactionCounters: Record<string, number> = {}

let pluginOptions: Readonly<Record<string, any>> = {}
let projectDirectory = ''

// The status RPC's change channel (src/status-rpc `changed`). Best effort: the TUI
// also polls, so a failed emit only delays its refresh.
let emitChanged: (reason: string) => void = () => {}

function debugLog(message: string): void {
  if (pluginOptions.debug === true) console.error(message)
}

// ---------------------------------------------------------------------------
// Sessions: a subagent's session shares its root's taint.
// ---------------------------------------------------------------------------

const rootCache = new Map<string, string>()
const MAX_ROOT_DEPTH = 8

async function rootOf(ctx: PluginContext, sessionID: string): Promise<string> {
  const cached = rootCache.get(sessionID)
  if (cached !== undefined) return cached
  let current = sessionID
  for (let depth = 0; depth < MAX_ROOT_DEPTH; depth++) {
    let found: { data?: unknown; parentID?: unknown } | null | undefined
    try {
      found = (await ctx.session.get({ sessionID: current })) as { data?: unknown; parentID?: unknown } | null | undefined
    } catch (error) {
      throw new Error('barmkin-opencode: the session lineage lookup failed (' + (error instanceof Error ? error.message : String(error)) + '), so the session\'s taint could not be resolved')
    }
    const info = (found && typeof found === 'object' && 'data' in found && found.data ? found.data : found) as { parentID?: unknown } | null | undefined
    const parent = info && typeof info.parentID === 'string' && info.parentID !== '' ? info.parentID : null
    if (parent === null) break
    current = parent
  }
  rootCache.set(sessionID, current)
  if (mcpTaintReason !== null) markTainted(current, mcpTaintReason)
  return current
}

// ---------------------------------------------------------------------------
// Taint legs.
// ---------------------------------------------------------------------------

function markTainted(root: string, reason: string): void {
  const wasTainted = read(tainted, root)
  update(tainted, root, () => true)
  update(taintReason, root, (current) => current ?? reason)
  if (!wasTainted) emitChanged('taint')
}

// Taints the session and records that only a person's /barmkin-mod-clear-taint
// clears it. The first acknowledgement reason recorded for a session wins.
function markTaintedNeedingAck(root: string, reason: string, ackReason: string): void {
  markTainted(root, reason)
  update(taintAckReason, root, (current) => current ?? ackReason)
}

function markSensitive(root: string, reason: string): void {
  update(sensitiveAccess, root, () => true)
  update(sensitiveReason, root, (current) => current ?? reason)
}

// What a denied call tells the model about getting unblocked. Sticky posture: a
// new message never clears.
function askAgainHint(ackReason: string | null): string {
  return ackReason === null
    ? 'Ask the user to run /barmkin-mod-clear-taint; a new message does not clear this taint.'
    : 'Ask the user to run /barmkin-mod-clear-taint to acknowledge it; a new message does not clear this taint.'
}

function readLegs(root: string): TrifectaLegs {
  return {
    untrusted: read(tainted, root),
    untrustedReason: read(taintReason, root),
    sensitive: read(sensitiveAccess, root),
    sensitiveReason: read(sensitiveReason, root),
    // Always: the posture is sticky (V27), so a message never clears and the denial must say so.
    ackRequired: true,
  }
}

// Clears both legs and returns what they held. The only caller is the command: a
// taint that requires acknowledgement is cleared by the command alone.
function clearTaintLegs(root: string): HeldTaint {
  const held: HeldTaint = {
    tainted: read(tainted, root),
    taintReason: read(taintReason, root),
    sensitive: read(sensitiveAccess, root),
    sensitiveReason: read(sensitiveReason, root),
    ackReason: read(taintAckReason, root),
  }
  update(tainted, root, () => false)
  update(taintReason, root, () => null)
  update(taintAckReason, root, () => null)
  update(sensitiveAccess, root, () => false)
  update(sensitiveReason, root, () => null)
  emitChanged('taint cleared')
  return held
}

// Checks and reserves the taint in one step, so a skill load that fails or is
// denied still leaves the session tainted. Returns the standing reason when the
// session is already tainted (the load is denied), or null once this load holds
// the reservation.
function reserveSkillLoad(root: string, loadReason: string): { standingReason: string | null; ackReason: string | null } | null {
  if (read(tainted, root)) return { standingReason: read(taintReason, root), ackReason: read(taintAckReason, root) }
  update(tainted, root, () => true)
  update(taintReason, root, () => loadReason)
  emitChanged('taint')
  return null
}

// Hidden text the MCP guard stripped from a tool description, schema or server
// instructions. Those are read before any session exists, so a stripped count past
// the threshold taints every session seen so far and, through rootOf, every one
// opened later. Reported once per distinct (where, count): the same unchanged
// catalog does not re-taint a session a person has since cleared.
let mcpTaintReason: string | null = null
const mcpHiddenSeen = new Set<string>()

function onMcpHiddenText(hiddenCount: number, where: string): void {
  if (hiddenCount <= INVISIBLE_CHAR_TAINT_THRESHOLD) return
  const key = where + ':' + hiddenCount
  if (mcpHiddenSeen.has(key)) return
  mcpHiddenSeen.add(key)
  const reason = 'stripped ' + hiddenCount + ' invisible character(s) from ' + where
  mcpTaintReason ??= reason
  for (const root of new Set(rootCache.values())) markTainted(root, reason)
}

// Shared by every scrubInvisible call site: taints the session when a scrub
// stripped more than INVISIBLE_CHAR_TAINT_THRESHOLD characters.
function taintForScrub(root: string, hiddenCount: number, source: string): void {
  if (hiddenCount <= INVISIBLE_CHAR_TAINT_THRESHOLD) return
  markTainted(root, 'stripped ' + hiddenCount + ' invisible character(s) from ' + source)
}

// ---------------------------------------------------------------------------
// Redaction helpers.
// ---------------------------------------------------------------------------

function redactInEitherView(text: string, counters: Record<string, number> = redactionCounters): { text: string; redactedCount: number } {
  return redactInEitherViewLib(text, REDACTION_RULES, counters)
}

// ---------------------------------------------------------------------------
// The egress gate. The normaliser re-keys 2.x calls to the names egress.ts
// classifies on and adds the Code Mode class (`execute` has an unmediated
// `fetch`, V25, so it is denied while the session is tainted: re-scout section 8,
// item 4). The class is added to the lib's, not a change to it.
// ---------------------------------------------------------------------------

// Notes any sensitive access in the calls, classifies them, and decides over the
// trifecta legs. A deny or warn is recorded for the status surface. Never answers allow.
function egressGate(root: string, calls: readonly EgressCall[]): EgressVerdict {
  for (const call of calls) {
    if (touchesSecretPath(call)) markSensitive(root, 'a ' + call.tool + ' call named a credential path')
  }
  const { verdict } = gateEgress(calls, readLegs(root))
  if (verdict.kind !== 'pass') {
    update(lastEgress, root, () => ({
      tool: calls[0]?.tool ?? '',
      classIds: verdict.classIds,
      decision: verdict.kind,
      rule: verdict.kind === 'deny' ? verdict.rule : 'untrusted',
      at: Date.now(),
    }))
  }
  return verdict
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
}

const SHELL_TOOL_IDS = new Set(['shell', 'bash'])
const SUBAGENT_TOOL_IDS = new Set(['subagent', 'task'])
const CODE_MODE_TOOL_IDS = new Set(['execute'])
const WEB_TOOL_IDS = new Set(['webfetch', 'websearch'])
// Tool ids OpenCode 2.0 registers itself; used only when the tool list cannot be read.
const BUILTIN_TOOL_IDS = new Set([
  'shell', 'bash', 'read', 'write', 'edit', 'patch', 'apply_patch', 'glob', 'grep', 'list', 'webfetch', 'websearch',
  'subagent', 'task', 'skill', 'execute', 'todowrite', 'todoread', 'question', 'plan', 'lsp',
])

interface ToolMeta {
  // The MCP server namespace, when the tool is an MCP tool.
  mcpServer: string | null
  // Whether its result is untrusted content to screen.
  screened: boolean
}

const toolNamespaces = new Map<string, string | null>()
let toolListFresh = 0

async function refreshToolList(ctx: PluginContext): Promise<boolean> {
  try {
    const tools = await ctx.tool.list()
    toolNamespaces.clear()
    for (const tool of tools) toolNamespaces.set(tool.id, tool.options?.namespace ?? null)
    toolListFresh = Date.now()
    return true
  } catch {
    return false
  }
}

// MCP tools register with a server namespace (tool/mcp.ts). A tool the list does
// not know is read as MCP unless it is one of OpenCode's own, so a failed lookup
// screens more rather than less.
async function toolMeta(ctx: PluginContext, toolId: string): Promise<ToolMeta> {
  if (!toolNamespaces.has(toolId) && Date.now() - toolListFresh > 2_000) await refreshToolList(ctx)
  const namespace = toolNamespaces.get(toolId)
  if (namespace) return { mcpServer: namespace, screened: true }
  if (namespace === undefined && !BUILTIN_TOOL_IDS.has(toolId)) return { mcpServer: null, screened: true }
  return { mcpServer: null, screened: false }
}

// How the normaliser tells an MCP tool from a built-in: the registry namespace the
// tool list reports, else (for an id the list does not know) anything that is not
// one of OpenCode's own. Mirrors toolMeta without refreshing the list.
function normaliseOptions(): NormaliseOptions {
  return {
    mcpServers: [...new Set([...toolNamespaces.values()].filter((v): v is string => typeof v === 'string' && v !== ''))],
    isMcpTool: (id) => {
      const namespace = toolNamespaces.get(id)
      return namespace ? true : namespace === undefined && !BUILTIN_TOOL_IDS.has(id)
    },
  }
}

// ---------------------------------------------------------------------------
// Jev System One client. Provider-neutral: base_url is always operator config
// pointing at an OpenRouter- or Vercel-AI-Gateway-style endpoint that speaks the
// same /v1/systemone wire format as barmkin's jev.go. Jev only ever tightens a
// verdict (pass -> escalate -> deny); see composeScreen in lib/taint.ts.
// ---------------------------------------------------------------------------

interface JevOptions {
  baseUrl: string
  model: string
  apiKey: string
}

function getJevOptions(options: Readonly<Record<string, any>>): JevOptions {
  const rawBase = typeof options.jev_base_url === 'string' ? options.jev_base_url.trim() : ''
  return {
    baseUrl: rawBase.replace(/\/+$/, ''),
    model: typeof options.jev_model === 'string' && options.jev_model ? options.jev_model : 'jev-1.13.0',
    apiKey: typeof options.jev_api_key === 'string' ? options.jev_api_key : '',
  }
}

// `text` is one window of the redacted payload, so no secret leaves for the
// third-party endpoint. Never throws: every failure path returns { ok: false,
// reason }, which screenContent treats as "classifier unavailable" for that
// window, never as a pass.
async function callJevSystemOne(
  jev: JevOptions,
  text: string,
  questions: Record<string, NoulQuestion>,
): Promise<SystemOneParseResult> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), JEV_TIMEOUT_MS)
  try {
    const body = buildSystemOneRequest(jev.model, { content: text }, questions)
    const response = await fetch(jev.baseUrl + '/v1/systemone', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(jev.apiKey ? { Authorization: 'Bearer ' + jev.apiKey } : {}),
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    })
    if (!response.ok) return { ok: false, reason: 'http_' + response.status }
    let parsed: unknown
    try {
      parsed = JSON.parse(await response.text())
    } catch {
      return { ok: false, reason: 'malformed_response: not JSON' }
    }
    return parseSystemOneResponse(parsed, Object.keys(questions), JEV_MODEL_PATTERN)
  } catch (error) {
    return { ok: false, reason: controller.signal.aborted ? 'timeout' : 'network: ' + String(error) }
  } finally {
    clearTimeout(timer)
  }
}

// A failure worth one more try: the endpoint was slow, unreachable, rate limited
// or erroring. A malformed or refused answer would fail the same way.
function isTransient(reason: string): boolean {
  return reason === 'timeout' || reason.startsWith('network') || reason === 'http_429' || /^http_5\d\d$/.test(reason)
}

// Asks every window at once, then once more for each window that failed for a
// transient reason. Each call is bounded by JEV_TIMEOUT_MS.
async function classifyWindows(jev: JevOptions, text: string, windows: { start: number; end: number }[]): Promise<SystemOneParseResult[]> {
  const results = await Promise.all(windows.map((w) => callJevSystemOne(jev, text.slice(w.start, w.end), PRODUCTION_QUESTIONS)))
  await Promise.all(
    results.map(async (r, i) => {
      if (r.ok || !isTransient(r.reason)) return
      results[i] = await callJevSystemOne(jev, text.slice(windows[i].start, windows[i].end), PRODUCTION_QUESTIONS)
    }),
  )
  return results
}

// The four-question shadow screen: every window, once per wording arm, in
// parallel with the production calls. No retry. Results are indexed by arm, then window.
async function classifyShadowWindows(jev: JevOptions, text: string, windows: { start: number; end: number }[]): Promise<SystemOneParseResult[][]> {
  return Promise.all(
    SHADOW_ARMS.map((arm: ShadowArm) =>
      Promise.all(windows.map((w) => callJevSystemOne(jev, text.slice(w.start, w.end), shadowQuestions(arm)))),
    ),
  )
}

function recordBreakerFailure(root: string): void {
  const failures = update(breakerFailureCount, root, (n) => n + 1)
  if (failures >= BREAKER_FAILURE_THRESHOLD) update(breakerOpenUntil, root, () => Date.now() + BREAKER_COOLDOWN_MS)
}

function describeShadowArm(record: ShadowArmRecord): string {
  const windows = record.answered + '/' + record.windows + ' windows'
  if (record.answered === 0) return '[' + record.arm + '] no window answered (' + windows + ')'
  return '[' + record.arm + '] ' + windows + ': ' + SCREEN_QUESTION_IDS.map((id) => id + '=' + (record.scores[id] ?? 0).toFixed(2)).join(' ')
}

// Records what the shadow screen answered and counts one shadow breaker event for
// the whole screen. Annotation only: nothing here taints, withholds or marks a leg.
function recordShadow(root: string, label: string, callId: string | undefined, results: SystemOneParseResult[][]): void {
  const arms: ShadowArmRecord[] = SHADOW_ARMS.map((arm: ShadowArm, i: number) => {
    const merged = mergeWindowAnswers(results[i], SCREEN_QUESTION_IDS)
    return {
      arm,
      answered: merged === null ? 0 : merged.answered,
      windows: results[i].length,
      model: merged === null ? null : merged.model,
      scores: merged === null ? {} : merged.answers,
    }
  })
  if (results.every((armResults) => armResults.every((r) => r.ok))) {
    update(shadowBreakerFailureCount, root, () => 0)
  } else {
    const failures = update(shadowBreakerFailureCount, root, (n) => n + 1)
    if (failures >= BREAKER_FAILURE_THRESHOLD) update(shadowBreakerOpenUntil, root, () => Date.now() + BREAKER_COOLDOWN_MS)
  }
  update(lastShadow, root, () => ({ toolUseId: callId ?? '', label, arms, at: Date.now() }))
  debugLog('barmkin-opencode: shadow screen for ' + label + ': ' + arms.map(describeShadowArm).join(' | '))
}

// Screens one piece of untrusted content (a fetched page, an MCP result, a file
// read from outside cwd, a subagent's result, a skill body) and, as a side
// effect, updates the taint and verdict state. The same composition as
// register.ts's screenContent, over the 2.x state above.
async function screenContent(root: string, text: string, label: string, callId: string | undefined): Promise<ScreenOutcome> {
  const raw = text
  if (exceedsScreenedLimit(raw)) {
    return {
      decision: 'deny',
      tainted: false,
      reason: SCREENED_LIMIT_REASON,
      question: 'injection',
      probability: 0,
      model: 'heuristic',
      scores: { injection: 0, credentials: 0 },
      withholdReason: SCREENED_LIMIT_REASON,
    }
  }
  text = scrubInvisible(raw).text
  const jev = getJevOptions(pluginOptions)
  const now = Date.now()
  const canUseJev = jev.baseUrl !== '' && read(breakerOpenUntil, root) <= now

  const local: ScoreSource = {
    model: 'heuristic',
    injection: heuristicInjectionScore(text),
    credentials: containsSecretInEitherView(raw, REDACTION_RULES) ? 0.9 : 0,
  }

  // What the classifier would be sent, cut into its windows. Computed whenever Jev
  // is configured (even with the breaker open) to tell how much was classified.
  const jevInput = jev.baseUrl !== '' ? classifierInput(raw, REDACTION_RULES, {}) : null
  const plan = jevInput === null ? null : planWindows(jevInput)
  let results: (SystemOneParseResult | null)[] = plan ? plan.windows.map(() => null) : []

  if (canUseJev && plan && jevInput !== null) {
    // The shadow screen asks the same windows its own questions, in parallel with
    // the production calls. Its own breaker gates it, and nothing it returns
    // reaches the decision below.
    const shadowOpen = read(shadowBreakerOpenUntil, root) > now
    const [production, shadow] = await Promise.all([
      classifyWindows(jev, jevInput, plan.windows),
      shadowOpen ? Promise.resolve(null) : classifyShadowWindows(jev, jevInput, plan.windows),
    ])
    results = production
    // One breaker event per screen, however many windows it took.
    if (results.every((r) => r?.ok)) update(breakerFailureCount, root, () => 0)
    else recordBreakerFailure(root)
    if (shadow !== null) {
      try {
        recordShadow(root, label, callId, shadow)
      } catch {
        // The shadow screen is annotation only; it never fails the real one.
      }
    }
  }

  const screened = composeScreen(local, mergeWindowScores(results))
  // A withheld (deny) result never reaches the model, so only content that does
  // is held to what the classifier read.
  const unclassified =
    plan && jevInput !== null ? unclassifiedChars(jevInput.length, plan.windows, results.map((r) => r?.ok === true)) : 0
  const gap =
    screened.decision === 'deny' ? null : classifierGapReason(jev.baseUrl !== '', jevInput === null ? null : jevInput.length, unclassified)
  const composed: ScreenOutcome = gap
    ? { ...screened, tainted: true, decision: 'escalate', reason: screened.tainted ? screened.reason : gap }
    : screened

  update(lastVerdict, root, () => ({
    toolUseId: callId ?? '',
    question: label + ' (' + composed.question + ')',
    probability: composed.probability,
    decision: composed.decision,
    model: composed.model,
    at: now,
  }))

  if (gap) markTaintedNeedingAck(root, composed.reason, gap)
  else if (composed.tainted) markTainted(root, composed.reason)
  // Leg B follows the credentials score itself, not the question that drove the
  // decision: content that scores on injection and on credentials leaks the
  // secret all the same.
  if (screened.scores.credentials >= DEFAULT_TAINT_THRESHOLDS.taintAt) {
    markSensitive(root, credentialScoreReason(screened.scores.credentials))
  }
  return composed
}

// What a withheld untrusted result tells the model. A withhold for size alone is
// not a danger, so it points to paging; any other reason sends the model back to
// the person.
function withheldMessage(what: string, reason: string): string {
  return 'barmkin-opencode: withheld ' + what + ' (' + reason + '). ' + (reason === SCREENED_LIMIT_REASON ? PAGING_ADVICE : 'Ask the user before retrying.')
}

// ---------------------------------------------------------------------------
// tool.execute.before: the early refusal. Every deny is a throw.
// ---------------------------------------------------------------------------

// Calls awaiting their after hook: a warn to append, and shell calls in flight
// (shell.create.before carries no session, so it reads these).
const pendingWarnings = new Map<string, string>()
const shellInFlight = new Map<string, string>()
const MAX_TRACKED_CALLS = 256

function track<T>(map: Map<string, T>, key: string, value: T): void {
  map.set(key, value)
  if (map.size > MAX_TRACKED_CALLS) {
    const oldest = map.keys().next().value
    if (oldest !== undefined) map.delete(oldest)
  }
}

// Withholds an after event's result, or throws when the event cannot be edited
// (a frozen error message): a result the guard could not replace must not be
// delivered, and a throw after the tool ran reaches the model as an error (V22).
function withhold(e: ToolAfterEvent, message: string): void {
  if (!withholdAfterEvent(e, message)) throw new Error('barmkin-opencode: the result could not be withheld')
}

// A refusal this file decided on, as opposed to a bug in the guard itself: it is
// rethrown as is, where anything else becomes a fail-closed refusal.
class GuardDeny extends Error {}

function guardFailure(what: string, error: unknown): Error {
  return new Error('barmkin-opencode: the ' + what + ' failed (' + (error instanceof Error ? error.message : String(error)) + '), so this call was not run')
}

async function toolBefore(ctx: PluginContext, e: ToolBeforeEvent): Promise<void> {
  try {
    const root = await rootOf(ctx, e.sessionID)
    const meta = await toolMeta(ctx, e.tool)

    // MCP server allowlist.
    if (meta.mcpServer !== null) {
      if (!isServerAllowed(meta.mcpServer, parseAllowlist(pluginOptions.mcp_server_allowlist))) {
        throw new GuardDeny('barmkin-opencode: MCP server "' + meta.mcpServer + '" is not on the allowlist')
      }
    }

    // Subagent spawn gate.
    if (SUBAGENT_TOOL_IDS.has(e.tool) && read(tainted, root)) {
      throw new GuardDeny(
        'barmkin-opencode: subagent spawn blocked while this session is tainted (' +
          (read(taintReason, root) ?? 'unspecified') +
          '). ' +
          askAgainHint(read(taintAckReason, root)),
      )
    }

    // Skill-tool taint gate: a loaded skill is untrusted content in its own right.
    if (e.tool === 'skill') {
      const id = typeof asRecord(e.input).id === 'string' ? (asRecord(e.input).id as string) : 'unnamed'
      const standing = reserveSkillLoad(root, 'skill "' + id + '" was loaded')
      if (standing) {
        update(lastEgress, root, () => ({ tool: 'skill', classIds: ['skill-load'], decision: 'deny' as const, rule: 'untrusted', at: Date.now() }))
        throw new GuardDeny(
          'barmkin-opencode: loading a skill is blocked while this session is handling untrusted content (' +
            (standing.standingReason ?? 'unspecified') +
            '). ' +
            askAgainHint(standing.ackReason),
        )
      }
    }

    // Egress gate over the call as the model proposed it. The final command, URL
    // or path is rechecked at permission time.
    const verdict = egressGate(root, normaliseEgressCalls(e.tool, e.input, normaliseOptions()))
    if (verdict.kind === 'deny') throw new GuardDeny(verdict.message)
    if (verdict.kind === 'warn') track(pendingWarnings, e.id, verdict.message)
    if (SHELL_TOOL_IDS.has(e.tool)) track(shellInFlight, e.id, root)
  } catch (error) {
    if (error instanceof GuardDeny) throw error
    throw guardFailure('egress guard', error)
  }
}

// ---------------------------------------------------------------------------
// permission.evaluate: the final recheck, against the final command, URL or path
// after every other plugin's rewrite (V5-V9). Deny = throw, never `effect = "deny"`.
// ---------------------------------------------------------------------------

async function permissionEvaluate(ctx: PluginContext, e: PermissionEvaluation): Promise<void> {
  try {
    const root = await rootOf(ctx, e.sessionID)
    // The final action and resources after every other plugin's rewrite. An
    // action with no resources the normaliser can read (Code Mode `execute`, an
    // MCP tool) classifies on its name alone.
    const verdict = egressGate(root, normaliseEvaluate(e.action, e.resources, normaliseOptions()))
    if (verdict.kind === 'deny') throw new GuardDeny(verdict.message)
  } catch (error) {
    if (error instanceof GuardDeny) throw error
    throw new Error(
      'barmkin-opencode: the permission-time egress guard failed (' + (error instanceof Error ? error.message : String(error)) + '), so this call was not run',
    )
  }
}

// ---------------------------------------------------------------------------
// shell.create.before: the shell layer, after every tool hook. The event carries
// no session, so it is checked against the sessions with a shell tool call in
// flight; a shell no tool call started (a person's own `!` command) is left alone.
// permission.evaluate rechecks the same command with its session.
// ---------------------------------------------------------------------------

function shellCreateBefore(e: ShellCreateBefore): void {
  const roots = new Set(shellInFlight.values())
  if (roots.size === 0) return
  const calls = normaliseEgressCalls('shell', { command: e.command })
  try {
    for (const root of roots) {
      const verdict = egressGate(root, calls)
      if (verdict.kind === 'deny') throw new GuardDeny(verdict.message)
    }
  } catch (error) {
    if (error instanceof GuardDeny) throw error
    throw new Error('barmkin-opencode: the shell guard failed (' + (error instanceof Error ? error.message : String(error)) + '), so this command was not run')
  }
}

// ---------------------------------------------------------------------------
// tool.execute.after: screens, then redaction last, so redaction sees whatever an
// earlier step added. Fires on errors too (V21). A throw here reports an error
// after the command already ran (V22), so a failure first tries to withhold.
// ---------------------------------------------------------------------------

async function toolAfter(ctx: PluginContext, e: ToolAfterEvent): Promise<void> {
  shellInFlight.delete(e.id)
  const warning = pendingWarnings.get(e.id)
  pendingWarnings.delete(e.id)
  try {
    const root = await rootOf(ctx, e.sessionID)
    const meta = await toolMeta(ctx, e.tool)
    const payload = e.status === 'completed' ? e.result : e.error

    const withheld = await screenAfterResult(root, e, meta)
    if (withheld) return
    if (warning !== undefined && e.status === 'completed') noticeAfterEvent(e, warning)

    // Over the budget: a result nothing can scan whole is withheld, with the
    // limits of an untrusted surface where a screen covers the tool.
    const size = measureResult(payload, meta.screened)
    if (size !== 'within') {
      withhold(e, 'barmkin-opencode: this tool result is larger than the redaction scan budget, so it was withheld. ' + PAGING_ADVICE)
      return
    }

    let hiddenCount = 0
    let redactionHits = 0
    const redactValue = (value: string): string => {
      const scrubbed = scrubInvisible(value)
      hiddenCount += scrubbed.hiddenCount
      const { text: redacted, redactedCount } = redactInEitherView(value)
      redactionHits += redactedCount
      if (redactedCount === 0 && scrubbed.strippedCount === 0) return value
      return redacted
    }
    redactAfterEvent(e, redactValue)

    // A redaction hit means a credential-shaped value just passed through this
    // session: leg B of the trifecta.
    if (redactionHits > 0) markSensitive(root, 'a ' + (meta.mcpServer ? 'tool' : e.tool) + ' result held a credential-shaped value')
    taintForScrub(root, hiddenCount, 'tool:' + (meta.mcpServer ? 'mcp' : e.tool))
  } catch (error) {
    try {
      withhold(e, 'barmkin-opencode: the result guard failed (' + (error instanceof Error ? error.message : String(error)) + '); the result was withheld to avoid leaking an unredacted secret or untrusted content')
    } catch {
      throw new Error('barmkin-opencode: the result guard failed, so the result was not delivered')
    }
  }
}

// Whether the tool's result is untrusted content, and so is screened.
function screenLabelFor(toolId: string, meta: ToolMeta, input: unknown): string | null {
  if (meta.mcpServer !== null) return 'mcp:' + meta.mcpServer
  if (meta.screened) return 'mcp:' + toolId
  if (WEB_TOOL_IDS.has(toolId)) return 'fetch:' + toolId
  if (SUBAGENT_TOOL_IDS.has(toolId)) return 'subagent'
  if (CODE_MODE_TOOL_IDS.has(toolId)) return 'codemode'
  if (toolId === 'read') {
    const path = asRecord(input).path
    return typeof path === 'string' && isOutsideCwd(path, projectDirectory) ? 'read:' + path : null
  }
  return null
}

// Screens a completed or error result and a skill body. Returns true when the result was
// withheld, in which case nothing else is done to it.
async function screenAfterResult(root: string, e: ToolAfterEvent, meta: ToolMeta): Promise<boolean> {
  if (e.tool === 'skill') {
    const text = afterEventText(e)
    if (!text) return false
    const id = typeof asRecord(e.input).id === 'string' ? (asRecord(e.input).id as string) : 'unnamed'
    taintForScrub(root, scrubInvisible(text).hiddenCount, 'a skill body')
    const verdict = await screenContent(root, text, 'skill:' + id, e.id)
    if (verdict.decision === 'deny') {
      withhold(e, skillBodyWithheldText(verdict.withholdReason))
      return true
    }
    if (verdict.tainted) noticeAfterEvent(e, UNTRUSTED_CONTENT_WARNING)
    return false
  }

  const label = screenLabelFor(e.tool, meta, e.input)
  if (label === null) return false
  const text = afterEventText(e)
  if (!text) return false
  const verdict = await screenContent(root, text, label, e.id)
  if (verdict.decision === 'deny') {
    withhold(e, withheldMessage('this result', verdict.withholdReason))
    return true
  }
  if (verdict.tainted) noticeAfterEvent(e, UNTRUSTED_CONTENT_WARNING)
  return false
}

// ---------------------------------------------------------------------------
// session.prompt: redact what the person pasted. Refusing the turn is a throw
// (V26). No origin is available (V27), so a prompt never clears the taint.
// ---------------------------------------------------------------------------

function sessionPrompt(e: SessionPromptEvent): void {
  const text = promptText(e as SessionPromptShape)
  if (exceedsScreenedLimit(text)) {
    throw new Error('barmkin-opencode: your message is longer than the 16 KiB scan limit, so it was withheld')
  }
  let redactedCount = 0
  let withheld = false
  mapPromptStrings(e as SessionPromptShape, (value) => {
    const result = redactInEitherView(value, {})
    redactedCount += result.redactedCount
    if (result.text === WITHHELD_TEXT) withheld = true
    return result.redactedCount === 0 ? value : result.text
  })
  if (withheld) throw new Error('barmkin-opencode: your message could not be fully scanned after redaction, so it was withheld')
  if (redactedCount > 0) debugLog('barmkin-opencode: redacted ' + redactedCount + ' likely secret(s) from your message before sending it')
}

// ---------------------------------------------------------------------------
// The model boundary: session.context (before each primary request), title,
// compaction and generate. The raw copy of a prompt-borne or background-shell
// secret is removed from every request, side calls included (V28, V30). Skill
// listings and MCP catalog text are neutralised here too (V23, V31).
// ---------------------------------------------------------------------------

// The skill listing renders `<skill><id>..</id><name>..</name><description>..</description></skill>`
// (core skill/instructions.ts). Each entry goes through the lib's `- name: description`
// neutraliser alone, so an entry cannot reach into its neighbour.
const SKILL_ENTRY = /<skill>\s*<id>([\s\S]*?)<\/id>\s*<name>([\s\S]*?)<\/name>\s*<description>([\s\S]*?)<\/description>\s*<\/skill>/g

function neutralizeSkillListingXml(text: string): string {
  if (!text.includes('<skill>')) return text
  return text.replace(SKILL_ENTRY, (entry: string, id: string, name: string, description: string) => {
    const { text: neutralised, withheld } = neutralizeSkillListing('- ' + name + ': ' + scrubInvisible(description).text)
    if (withheld > 0) return ''
    const prefix = '- ' + name + ': '
    if (!neutralised.startsWith(prefix)) return ''
    const cleaned = neutralised.slice(prefix.length)
    return cleaned === description ? entry : '<skill><id>' + id + '</id><name>' + name + '</name><description>' + cleaned + '</description></skill>'
  })
}

function boundaryRewriter(root: string): (value: string) => string {
  const counters: Record<string, number> = {}
  return (value) => {
    const scrubbed = scrubInvisible(value)
    taintForScrub(root, scrubbed.hiddenCount, 'the model request')
    const { text, redactedCount } = redactInEitherView(value, counters)
    const redacted = redactedCount === 0 && scrubbed.strippedCount === 0 ? value : text
    return neutralizeSkillListingXml(redacted)
  }
}

async function modelBoundary(ctx: PluginContext, surface: 'context' | 'compaction' | 'generate' | 'title', e: SessionRequestEvent): Promise<void> {
  let root: string
  try {
    root = await rootOf(ctx, e.sessionID)
  } catch (error) {
    throw new Error('barmkin-opencode: the ' + surface + ' request was not sent (' + (error instanceof Error ? error.message : String(error)) + ')')
  }
  const rewrite = boundaryRewriter(root)
  mapRequestStrings(e as SessionContextShape, rewrite)
  if (surface === 'title') return
  // Tool descriptions are the model's too; a result an earlier plugin set on a
  // compaction enters history without passing the context hook.
  mapToolDescriptions((e as SessionContextShape).tools, rewrite, false)
  if (surface === 'compaction') mapCompactionResult(e as SessionCompactionShape, rewrite)
}

// ---------------------------------------------------------------------------
// Commands, the status channel and the posture line.
// ---------------------------------------------------------------------------

export interface Seat {
  inventory: 'ok' | 'unavailable'
  // The seat this guard runs from, as far as the inventory and environment show.
  name: 'inline-config' | 'file-or-package' | 'unverified'
  inlineSeated: boolean
  projectConfigDisabled: boolean
  others: string[]
  failed: string[]
}

let seat: Seat = { inventory: 'unavailable', name: 'unverified', inlineSeated: false, projectConfigDisabled: false, others: [], failed: [] }
let postureLines: string[] = []

function envFlag(name: string): boolean {
  const value = process.env[name]
  return value === '1' || value === 'true'
}

// The plugin-inventory probe (re-scout section 4: seat detection comes from the
// inventory, not from guessing). `plugin.list()` returns every plugin entry with
// its source and state; the environment says whether this guard is the inline-config
// plugin and whether project config is off.
async function probeSeat(ctx: PluginContext): Promise<Seat> {
  const projectConfigDisabled = envFlag('OPENCODE_DISABLE_PROJECT_CONFIG')
  const inlineConfig = process.env.OPENCODE_CONFIG_CONTENT ?? ''
  try {
    let timer: ReturnType<typeof setTimeout> | undefined
    const listed = await Promise.race([
      ctx.plugin.list(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('timeout')), INVENTORY_TIMEOUT_MS)
      }),
    ]).finally(() => clearTimeout(timer))
    const raw = (listed as { data?: unknown } | null)?.data ?? listed
    const entries = (Array.isArray(raw) ? raw : []) as PluginInfo[]
    const own = entries.find((p) => p.id === PLUGIN_ID)
    const ownTarget = own?.source.path ?? own?.source.target
    const inlineSeated =
      inlineConfig !== '' && (inlineConfig.includes(PLUGIN_ID) || (ownTarget !== undefined && inlineConfig.includes(ownTarget)))
    const nameOf = (p: PluginInfo): string => p.id ?? p.source.path ?? p.source.target ?? '(unnamed)'
    const others = entries.filter((p) => p !== own && p.source.type !== 'builtin').map(nameOf)
    const failed = entries.filter((p) => p.state.status === 'failed').map(nameOf)
    return { inventory: 'ok', name: inlineSeated ? 'inline-config' : 'file-or-package', inlineSeated, projectConfigDisabled, others, failed }
  } catch {
    return {
      inventory: 'unavailable',
      name: 'unverified',
      inlineSeated: inlineConfig.includes(PLUGIN_ID),
      projectConfigDisabled,
      others: [],
      failed: [],
    }
  }
}

// The per-seat gaps for the posture line's `not covered:` clause.
function notCovered(s: Seat): string[] {
  const gaps = [
    'secrets already in stored transcripts and shell output files',
    'MCP tool arguments, Code Mode fetch and command-template shell',
    'taint cleared only by a person running /barmkin-mod-clear-taint, never by a message',
    'any session where this guard is not loaded',
  ]
  if (!mcpDescriptionGuard) gaps.push('MCP tool descriptions')
  if (s.others.length > 0) gaps.push('plugins loaded beside this guard')
  return gaps
}

// The posture line is shipping text (CONTRACT.md "Posture line"): the first line
// is verbatim, the conditional lines are the re-scout section 2.2 wording, one per
// condition. The seat is named inside `not covered:`.
export function buildPostureLines(s: Seat, coreSha: string = CORE_SHA): string[] {
  const seatText = s.name === 'inline-config' ? 'seat "inline-config" is user-owned, not administrator-enforced' : s.name === 'file-or-package' ? 'seat "file-or-package" is user-owned, not administrator-enforced' : 'seat unverified'
  const lines = [
    '\u{1F3F0} barmkin-opencode ' +
      PLUGIN_VERSION +
      ' (core ' +
      coreSha +
      ') · partial port, not equivalent to barmkin-mod for Claude Code · OpenCode 2 has no administrator-locked plugin seat · not covered: ' +
      [seatText, ...notCovered(s)].join('; '),
  ]
  if (!s.inlineSeated && !s.projectConfigDisabled) {
    lines.push(
      "\u{1F3F0} barmkin-opencode: a repository's opencode.json can unload this guard unless project config is disabled or the guard is seated through OPENCODE_CONFIG_CONTENT.",
    )
  }
  if (s.others.length > 0 && !s.inlineSeated) {
    lines.push(
      '\u{1F3F0} barmkin-opencode: a later plugin can re-insert what the guard redacted; the inline-config seat or a plugin allowlist closes this (loaded beside the guard: ' +
        s.others.join(', ') +
        ').',
    )
  }
  if (s.failed.length > 0) lines.push('\u{1F3F0} barmkin-opencode: plugin(s) failed to load: ' + s.failed.join(', ') + '.')
  if (s.inventory === 'unavailable') lines.push('\u{1F3F0} barmkin-opencode: the plugin inventory could not be read, so the seat is unverified.')
  return lines
}

async function say(ctx: PluginContext, sessionID: string, text: string): Promise<void> {
  try {
    await ctx.session.synthetic({ sessionID, text, description: PLUGIN_ID, resume: false })
  } catch (error) {
    debugLog('barmkin-opencode: could not post to session ' + sessionID + ': ' + String(error))
  }
}

// The server-to-TUI channel (re-scout V34-V36; src/status-rpc): the TUI module
// calls `status` with no session, so taint is reported across every session this
// process has seen: tainted when any root is.
function statusReport(): StatusReport {
  const roots = [...new Set(rootCache.values())]
  const taintedRoot = roots.find((root) => read(tainted, root))
  const sensitiveRoot = roots.find((root) => read(sensitiveAccess, root))
  const reason = taintedRoot === undefined ? null : read(taintReason, taintedRoot)
  return {
    version: PLUGIN_VERSION,
    postureLine: postureLines[0] ?? '',
    conditionalLines: postureLines.slice(1),
    seat: {
      kind: seat.name,
      label: seat.name === 'unverified' ? 'unverified' : seat.name === 'inline-config' ? 'inline config' : 'file or package',
      repoCanUnload: !seat.inlineSeated && !seat.projectConfigDisabled,
    },
    taint: {
      tainted: taintedRoot !== undefined,
      sensitive: sensitiveRoot !== undefined,
      ...(reason !== null ? { reason } : {}),
    },
    ...(mcpGuard !== null ? { mcp: mcpGuard.status() } : {}),
  }
}

async function installOptional(ctx: PluginContext): Promise<void> {
  try {
    // Never throws inside a transform (V19).
    await ctx.command.transform((editor) => {
      try {
        editor.add({
          name: 'barmkin-mod-clear-taint',
          description: 'Clear the barmkin-opencode taint and sensitive-access flags and re-enable egress',
          execute: async (input) => {
            const root = await rootOf(ctx, input.sessionID)
            const held = clearTaintLegs(root)
            await say(ctx, input.sessionID, describeTaintClear(TAINT_POSTURE, held).replace('barmkin-mod:', 'barmkin-opencode:'))
          },
        })
      } catch (error) {
        debugLog('barmkin-opencode: could not add commands: ' + String(error))
      }
    })
  } catch (error) {
    debugLog('barmkin-opencode: command registration failed: ' + String(error))
  }
  try {
    const registration = (await ctx.rpc.register(statusRpc, { status: async () => statusReport() })) as {
      events?: { emit?: (name: 'changed', payload: { reason: string }) => Promise<void> }
    } | null
    const emit = registration?.events?.emit
    if (typeof emit === 'function') {
      emitChanged = (reason) => {
        emit.call(registration!.events, 'changed', { reason }).catch((error: unknown) => debugLog('barmkin-opencode: status event failed: ' + String(error)))
      }
    }
  } catch (error) {
    debugLog('barmkin-opencode: rpc registration failed: ' + String(error))
  }
}

// Emits the posture line once the inventory is readable. Deferred: the inventory
// may wait on plugin activation, and setup must not.
function startPostureProbe(ctx: PluginContext): void {
  void probeSeat(ctx).then((probed) => {
    seat = probed
    refreshMcpDescriptionGuard()
    postureLines = buildPostureLines(seat)
    for (const line of postureLines) console.error(line)
    emitChanged('seat')
  })
}

// ---------------------------------------------------------------------------
// The plugin.
// ---------------------------------------------------------------------------

export default {
  id: PLUGIN_ID,
  setup: async (ctx: PluginContext) => {
    pluginOptions = ctx.options ?? {}
    projectDirectory = ctx.location?.directory ?? ''
    postureLines = buildPostureLines(seat)

    // Guards. A registration that fails here throws out of setup, which OpenCode
    // reports as a failed plugin; nothing is half-registered silently.
    await ctx.tool.hook('execute.before', (e) => toolBefore(ctx, e))
    await ctx.permission.hook('evaluate', (e) => permissionEvaluate(ctx, e))
    await ctx.shell.hook('create.before', (e) => shellCreateBefore(e))
    await ctx.tool.hook('execute.after', (e) => toolAfter(ctx, e))
    await ctx.session.hook('prompt', (e) => sessionPrompt(e))
    await ctx.session.hook('context', (e) => modelBoundary(ctx, 'context', e))
    await ctx.session.hook('title', (e) => modelBoundary(ctx, 'title', e))
    await ctx.session.hook('compaction', (e) => modelBoundary(ctx, 'compaction', e))
    await ctx.session.hook('generate', (e) => modelBoundary(ctx, 'generate', e))

    // The MCP description neutraliser (src/mcp-guard). It registers its own
    // transforms and a second, allowlist-only before/evaluate/context hook, and it
    // never throws: a failed install shows in healthy() and leaves the posture line
    // naming MCP tool descriptions as not covered.
    mcpGuard = await installMcpGuard(ctx as unknown as McpGuardHost, {
      allowlist: ctx.options?.mcp_server_allowlist,
      onHiddenText: onMcpHiddenText,
    })
    refreshMcpDescriptionGuard()
    postureLines = buildPostureLines(seat)

    await installOptional(ctx)
    startPostureProbe(ctx)
  },
}
