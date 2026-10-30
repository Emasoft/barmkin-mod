// Pure logic for the switch registry: one named switch per security function
// this mod has, each on by default (the behaviour the mod had before switches
// existed). No `$` use here: register.ts reads the switches from $.state, keeps
// them in $.store, and asks each gate whether its switch is on.
//
// What "off" means is fixed per switch in `whenOff` below: the check that switch
// names does not run. Off never turns into an allow: a gate that is off returns
// what the rest of the chain decided, so a deny from another guard still stands.

export const SWITCH_DEFS = [
  // Gates over tool calls.
  {
    id: 'egress-gate',
    description: 'Egress gate: outward-effect calls (shell, network, web, MCP writes, persistence writes) are denied or warned on by taint and Rule of Two',
    whenOff: 'no egress class is checked, except the destructive tier, which has its own switch',
  },
  {
    id: 'destructive-tier',
    description: 'Destructive and history-rewrite tier: rm -rf of roots, home or secret paths, disk wipes and git history rewrites warn, and deny while tainted',
    whenOff: 'the destructive and history-rewrite classes are not checked',
  },
  // The untrusted-content taint and each of its effects.
  {
    id: 'taint',
    description: 'Untrusted-content taint: screened content that scores as injection, a skill load or hidden text marks the session tainted',
    whenOff: 'nothing marks the session tainted, and a taint already held is ignored by every gate',
  },
  {
    id: 'taint-blocks-egress',
    description: 'While tainted, each egress class keeps its posture (deny or warn), and a skill load is refused',
    whenOff: 'a taint alone changes no egress decision; the destructive tier warns as on a clean session',
  },
  {
    id: 'rule-of-two',
    description: 'Rule of Two: tainted plus sensitive access denies every egress class',
    whenOff: 'sensitive access never escalates an egress decision',
  },
  {
    id: 'skill-load-taints',
    description: 'Every Skill tool load taints the session',
    whenOff: 'a skill load does not taint the session',
  },
  {
    id: 'spawn-blocked-when-tainted',
    description: 'A subagent spawn is refused while the session is tainted',
    whenOff: 'subagents spawn whatever the taint',
  },
  {
    id: 'classifier-gap-needs-ack',
    description: 'Content Jev could not fully read taints until a person runs /barmkin-mod-clear-taint',
    whenOff: 'such content taints like any screen hit, and a message clears it',
  },
  {
    id: 'outside-cwd-read-taints',
    description: 'A Read of a file outside the working directory is screened as untrusted content',
    whenOff: 'reads outside the working directory are not screened',
  },
  {
    id: 'heuristic-only-taint',
    description: 'The local injection heuristics can taint without a Jev score',
    whenOff: 'only a Jev score taints on the injection question',
  },
  {
    id: 'consume-own-notifications',
    description: 'Task notifications and scheduled triggers are screened like peer messages, and can be withheld',
    whenOff: 'task notifications and scheduled triggers are delivered unscreened',
  },
  // Content screens.
  {
    id: 'jev-screening',
    description: 'Jev System One screens untrusted content (needs OPENROUTER_API_KEY)',
    whenOff: 'only the local heuristics screen; no classifier request is sent',
  },
  {
    id: 'shadow-screen',
    description: 'Shadow questions asked beside the real screen, for contrast only',
    whenOff: 'no shadow request is sent',
  },
  {
    id: 'web-screen',
    description: 'WebFetch and WebSearch results are screened for injection',
    whenOff: 'web results are not screened',
  },
  {
    id: 'mcp-guard',
    description: 'MCP guard: server allowlist, description hardening and MCP result screening',
    whenOff: 'no MCP allowlist, description hardening or result screening',
  },
  {
    id: 'skill-guard',
    description: 'Skill body and skill listing screens',
    whenOff: 'skill bodies and the skill listing are not screened',
  },
  {
    id: 'skill-shell-mediation',
    description: "A skill's inline shell may not run outward-effect commands or read credential paths",
    whenOff: 'inline skill shell is left to the permission layer',
  },
  {
    id: 'a2a-firewall',
    description: 'Agent-to-agent firewall: inbound messages are screened and withheld on a hit or over 16 KiB',
    whenOff: 'inbound messages are delivered unscreened',
  },
  {
    id: 'a2a-outbound',
    description: 'Outbound agent messages over 16 KiB or holding a secret are not sent',
    whenOff: 'outbound messages are sent unchecked',
  },
  {
    id: 'redaction',
    description: 'Secret redaction in tool results and prompts, with the scan-size limits',
    whenOff: 'tool results, prompts and skill bodies pass unredacted and unscrubbed, nothing is withheld for size, and a credential in a result no longer counts as sensitive access',
  },
  {
    id: 'posture-check',
    description: 'Session-start check of version, seating, bypass mode, sandbox, skill shell and MCP allowlist',
    whenOff: 'no posture line is shown at session start',
  },
  {
    id: 'self-protection',
    description: "Self-protection: this mod's switch store, install and marketplace folders, settings entries and uninstall are guarded",
    whenOff: 'those calls are not checked, and an edited switch store is accepted',
  },
] as const

export type SwitchId = (typeof SWITCH_DEFS)[number]['id']
export type SwitchMap = Record<SwitchId, boolean>

export const SWITCH_IDS: readonly SwitchId[] = SWITCH_DEFS.map((d) => d.id)

// The $.store key that holds the switches, and the version of its value.
export const SWITCH_STORE_KEY = 'switches'
export const SWITCH_STORE_VERSION = 1

export function isSwitchId(value: unknown): value is SwitchId {
  return typeof value === 'string' && (SWITCH_IDS as readonly string[]).includes(value)
}

export function defaultSwitches(): SwitchMap {
  return Object.fromEntries(SWITCH_IDS.map((id) => [id, true])) as SwitchMap
}

// Reads a stored value into a full map. Why every unreadable part reads as on:
// the default is the behaviour the mod had before switches, so a missing,
// malformed or unknown entry can only leave a protection running.
export function normalizeSwitches(raw: unknown): SwitchMap {
  const map = defaultSwitches()
  const stored = raw && typeof raw === 'object' ? (raw as { switches?: unknown }).switches : undefined
  if (!stored || typeof stored !== 'object' || Array.isArray(stored)) return map
  for (const id of SWITCH_IDS) {
    const value = (stored as Record<string, unknown>)[id]
    if (typeof value === 'boolean') map[id] = value
  }
  return map
}

// The value written to $.store: plain JSON, so what `$.store.get` reads back is
// the same object and its fingerprint matches the one recorded at write time.
export function toStoreValue(map: SwitchMap): { version: number; switches: Record<string, boolean> } {
  const switches: Record<string, boolean> = {}
  for (const id of SWITCH_IDS) switches[id] = map[id]
  return { version: SWITCH_STORE_VERSION, switches }
}

// JSON with object keys sorted at every depth, so two equal values always
// produce the same text.
export function canonicalJson(value: unknown): string {
  if (value === undefined) return 'null'
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']'
  const entries = Object.keys(value)
    .sort()
    .filter((k) => (value as Record<string, unknown>)[k] !== undefined)
    .map((k) => JSON.stringify(k) + ':' + canonicalJson((value as Record<string, unknown>)[k]))
  return '{' + entries.join(',') + '}'
}

// A 64-bit string hash (two 32-bit lanes). Why not a cryptographic digest: the
// recorded fingerprint lives in $.state, which only this plugin can write, so it
// only has to tell two values apart, and a pure function keeps it testable.
export function hashText(text: string): string {
  let h1 = 0xdeadbeef
  let h2 = 0x41c6ce57
  for (let i = 0; i < text.length; i++) {
    const ch = text.charCodeAt(i)
    h1 = Math.imul(h1 ^ ch, 2654435761)
    h2 = Math.imul(h2 ^ ch, 1597334677)
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909)
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909)
  return (h2 >>> 0).toString(16).padStart(8, '0') + (h1 >>> 0).toString(16).padStart(8, '0')
}

export function storeFingerprint(raw: unknown): string {
  return hashText(canonicalJson(raw))
}

// The tamper check over one read of the store. `known` and `knownHash` are what
// this session last wrote or loaded ($.state); `storedRaw` is what the store
// holds now.
// - No fingerprint recorded yet (a new session, or after /clear, /resume or
//   /branch reset $.state): the store is taken as it is.
// - The fingerprint matches: nothing changed.
// - It does not match: something other than this session wrote the store. With
//   this session's self-protection on, the value is ignored and this session's
//   last known value is written back. Which self-protection decides: this
//   session's own, never the stored one, which is the value under suspicion.
//   With it off, the new value is accepted.
export type StoreCheck =
  | { kind: 'load'; map: SwitchMap; hash: string }
  | { kind: 'unchanged'; map: SwitchMap; hash: string }
  | { kind: 'restore'; map: SwitchMap; hash: string; storeValue: ReturnType<typeof toStoreValue> }
  | { kind: 'accept'; map: SwitchMap; hash: string }

export function checkStore(known: SwitchMap | null, knownHash: string | null, storedRaw: unknown): StoreCheck {
  const hash = storeFingerprint(storedRaw)
  if (known === null || knownHash === null) return { kind: 'load', map: normalizeSwitches(storedRaw), hash }
  if (hash === knownHash) return { kind: 'unchanged', map: known, hash }
  if (known['self-protection']) {
    const storeValue = toStoreValue(known)
    return { kind: 'restore', map: known, hash: storeFingerprint(storeValue), storeValue }
  }
  return { kind: 'accept', map: normalizeSwitches(storedRaw), hash }
}

export const TAMPER_NOTICE =
  'barmkin-mod: the switch store changed outside this session (another session, or an edit), so this session kept its own switches and wrote them back.'
export const ACCEPT_NOTICE =
  'barmkin-mod: the switch store changed outside this session; self-protection is off, so the new values were taken.'

// What /barmkin-mod-rule was asked: list, or one switch on or off.
export type RuleRequest =
  | { kind: 'list' }
  | { kind: 'set'; id: SwitchId; on: boolean }
  | { kind: 'error'; message: string }

export function parseRuleArgs(args: unknown): RuleRequest {
  const words = (typeof args === 'string' ? args : '').trim().split(/\s+/).filter(Boolean)
  const [first = '', second = ''] = words
  if (words.length === 0 || (words.length === 1 && first.toLowerCase() === 'list')) return { kind: 'list' }
  const usage = 'usage: /barmkin-mod-rule list, or /barmkin-mod-rule <id> on|off. Ids: ' + SWITCH_IDS.join(', ')
  if (words.length !== 2) return { kind: 'error', message: 'barmkin-mod: ' + usage }
  const id = first.toLowerCase()
  const state = second.toLowerCase()
  if (!isSwitchId(id)) return { kind: 'error', message: 'barmkin-mod: no switch named "' + first + '". ' + usage }
  if (state !== 'on' && state !== 'off') return { kind: 'error', message: 'barmkin-mod: say on or off. ' + usage }
  return { kind: 'set', id, on: state === 'on' }
}

export function originKindOf(origin: unknown): string {
  const kind = origin && typeof origin === 'object' ? (origin as { kind?: unknown }).kind : undefined
  return typeof kind === 'string' ? kind : 'none'
}

// Who may change a switch from the command: the person's own Enter in the
// terminal (`composer`) or the Remote Control bridge. Never a plugin, even one
// that submitted the prompt asUser, never the SDK, a notification, a schedule
// or a peer: each of those is code or another agent, not the owner. A missing
// or unknown origin refuses.
export function originMayChangeSwitches(origin: unknown): boolean {
  const kind = originKindOf(origin)
  return kind === 'composer' || kind === 'bridge'
}

export function switchesOff(map: SwitchMap): SwitchId[] {
  return SWITCH_IDS.filter((id) => !map[id])
}


// Switches whose check never reaches a decision: the shadow screen is
// annotation only. Turning one off removes no protection, so the session guard
// label does not call the session degraded for it.
export const ANNOTATION_ONLY_SWITCHES: readonly SwitchId[] = ['shadow-screen']

// The switched-off protections: what the HUD and the guard label report.
export function protectionsOff(map: SwitchMap): SwitchId[] {
  return switchesOff(map).filter((id) => !ANNOTATION_ONLY_SWITCHES.includes(id))
}

export function switchDef(id: SwitchId): (typeof SWITCH_DEFS)[number] {
  return SWITCH_DEFS.find((d) => d.id === id) as (typeof SWITCH_DEFS)[number]
}

export function describeSwitchList(map: SwitchMap): string {
  const lines = ['barmkin-mod switches (change with /barmkin-mod-rule <id> on|off, or in /barmkin-mod-panel):']
  for (const def of SWITCH_DEFS) lines.push((map[def.id] ? '  on   ' : '  OFF  ') + def.id + ' - ' + def.description)
  return lines.join('\n')
}

export function describeSwitchChange(id: SwitchId, on: boolean): string {
  return 'barmkin-mod: ' + id + ' is now ' + (on ? 'on.' : 'off: ' + switchDef(id).whenOff + '.')
}

// The egress classes the destructive tier owns; every other class belongs to the egress gate.
export const DESTRUCTIVE_CLASS_IDS: readonly string[] = ['destructive', 'history-rewrite']

export function egressClassEnabled(classId: string, map: SwitchMap): boolean {
  return DESTRUCTIVE_CLASS_IDS.includes(classId) ? map['destructive-tier'] : map['egress-gate']
}