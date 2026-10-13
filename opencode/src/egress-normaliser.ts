// Re-keys OpenCode 2.x tool ids and argument names to the Claude-side keys that
// hooks/lib/egress.ts classifies on (`Bash`/`command`, `Edit`/`file_path`,
// `WebFetch`, `mcp__<server>__<tool>`, ...), so egress.ts stays verbatim and
// both hosts share one policy. 2.x ids and arguments: re-scout S11
// (core/src/tool/plugin/*.ts), observed in the lab as V1-V9, V24, V29, V31, V33:
//
//   shell(command, workdir, timeout, background)      -> Bash
//   read(path, offset, limit)                         -> Read
//   write(path, content)                              -> Write
//   edit(path, oldString, newString, replaceAll)      -> Edit
//   patch(patchText)                                  -> Edit, one call per file in the patch
//   webfetch(url, format, timeout)                    -> WebFetch
//   websearch(...)                                    -> WebSearch
//   subagent(agent, description, prompt, ...)         -> Task
//   skill(id)                                         -> Skill
//   execute(code)                                     -> `execute` (Code Mode, no Claude key)
//   <server>_<tool>                                   -> mcp__<server>__<tool>
//
// The brief's shorthand names (`bash`, `apply_patch`, `task`) are 1.x ids and
// are accepted as aliases. A 2.x MCP tool is a flat `<server>_<tool>` id with no
// marker (V24: `evil_fetch_page`), so the adapter should pass its MCP inventory
// as `isMcpTool`; without it any id outside the built-in set is treated as MCP,
// which is the safe direction (it can only add a write-class deny while
// tainted).
//
// 2.x has no leaf/CSR/minting step (re-scout section 2): the model is
// deny-on-taint plus record-on-allow. `gateEgress` returns the verdict the
// adapter turns into a throw (execute.before for the early refusal,
// permission.evaluate for the final recheck, V2, V7) and, when a call is allowed
// but egress-shaped, an `EgressRecord` for the adapter to keep.

import {
  EGRESS_CLASSES,
  classifyEgress,
  decideEgress,
  touchesSecretPath,
  type EgressCall,
  type EgressClass,
  type EgressVerdict,
  type TrifectaLegs,
} from '../../hooks/lib/egress'

// ---------------------------------------------------------------------------
// Classes: Claude's, plus the one 2.x-only channel.
// ---------------------------------------------------------------------------

// Code Mode's `execute` runs a script whose `fetch` is a raw globalThis.fetch
// with no permission step and no plugin hook (V25, S16). The only visible
// moment is the outer `execute` call, so it is classed as an outward-effect
// tool and denied while the session is tainted (re-scout section 8, item 4).
// Inner tool calls from Code Mode still fire the ordinary hooks (V24) and are
// classified as themselves.
export const CODEMODE_TOOL = 'execute'

export const CODEMODE_EGRESS_CLASS: EgressClass = {
  id: 'codemode-execute',
  description: 'a Code Mode script (its fetch is an unmediated outbound channel)',
  tools: [CODEMODE_TOOL],
  onUntrusted: 'deny',
}

export const OPENCODE_EGRESS_CLASSES: readonly EgressClass[] = [...EGRESS_CLASSES, CODEMODE_EGRESS_CLASS]

// ---------------------------------------------------------------------------
// Tool id and argument re-keying.
// ---------------------------------------------------------------------------

const TOOL_KEYS: Readonly<Record<string, string>> = {
  shell: 'Bash',
  bash: 'Bash',
  read: 'Read',
  write: 'Write',
  edit: 'Edit',
  patch: 'Edit',
  apply_patch: 'Edit',
  glob: 'Glob',
  grep: 'Grep',
  webfetch: 'WebFetch',
  websearch: 'WebSearch',
  subagent: 'Task',
  task: 'Task',
  skill: 'Skill',
}

// Ids that are OpenCode's own or this plugin's, never an MCP server's: the
// `opencode_*` management tools (V1 inventory) and barmkin's refusal tool.
const NON_MCP_PREFIXES: readonly string[] = ['opencode_', 'barmkin_']
const NON_MCP_IDS: ReadonlySet<string> = new Set(['question', CODEMODE_TOOL])

export interface NormaliseOptions {
  // Server names, for splitting `<server>_<tool>` into the Claude MCP form.
  mcpServers?: readonly string[]
  // True when the id is a known MCP tool (from the MCP inventory). When
  // omitted, an id outside the built-in set is taken to be MCP.
  isMcpTool?: (id: string) => boolean
}

function asRecord(input: unknown): Record<string, unknown> {
  return input && typeof input === 'object' && !Array.isArray(input) ? (input as Record<string, unknown>) : {}
}

function isMcp(id: string, opts: NormaliseOptions): boolean {
  if (opts.isMcpTool) return opts.isMcpTool(id)
  if (id in TOOL_KEYS || NON_MCP_IDS.has(id)) return false
  return !NON_MCP_PREFIXES.some((p) => id.startsWith(p))
}

// `evil_fetch_page` -> `mcp__evil__fetch_page`. The longest matching server
// name wins; with none, the whole id is the tool part (the verb scan in
// egress.ts reads the words after the first `__`, so a server name that is a
// write verb cannot cause a false hit when it is split off).
export function mcpKey(id: string, servers: readonly string[] = []): string {
  const match = [...servers].sort((a, b) => b.length - a.length).find((s) => id.startsWith(s + '_') && id.length > s.length + 1)
  return match ? `mcp__${match}__${id.slice(match.length + 1)}` : `mcp__unknown__${id}`
}

// Paths a patch text names. Handles OpenCode's `*** Begin Patch` envelope
// (`*** Add|Update|Delete File:`, `*** Move to:`) and unified-diff `+++`/`---`
// headers. The argument name is S11; the body format is not lab-run, so an
// unparsed patch yields one path-less Edit call and is left to the
// permission-time recheck, which sees the real paths.
export function patchPaths(patchText: string): string[] {
  const paths = new Set<string>()
  for (const m of patchText.matchAll(/^\*\*\* (?:Add|Update|Delete) File:\s*(.+?)\s*$/gm)) paths.add(m[1])
  for (const m of patchText.matchAll(/^\*\*\* Move to:\s*(.+?)\s*$/gm)) paths.add(m[1])
  for (const m of patchText.matchAll(/^(?:\+\+\+|---) (?:[ab]\/)?(\S+)/gm)) if (m[1] !== '/dev/null') paths.add(m[1])
  return [...paths]
}

function withPath(input: Record<string, unknown>, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const out: Record<string, unknown> = { ...input, ...extra }
  if (typeof input.path === 'string' && out.file_path === undefined) out.file_path = input.path
  return out
}

// The Claude-keyed calls for one 2.x tool call. One call for most tools; a
// patch yields one Edit call per file it touches. Never throws on odd input:
// a non-object `input` classifies on the tool id alone.
export function normaliseEgressCalls(tool: string, input: unknown, opts: NormaliseOptions = {}): EgressCall[] {
  const args = asRecord(input)
  if (tool === CODEMODE_TOOL) return [{ tool: CODEMODE_TOOL, input: args }]
  const key = TOOL_KEYS[tool]
  if (key === undefined) {
    return isMcp(tool, opts) ? [{ tool: mcpKey(tool, opts.mcpServers), input: args }] : [{ tool, input: args }]
  }
  switch (tool) {
    case 'patch':
    case 'apply_patch': {
      const text = typeof args.patchText === 'string' ? args.patchText : typeof args.patch === 'string' ? args.patch : ''
      const paths = patchPaths(text)
      return paths.length === 0
        ? [{ tool: 'Edit', input: args }]
        : paths.map((p) => ({ tool: 'Edit', input: { ...args, file_path: p } }))
    }
    case 'edit':
      return [
        {
          tool: 'Edit',
          input: withPath(args, {
            old_string: args.oldString,
            new_string: args.newString,
            replace_all: args.replaceAll,
          }),
        },
      ]
    case 'skill':
      return [{ tool: 'Skill', input: { ...args, skill: args.id ?? args.skill } }]
    case 'write':
    case 'read':
      return [{ tool: key, input: withPath(args) }]
    default:
      return [{ tool: key, input: args }]
  }
}

// The calls a `permission.evaluate` event stands for. At permission time the
// event carries `action` and `resources`, not the tool input (V5-V9, V33):
// `shell` resources are the final parsed commands (one entry per `&&`-separated
// command, V9), `webfetch` the URL, `skill` / `subagent` the id, file tools
// paths. An MCP tool's action is its id with resources `["*"]`, so only the
// tool name classifies (V24); `external_directory` is not an outward effect.
export function normaliseEvaluate(action: string, resources: readonly string[], opts: NormaliseOptions = {}): EgressCall[] {
  const list = resources.filter((r): r is string => typeof r === 'string')
  switch (action) {
    case 'shell':
    case 'bash':
      return list.map((command) => ({ tool: 'Bash', input: { command } }))
    case 'webfetch':
      return list.map((url) => ({ tool: 'WebFetch', input: { url } }))
    case 'websearch':
      return list.map((query) => ({ tool: 'WebSearch', input: { query } }))
    case 'read':
      return list.map((p) => ({ tool: 'Read', input: { path: p, file_path: p } }))
    case 'write':
    case 'edit':
    case 'patch':
    case 'apply_patch':
      return list.map((p) => ({ tool: action === 'write' ? 'Write' : 'Edit', input: { path: p, file_path: p } }))
    case 'skill':
      return list.map((id) => ({ tool: 'Skill', input: { skill: id, id } }))
    case 'subagent':
    case 'task':
      return [{ tool: 'Task', input: {} }]
    case 'external_directory':
      return []
    default:
      return normaliseEgressCalls(action, {}, opts)
  }
}

// The B leg's path source across the normalised calls (egress.ts reads
// `command`, `file_path`, `notebook_path` and `path`).
export function touchesSecretPathOc(calls: readonly EgressCall[]): boolean {
  return calls.some(touchesSecretPath)
}

// ---------------------------------------------------------------------------
// Deny-on-taint + record-on-allow.
// ---------------------------------------------------------------------------

// The outbound path a class stands for, kept as a record label only: policy is
// decideEgress. `net.http` is a request to a URL, `net.connect` a connection to
// a host (socket, remote copy, DNS, an inline script, a Code Mode script that
// can do either); both are deny-level while the session is tainted. The rest
// are local or in-protocol effects.
export type EgressChannel = 'net.http' | 'net.connect' | 'mcp.write' | 'persist' | 'skill.load'

const CHANNEL_BY_CLASS: Readonly<Record<string, EgressChannel>> = {
  'web-fetch': 'net.http',
  'web-search': 'net.http',
  forge: 'net.http',
  publish: 'net.http',
  cloud: 'net.http',
  'shell-outward': 'net.http',
  'net-client': 'net.connect',
  dns: 'net.connect',
  'interpreter-net': 'net.connect',
  'monitor-ws': 'net.connect',
  'codemode-execute': 'net.connect',
  'mcp-write': 'mcp.write',
  'persist-shell': 'persist',
  persistence: 'persist',
  'skill-load': 'skill.load',
}

export function channelOf(classId: string): EgressChannel | null {
  return CHANNEL_BY_CLASS[classId] ?? null
}

// What the adapter keeps when an egress-shaped call is let through (leg A
// clear, or a warn-posture class under leg A alone). Hosts only: a URL's path
// and query can carry the payload, so they are never recorded.
export interface EgressRecord {
  tool: string
  classIds: string[]
  channels: EgressChannel[]
  hosts: string[]
  verdict: 'pass' | 'warn'
}

export interface EgressDecision {
  calls: EgressCall[]
  classes: EgressClass[]
  verdict: EgressVerdict
  // The channels the verdict acts on: the denied classes' when denying, else all.
  channels: EgressChannel[]
  // Non-null only when the call was not denied and matched an egress class.
  record: EgressRecord | null
}

function hostOf(url: string): string | null {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#\\]*)/i.exec(url)
  if (!m) return null
  const authority = m[1].split('@').pop() as string
  const host = /^(\[[^\]]*\]|[^:]*)/.exec(authority)?.[1]
  return host ? host.toLowerCase() : null
}

function hostsIn(call: EgressCall): string[] {
  const out = new Set<string>()
  const texts = [call.input.url, call.input.command].filter((v): v is string => typeof v === 'string')
  for (const text of texts) {
    for (const url of text.match(/[a-z][a-z0-9+.-]*:\/\/[^\s"'`)]+/gi) ?? []) {
      const host = hostOf(url)
      if (host) out.add(host)
    }
  }
  return [...out]
}

function dedupeClasses(classes: EgressClass[]): EgressClass[] {
  const seen = new Set<string>()
  return classes.filter((c) => !seen.has(c.id) && seen.add(c.id))
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)]
}

// Classifies the calls against the Claude classes plus Code Mode, applies the
// Rule-of-Two decision for `legs`, and builds the record-on-allow value. Pure:
// the adapter owns the state legs, the throw, and where the record goes.
export function gateEgress(
  calls: readonly EgressCall[],
  legs: TrifectaLegs,
  classes: readonly EgressClass[] = OPENCODE_EGRESS_CLASSES,
): EgressDecision {
  const matched = dedupeClasses(calls.flatMap((c) => classifyEgress(c, classes)))
  const verdict = decideEgress(matched, legs)
  const acted =
    verdict.kind === 'pass' ? matched : matched.filter((c) => (verdict as { classIds: string[] }).classIds.includes(c.id))
  const channels = unique(acted.map((c) => channelOf(c.id)).filter((c): c is EgressChannel => c !== null))
  const record: EgressRecord | null =
    verdict.kind === 'deny' || matched.length === 0
      ? null
      : {
          tool: calls[0]?.tool ?? '',
          classIds: matched.map((c) => c.id),
          channels: unique(matched.map((c) => channelOf(c.id)).filter((c): c is EgressChannel => c !== null)),
          hosts: unique(calls.flatMap(hostsIn)),
          verdict: verdict.kind,
        }
  return { calls: [...calls], classes: matched, verdict, channels, record }
}

// One-step form for the execute.before site: a 2.x tool id and its arguments.
export function gateToolCall(
  tool: string,
  input: unknown,
  legs: TrifectaLegs,
  opts: NormaliseOptions = {},
): EgressDecision {
  return gateEgress(normaliseEgressCalls(tool, input, opts), legs)
}

// One-step form for the permission.evaluate site: the final recheck on the
// action and resources after every other plugin's rewrite (V7-V9).
export function gateEvaluate(
  action: string,
  resources: readonly string[],
  legs: TrifectaLegs,
  opts: NormaliseOptions = {},
): EgressDecision {
  return gateEgress(normaliseEvaluate(action, resources, opts), legs)
}
