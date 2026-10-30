// Pure logic for the self-protection switch: which tool calls target this mod's
// own switch store, its installed copy or marketplace clone, its settings
// entries, its uninstall, or its switch command. No `$` use here: register.ts
// resolves paths, reads the current settings file for a Write, and denies.
//
// Deny only. A call this file does not recognise is left to every other guard.
// Like the egress classes, this reads command text, not a parsed shell: a path
// put together from pieces (a `cd` first, a variable, an encoding), a
// configuration folder not named .claude, or a removal through a tool other
// than the usual commands (rm, mv, rmdir, unlink, trash, shred) is not
// recognised. The switch store's tamper check (switches.ts, checkStore) is the
// second line for the store.

export const PROTECTED_PLUGIN = 'barmkin-mod'
export const PROTECTED_MARKETPLACE = 'emasoft-barmkin'
// The command that changes a switch; only the owner runs it.
export const SWITCH_COMMAND = 'barmkin-mod-rule'

// Files whose entries enable this plugin or its marketplace.
const SETTINGS_BASENAMES: readonly string[] = [
  'settings.json',
  'settings.local.json',
  'managed-settings.json',
  'installed_plugins.json',
  'known_marketplaces.json',
]
const SETTINGS_MENTION = /settings(?:\.local)?\.json|managed-settings\.json|installed_plugins\.json|known_marketplaces\.json|enabledPlugins|extraKnownMarketplaces/
const MENTIONS_US = /barmkin-mod|emasoft-barmkin/

// The store file is `<plugin>_<marketplace>-<hash>.json` (`inline` for a --plugin-dir
// copy), whose hash part is not knowable here, so a glob is tested against these shapes.
const STORE_FILE_PREFIX = PROTECTED_PLUGIN + '_'
const STORE_FILE_SAMPLES: readonly string[] = [
  STORE_FILE_PREFIX + PROTECTED_MARKETPLACE + '-000000000000.json',
  STORE_FILE_PREFIX + 'inline-000000000000.json',
]

export type ProtectedKind = 'store' | 'install' | 'marketplace'

function hasGlob(segment: string): boolean {
  return /[*?[]/.test(segment)
}

function globMatches(glob: string, name: string): boolean {
  const pattern = glob.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')
  try {
    return new RegExp('^' + pattern + '$').test(name)
  } catch {
    // An unparseable bracket expression: treat it as able to match.
    return true
  }
}

// One path segment that names `name` exactly, or a glob that could match it.
function segmentNames(segment: string, name: string): boolean {
  return hasGlob(segment) ? globMatches(segment, name) : segment === name
}

export function basenameOf(path: string): string {
  const parts = path.replace(/\\/g, '/').split('/').filter(Boolean)
  return parts[parts.length - 1] ?? ''
}

// Which protected place a path names: the store file (or a glob over the store
// folder that could match it), the installed copy under plugins/cache/<marketplace>,
// or the marketplace clone under plugins/marketplaces/<marketplace>. Works on
// absolute, `~` and relative spellings alike, because it reads the trailing
// `plugins/<kind>/<name>` part, not the configuration folder in front of it.
export function protectedPathKind(path: string): ProtectedKind | null {
  const segments = path.replace(/\\/g, '/').split('/').filter((s) => s.length > 0 && s !== '.')
  for (let i = 0; i + 2 < segments.length; i++) {
    if (segments[i] !== 'plugins') continue
    const area = segments[i + 1] ?? ''
    const target = segments[i + 2] ?? ''
    if (area === 'store' && (hasGlob(target) ? STORE_FILE_SAMPLES.some((s) => globMatches(target, s)) : target.startsWith(STORE_FILE_PREFIX))) return 'store'
    if (area === 'cache' && segmentNames(target, PROTECTED_MARKETPLACE)) return 'install'
    if (area === 'marketplaces' && segmentNames(target, PROTECTED_MARKETPLACE)) return 'marketplace'
  }
  // The store file named alone, as from inside the store folder.
  const base = segments[segments.length - 1] ?? ''
  if (base.startsWith(STORE_FILE_PREFIX) && base.endsWith('.json')) return 'store'
  return null
}

const KIND_TEXT: Record<ProtectedKind, string> = {
  store: "barmkin-mod's switch store",
  install: 'the installed copy of barmkin-mod',
  marketplace: 'the barmkin-mod marketplace clone',
}

function denyReason(what: string): string {
  return (
    'barmkin-mod: self-protection blocked a call that ' +
    what +
    '. Only the owner changes barmkin-mod, from their own prompt or the /barmkin-mod-panel switch panel.'
  )
}

// A shell command split into words at blanks, quotes and shell operators, plus the
// part after `=` of a word such as `of=<path>` or `--output=<path>`.
export function shellTokens(command: string): string[] {
  const words = command.replace(/\\/g, '/').split(/[\s'"`;&|()<>{}]+/).filter(Boolean)
  const tokens: string[] = []
  for (const word of words) {
    tokens.push(word)
    const eq = word.lastIndexOf('=')
    if (eq >= 0 && eq < word.length - 1) tokens.push(word.slice(eq + 1))
  }
  return tokens
}

const UNINSTALL_VERBS: ReadonlySet<string> = new Set(['disable', 'uninstall', 'remove', 'rm'])
const REMOVE_VERBS: ReadonlySet<string> = new Set(['remove', 'rm'])
const REMOVAL_COMMANDS: ReadonlySet<string> = new Set(['rm', 'rmdir', 'mv', 'unlink', 'trash', 'shred'])

// A folder that holds the installed copy or the marketplace clone: the
// configuration folder itself, its plugins folder, or plugins/cache or
// plugins/marketplaces (a glob counts when it could name one). Only under a
// folder named .claude, so a project's own plugins folder is not mistaken for it.
export function isProtectedAncestor(path: string): boolean {
  const segments = path.replace(/\\/g, '/').split('/').filter((s) => s.length > 0 && s !== '.')
  const last = segments[segments.length - 1] ?? ''
  const prev = segments[segments.length - 2] ?? ''
  const prevPrev = segments[segments.length - 3] ?? ''
  if (last === '.claude') return true
  if (last === 'plugins' && prev === '.claude') return true
  return prev === 'plugins' && prevPrev === '.claude' && (segmentNames(last, 'cache') || segmentNames(last, 'marketplaces'))
}

// Why a shell command (Bash, PowerShell, Monitor, an inline skill shell) is denied, or null.
export function shellSelfProtectionReason(command: string): string | null {
  const tokens = shellTokens(command)
  for (const token of tokens) {
    const kind = protectedPathKind(token)
    if (kind) return denyReason('names ' + KIND_TEXT[kind])
  }
  if (tokens.some((t) => REMOVAL_COMMANDS.has(basenameOf(t))) && tokens.some((t) => isProtectedAncestor(t))) {
    return denyReason('removes or moves a folder that holds barmkin-mod')
  }
  const runsClaude = tokens.some((t) => basenameOf(t) === 'claude')
  if (runsClaude) {
    const lower = tokens.map((t) => t.toLowerCase())
    const pluginVerb = lower.includes('plugin') || lower.includes('plugins')
    const namesPlugin = tokens.some((t) => t === PROTECTED_PLUGIN || t.startsWith(PROTECTED_PLUGIN + '@'))
    if (pluginVerb && namesPlugin && lower.some((t) => UNINSTALL_VERBS.has(t))) return denyReason('disables or uninstalls barmkin-mod')
    if (pluginVerb && lower.includes('marketplace') && tokens.includes(PROTECTED_MARKETPLACE) && lower.some((t) => REMOVE_VERBS.has(t))) {
      return denyReason('removes the ' + PROTECTED_MARKETPLACE + ' marketplace')
    }
    if (command.includes(SWITCH_COMMAND)) return denyReason('runs the ' + SWITCH_COMMAND + ' switch command in another session')
  }
  if (MENTIONS_US.test(command) && SETTINGS_MENTION.test(command)) return denyReason("touches barmkin-mod's entries in the settings files")
  return null
}

export function isSettingsFile(path: string): boolean {
  return SETTINGS_BASENAMES.includes(basenameOf(path))
}

function editStrings(tool: string, input: Record<string, unknown>): string[] {
  const out: string[] = []
  const push = (v: unknown) => {
    if (typeof v === 'string') out.push(v)
  }
  if (tool === 'Edit') {
    push(input.old_string)
    push(input.new_string)
  }
  if (tool === 'MultiEdit' && Array.isArray(input.edits)) {
    for (const edit of input.edits) {
      if (edit && typeof edit === 'object') {
        push((edit as Record<string, unknown>).old_string)
        push((edit as Record<string, unknown>).new_string)
      }
    }
  }
  return out
}

// Why a file-tool call (Write, Edit, MultiEdit, NotebookEdit) is denied, or null.
// `path` is the target resolved against the working directory where it was
// relative. A Write to a settings file is judged by writeChangesProtectedEntries,
// which needs the file's current text, so it is not decided here.
export function fileSelfProtectionReason(tool: string, input: Record<string, unknown>, path: string): string | null {
  const kind = protectedPathKind(path)
  if (kind) return denyReason('writes into ' + KIND_TEXT[kind])
  if (isSettingsFile(path) && editStrings(tool, input).some((s) => MENTIONS_US.test(s))) {
    return denyReason("edits barmkin-mod's entries in a settings file")
  }
  return null
}

export const SETTINGS_WRITE_REASON = denyReason("rewrites barmkin-mod's entries in a settings file")


export const SWITCH_COMMAND_REASON = denyReason('runs the ' + SWITCH_COMMAND + ' switch command')

// Every entry under a key that names this plugin (`barmkin-mod`, `barmkin-mod@…`)
// or its marketplace, anywhere in the JSON, as path -> JSON text. Null when the
// text is not JSON.
export function protectedEntries(text: string): Map<string, string> | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return null
  }
  const entries = new Map<string, string>()
  const walk = (value: unknown, path: string) => {
    if (Array.isArray(value)) {
      value.forEach((v, i) => walk(v, path + '[' + i + ']'))
      return
    }
    if (!value || typeof value !== 'object') return
    for (const [key, v] of Object.entries(value)) {
      const here = path + '/' + key
      if (key === PROTECTED_PLUGIN || key.startsWith(PROTECTED_PLUGIN + '@') || key === PROTECTED_MARKETPLACE) {
        entries.set(here, JSON.stringify(v))
      } else {
        walk(v, here)
      }
    }
  }
  walk(parsed, '')
  return entries
}

// Whether a Write of `newText` over a settings file holding `oldText` (null when
// the file does not exist) changes, adds or removes any entry of this plugin or
// its marketplace. Fail closed: a current file that is not JSON cannot be
// compared, so the write counts as a change; a new text that is not JSON counts
// as one when the current file held an entry.
export function writeChangesProtectedEntries(oldText: string | null, newText: string): boolean {
  const before = oldText === null ? new Map<string, string>() : protectedEntries(oldText)
  if (before === null) return true
  const after = protectedEntries(newText)
  if (after === null) return before.size > 0
  if (before.size !== after.size) return true
  for (const [path, value] of before) if (after.get(path) !== value) return true
  return false
}

// The Skill tool call that would run the switch command (`barmkin-mod-rule`, or
// its plugin-namespaced form). Denied whatever origin the run would carry: the
// command already refuses a non-person origin, and this keeps the model from
// reaching it at all.
export function isSwitchCommandSkill(skill: unknown): boolean {
  return typeof skill === 'string' && new RegExp('(^|:)/?' + SWITCH_COMMAND + '$').test(skill.trim())
}

// Every string in a tool input, at any depth: what an MCP tool call is judged on.
export function inputStrings(input: unknown): string[] {
  const out: string[] = []
  const walk = (value: unknown) => {
    if (typeof value === 'string') out.push(value)
    else if (Array.isArray(value)) value.forEach(walk)
    else if (value && typeof value === 'object') Object.values(value).forEach(walk)
  }
  walk(input)
  return out
}

// Why an MCP tool call is denied, or null, judged on every string of its input:
// one that names a protected place, or a settings file named beside a mention of
// this plugin or its marketplace. Narrower than the shell rule, because an MCP
// input is often prose (an issue body, a message) rather than a command.
export function mcpSelfProtectionReason(strings: readonly string[]): string | null {
  for (const s of strings) {
    for (const token of shellTokens(s)) {
      const kind = protectedPathKind(token)
      if (kind) return denyReason('names ' + KIND_TEXT[kind])
    }
  }
  const namesSettings = strings.some((s) => shellTokens(s).some((t) => isSettingsFile(t)))
  if (namesSettings && strings.some((s) => MENTIONS_US.test(s))) return denyReason("touches barmkin-mod's entries in the settings files")
  return null
}