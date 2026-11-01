// Pure logic for the self-protection switch: which tool calls target this mod's
// own switch store, its installed copy or marketplace clone, its settings
// entries or the settings keys that turn hooks off, its uninstall, or its switch
// command. No `$` use here: register.ts resolves paths, reads the current
// settings file for a Write or an Edit, and denies.
//
// Deny only. A call this file does not recognise is left to every other guard.
// Like the egress classes, this reads command text, not a parsed shell: a path
// put together from pieces (a `cd` first, a variable, an encoding), a
// configuration folder not named .claude, or a removal or write through a tool
// other than the usual commands (rm, mv, cp, tee, a redirection, an in-place
// sed or perl, an interpreter's inline code) is not recognised. The switch
// store's tamper check (switches.ts, checkStore) is the second line for the store.

import { shellSegments } from './egress'

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
const SETTINGS_MENTION = /settings(?:\.local)?\.json|managed-settings\.json|installed_plugins\.json|known_marketplaces\.json|enabledPlugins|extraKnownMarketplaces/i
// The marketplaces this plugin is protected under: the one it is published in,
// and the one the running copy was installed from (protectMarketplace, called by
// register.ts at session start), which differs for a copy installed from
// another marketplace, such as the upstream project's.
const marketplaces = new Set<string>([PROTECTED_MARKETPLACE])

// Adds the marketplace a running copy came from. A name that is not a plain
// marketplace name (letters, digits, dot, dash, underscore) is ignored.
export function protectMarketplace(name: string): void {
  if (/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) marketplaces.add(name.toLowerCase())
}

// The marketplace of an installed copy, from its folder
// (`…/plugins/cache/<marketplace>/barmkin-mod/<version>`), or null for a copy
// anywhere else, such as a --plugin-dir working tree.
export function marketplaceFromRoot(root: unknown): string | null {
  if (typeof root !== 'string') return null
  const segments = root.replace(/\\/g, '/').split('/').filter(Boolean)
  for (let i = 0; i + 3 < segments.length; i++) {
    if (segments[i] === 'plugins' && segments[i + 1] === 'cache' && segments[i + 3] === PROTECTED_PLUGIN) return segments[i + 2] ?? null
  }
  return null
}

// The configuration folder of an installed copy, from its folder
// (`<config>/plugins/cache/<marketplace>/barmkin-mod/<version>`), or null for a
// copy anywhere else.
export function configDirFromRoot(root: unknown): string | null {
  if (typeof root !== 'string') return null
  const absolute = root.startsWith('/')
  const segments = root.replace(/\\/g, '/').split('/').filter(Boolean)
  for (let i = 0; i + 3 < segments.length; i++) {
    if (segments[i] === 'plugins' && segments[i + 1] === 'cache' && segments[i + 3] === PROTECTED_PLUGIN) {
      return (absolute ? '/' : '') + segments.slice(0, i).join('/')
    }
  }
  return null
}

// A mention of this plugin or of a marketplace it is protected under.
function mentionsUs(text: string): boolean {
  const folded = text.toLowerCase()
  return folded.includes(PROTECTED_PLUGIN) || [...marketplaces].some((m) => folded.includes(m))
}

// Settings keys that turn this mod off without naming it: disableAllHooks stops
// every installed mod (from any settings file), allowManagedHooksOnly and
// allowManagedModsOnly every mod the organization does not manage. Any change to
// one counts, removing it included: denying a harmless change costs less than
// telling it apart from a harmful one.
const HOOKS_OFF_KEYS: readonly string[] = ['disableAllHooks', 'allowManagedHooksOnly', 'allowManagedModsOnly']
// The keys of the settings that enable plugins or turn hooks off: what a shell
// or MCP write of a settings file is known by when its path does not show the
// file is Claude Code's.
const SETTINGS_KEY_MENTION = /enabledPlugins|extraKnownMarketplaces|disableAllHooks|allowManagedHooksOnly|allowManagedModsOnly/i
// Settings file names no other program uses.
const CLAUDE_ONLY_BASENAMES: readonly string[] = ['managed-settings.json', 'installed_plugins.json', 'known_marketplaces.json']

// The store file is `<plugin>_<marketplace>-<hash>.json` (`inline` for a --plugin-dir
// The store file is `<plugin>_<marketplace>-<hash>.json` (`inline` for a --plugin-dir
// copy), whose hash part is not knowable here, so a glob is tested against these shapes.
const STORE_FILE_PREFIX = PROTECTED_PLUGIN + '_'
function storeFileSamples(): string[] {
  return [...marketplaces, 'inline'].map((m) => STORE_FILE_PREFIX + m + '-000000000000.json')
}

export type ProtectedKind = 'store' | 'install' | 'marketplace'

// Paths and commands are compared case-folded (review R1 of the 0.3.0 fix round):
// the default volumes of macOS and Windows are case-insensitive, so
// ~/.claude/Settings.json and ~/.CLAUDE are the same files as their lower-case
// spelling, and RM or CLAUDE run the same programs. Resolving does not help, as
// FsStat.realPath keeps the spelling of a case alias. On a case-sensitive volume
// a name that differs only in case is protected too: a denial that costs little.
function fold(path: string): string {
  return path.replace(/\\/g, '/').toLowerCase()
}

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
  const segments = fold(path).split('/').filter((s) => s.length > 0 && s !== '.')
  for (let i = 0; i + 2 < segments.length; i++) {
    if (segments[i] !== 'plugins') continue
    const area = segments[i + 1] ?? ''
    const target = segments[i + 2] ?? ''
    if (area === 'store' && (hasGlob(target) ? storeFileSamples().some((s) => globMatches(target, s)) : target.startsWith(STORE_FILE_PREFIX))) return 'store'
    if (area === 'cache' && [...marketplaces].some((m) => segmentNames(target, m))) return 'install'
    if (area === 'marketplaces' && [...marketplaces].some((m) => segmentNames(target, m))) return 'marketplace'
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

// A folder that holds the installed copy, the marketplace clone or the switch
// store: the configuration folder itself, its plugins folder, or plugins/cache,
// plugins/marketplaces or plugins/store (a glob counts when it could name one).
// Only under a folder named .claude, so a project's own plugins folder is not
// mistaken for it.
export function isProtectedAncestor(path: string): boolean {
  const segments = fold(path).split('/').filter((s) => s.length > 0 && s !== '.')
  const last = segments[segments.length - 1] ?? ''
  const prev = segments[segments.length - 2] ?? ''
  const prevPrev = segments[segments.length - 3] ?? ''
  if (last === '.claude') return true
  if (last === 'plugins' && prev === '.claude') return true
  return prev === 'plugins' && prevPrev === '.claude' && ['cache', 'marketplaces', 'store'].some((area) => segmentNames(last, area))
}

// A token naming the plugin store folder itself (`…/plugins/store`), which holds
// the switch store beside other plugins' stores, in any spelling.
function namesStoreFolder(token: string): boolean {
  const segments = fold(token).split('/').filter((s) => s.length > 0 && s !== '.')
  return segments[segments.length - 1] === 'store' && segments[segments.length - 2] === 'plugins'
}

// A glob that could match the switch store's file name (`barmkin*`, `*.json`, `*`).
function globCouldNameStore(token: string): boolean {
  const base = basenameOf(fold(token))
  return hasGlob(base) && storeFileSamples().some((s) => globMatches(base, s))
}

// Redirection targets in a command (`> f`, `>> f`, `&> f`, `>| f`), quotes
// removed. The /dev streams (`2>/dev/null`) are not files.
function redirectTargets(command: string): string[] {
  const out: string[] = []
  for (const m of command.matchAll(/(?:>>?|&>|>&|>\|)\s*("[^"]*"|'[^']*'|[^\s;&|()<>]+)/g)) {
    const target = (m[1] ?? '').replace(/^["']|["']$/g, '')
    if (!target.startsWith('/dev/')) out.push(target)
  }
  return out
}

// Commands that write, move or remove every file they name, and those that
// write only the last one (the destination).
const ALL_ARG_WRITERS: ReadonlySet<string> = new Set([
  ...REMOVAL_COMMANDS,
  'tee',
  'sponge',
  'truncate',
  'set-content',
  'add-content',
  'out-file',
  'copy-item',
  'move-item',
  'remove-item',
])
const LAST_ARG_WRITERS: ReadonlySet<string> = new Set(['cp', 'install', 'ln', 'rsync'])
// An in-place sed, perl or yq, and an interpreter running inline code: which
// file they write cannot be read from the text, so every file named counts.
const IN_PLACE = /\b(?:sed|perl|yq)\b[^|;&]*\s(?:-[a-zA-Z]*i|--in-place)\b/
const INLINE_CODE = /\b(?:python[0-9.]*|node|ruby|perl|php|deno|bun|osascript|pwsh|powershell)\b[^|;&]*\s(?:-c|-e|-r|--eval|-Command)(?:\s|$)/i

// The files a shell command may write, move or remove, as spelled in it.
function writtenPaths(command: string): string[] {
  const out = redirectTargets(command)
  for (const [head = '', ...args] of shellSegments(command)) {
    const files = args.filter((a) => !a.startsWith('-'))
    if (ALL_ARG_WRITERS.has(head)) out.push(...files)
    else if (LAST_ARG_WRITERS.has(head)) out.push(...files.slice(-1))
    else if (head === 'dd') out.push(...args.filter((a) => a.startsWith('of=')).map((a) => a.slice(3)))
  }
  if (IN_PLACE.test(command) || INLINE_CODE.test(command)) out.push(...shellTokens(command))
  return out
}

// A settings file whose path shows it is Claude Code's: under a .claude folder,
// or a name only Claude Code uses.
function isClaudeSettingsPath(path: string): boolean {
  if (!isSettingsFile(path)) return false
  const folded = fold(path)
  return folded.split('/').includes('.claude') || CLAUDE_ONLY_BASENAMES.includes(basenameOf(folded))
}

// Whether a shell command writes, moves or removes a Claude Code settings file.
// A Write or an Edit is compared against the file (writeChangesProtectedEntries);
// a shell write cannot be, so every such write counts, whatever it names: a jq
// filter or a python one-liner can drop enabledPlugins or add disableAllHooks
// without spelling this plugin. A bare settings.json (an editor's, or one
// reached after a `cd`) counts beside a key of the settings that enable plugins
// or turn hooks off. A read is never a write here.
function shellWritesSettings(command: string): boolean {
  const written = writtenPaths(command).filter((p) => isSettingsFile(p))
  return written.some((p) => isClaudeSettingsPath(p)) || (written.length > 0 && SETTINGS_KEY_MENTION.test(command))
}

// Whether a command changes the files it reaches: find's -exec, -execdir, -ok
// or -delete, xargs, or any write writtenPaths recognises.
const FIND_ACTIONS = /(?:^|\s)-(?:exec|execdir|ok|okdir|delete)(?:\s|$)|\bxargs\b/
function changesFiles(command: string): boolean {
  return FIND_ACTIONS.test(command) || writtenPaths(command).length > 0
}

// Whether a command makes a link: ln or link, cp with -l or --link (cp -al
// too), or rsync --link-dest. The command arrives folded.
function makesLink(command: string): boolean {
  for (const [head = '', ...args] of shellSegments(command)) {
    const name = basenameOf(head)
    if (name === 'ln' || name === 'link') return true
    if (name === 'cp' && args.some((a) => a === '--link' || /^-[a-z]*l[a-z]*$/.test(a))) return true
    if (name === 'rsync' && args.some((a) => a.startsWith('--link-dest'))) return true
  }
  return false
}

// Why a shell command (Bash, PowerShell, Monitor, an inline skill shell) is denied, or null.
export function shellSelfProtectionReason(raw: string): string | null {
  // Folded once here, so every rule below compares case-folded (see fold).
  const command = raw.toLowerCase()
  const tokens = shellTokens(command)
  for (const token of tokens) {
    const kind = protectedPathKind(token)
    if (kind) return denyReason('names ' + KIND_TEXT[kind])
  }
  if (tokens.some((t) => REMOVAL_COMMANDS.has(basenameOf(t))) && tokens.some((t) => isProtectedAncestor(t))) {
    return denyReason('removes or moves a folder that holds barmkin-mod')
  }
  // A hard link gives a protected file a second name that the file tools never
  // resolve (FsStat.realPath keeps the spelling of a hard link), so an Edit of the
  // link would change the settings unseen (review R2). A link command naming a
  // settings file or a folder that holds barmkin-mod is denied, a symbolic link
  // too: denying one costs little, and such a link has no ordinary use.
  if (makesLink(command) && tokens.some((t) => isSettingsFile(t) || isProtectedAncestor(t))) {
    return denyReason('makes a second name (a link) for a file barmkin-mod protects')
  }
  // The store folder named without the file: a glob, a find or a copy into it
  // reaches the switch store without spelling the store file's name.
  if (tokens.some(namesStoreFolder) && (tokens.some(globCouldNameStore) || changesFiles(command))) {
    return denyReason("reaches barmkin-mod's switch store through the plugin store folder")
  }
  if (tokens.some((t) => isProtectedAncestor(t)) && tokens.some(globCouldNameStore) && changesFiles(command)) {
    return denyReason('changes files under a folder that holds barmkin-mod, through a name pattern that matches its switch store')
  }
  const runsClaude = tokens.some((t) => basenameOf(t) === 'claude')
  if (runsClaude) {
    const lower = tokens.map((t) => t.toLowerCase())
    const pluginVerb = lower.includes('plugin') || lower.includes('plugins')
    const namesPlugin = tokens.some((t) => t === PROTECTED_PLUGIN || t.startsWith(PROTECTED_PLUGIN + '@'))
    if (pluginVerb && namesPlugin && lower.some((t) => UNINSTALL_VERBS.has(t))) return denyReason('disables or uninstalls barmkin-mod')
    const marketplace = tokens.find((t) => marketplaces.has(t))
    if (pluginVerb && lower.includes('marketplace') && marketplace && lower.some((t) => REMOVE_VERBS.has(t))) {
      return denyReason('removes the ' + marketplace + ' marketplace')
    }
    if (command.includes(SWITCH_COMMAND)) return denyReason('runs the ' + SWITCH_COMMAND + ' switch command in another session')
  }
  if (shellWritesSettings(command)) return SHELL_SETTINGS_REASON
  if (mentionsUs(command) && SETTINGS_MENTION.test(command)) return denyReason("touches barmkin-mod's entries in the settings files")
  return null
}

export function isSettingsFile(path: string): boolean {
  return SETTINGS_BASENAMES.includes(basenameOf(path).toLowerCase())
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

// The text an Edit or MultiEdit leaves in a file whose current text is `text`
// (null: no file), applied as the tool applies it: each old_string replaced by
// its new_string, every occurrence under replace_all, edits in order, an empty
// old_string creating the file. Null when an edit cannot be applied (the text to
// replace is not there, a field is not a string): the edit cannot be judged.
export function editedText(text: string | null, tool: string, input: Record<string, unknown>): string | null {
  const edits: unknown[] = tool === 'Edit' ? [input] : tool === 'MultiEdit' && Array.isArray(input.edits) ? input.edits : []
  if (edits.length === 0) return null
  let out = text
  for (const edit of edits) {
    if (!edit || typeof edit !== 'object') return null
    const { old_string: from, new_string: to, replace_all: all } = edit as Record<string, unknown>
    if (typeof from !== 'string' || typeof to !== 'string') return null
    if (from === '') {
      if (out !== null && out !== '') return null
      out = to
      continue
    }
    if (out === null) return null
    const at = out.indexOf(from)
    if (at === -1) return null
    out = all === true ? out.split(from).join(to) : out.slice(0, at) + to + out.slice(at + from.length)
  }
  return out
}

// Why a file-tool call (Write, Edit, MultiEdit, NotebookEdit) is denied, or null.
// `path` is the target resolved against the working directory where it was
// relative. A Write or an Edit of a settings file is also judged by
// writeChangesProtectedEntries, which needs the file's current text, so
// register.ts decides that part.
export function fileSelfProtectionReason(tool: string, input: Record<string, unknown>, path: string): string | null {
  const kind = protectedPathKind(path)
  if (kind) return denyReason('writes into ' + KIND_TEXT[kind])
  if (isSettingsFile(path) && editStrings(tool, input).some((s) => mentionsUs(s))) {
    return denyReason("edits barmkin-mod's entries in a settings file")
  }
  return null
}

export const SETTINGS_WRITE_REASON = denyReason("changes barmkin-mod's entries, or a setting that turns hooks off, in a settings file")
export const SETTINGS_EDIT_UNCHECKED_REASON = denyReason(
  'edits a settings file in a way that cannot be checked (the edit cannot be applied to the file as it is)',
)
// A file tool target that may be a hard link to a settings file (review R2).
export const SETTINGS_LINK_REASON = denyReason(
  'edits a file with the size and modification time of a Claude Code settings file, so it may be a second name (a hard link) for it',
)
const SHELL_SETTINGS_REASON = denyReason(
  'writes, moves or removes a Claude Code settings file from the shell, where the change cannot be checked (the Write and Edit tools can be)',
)

export const SWITCH_COMMAND_REASON = denyReason('runs the ' + SWITCH_COMMAND + ' switch command')

// Every entry under a key that names this plugin (`barmkin-mod`, `barmkin-mod@…`)
// or its marketplace, or turns hooks off (HOOKS_OFF_KEYS), anywhere in the JSON,
// as path -> JSON text. The path is part of the entry, so an entry moved under
// another key (a renamed enabledPlugins) is a change. Null when the text is not JSON.
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
      if (key === PROTECTED_PLUGIN || key.startsWith(PROTECTED_PLUGIN + '@') || marketplaces.has(key) || HOOKS_OFF_KEYS.includes(key)) {
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
// its marketplace, or a key that turns hooks off. An Edit is judged the same way,
// on the text it leaves (editedText). Fail closed: a current file that is not
// JSON cannot be compared, so the write counts as a change; a new text that is
// not JSON counts as one when the current file held an entry.
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
// one that names a protected place, a settings file named beside a mention of
// this plugin or its marketplace, or a Claude Code settings file named beside a
// key of the settings that enable plugins or turn hooks off (an MCP write of
// `{"disableAllHooks": true}` names no plugin). Narrower than the shell rule,
// because an MCP input is often prose (an issue body, a message) rather than a
// command.
export function mcpSelfProtectionReason(strings: readonly string[]): string | null {
  for (const s of strings) {
    for (const token of shellTokens(s)) {
      const kind = protectedPathKind(token)
      if (kind) return denyReason('names ' + KIND_TEXT[kind])
    }
  }
  const namesSettings = strings.some((s) => shellTokens(s).some((t) => isSettingsFile(t)))
  if (namesSettings && strings.some((s) => mentionsUs(s))) return denyReason("touches barmkin-mod's entries in the settings files")
  const namesClaudeSettings = strings.some((s) => shellTokens(s).some((t) => isClaudeSettingsPath(t)))
  if (namesClaudeSettings && strings.some((s) => SETTINGS_KEY_MENTION.test(s))) {
    return denyReason('touches the settings that enable plugins or turn hooks off in a Claude Code settings file')
  }
  return null
}