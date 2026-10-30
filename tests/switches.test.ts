// Pure tests for the switch registry (hooks/lib/switches.ts), the egress
// escalations a switch can drop (decideEgressWith), and the self-protection
// matchers (hooks/lib/self-protection.ts). The hooks that use them are covered
// in switches-hooks.test.ts.
import { expect, test } from 'claude-code/testing'
import {
  SWITCH_DEFS,
  SWITCH_IDS,
  defaultSwitches,
  normalizeSwitches,
  toStoreValue,
  canonicalJson,
  storeFingerprint,
  checkStore,
  parseRuleArgs,
  originMayChangeSwitches,
  originKindOf,
  egressClassEnabled,
  protectionsOff,
  describeSwitchList,
  describeSwitchChange,
  type SwitchMap,
} from '../hooks/lib/switches'
import { classifyEgress, decideEgress, decideEgressWith, type TrifectaLegs } from '../hooks/lib/egress'
import {
  protectedPathKind,
  shellSelfProtectionReason,
  fileSelfProtectionReason,
  writeChangesProtectedEntries,
  isSwitchCommandSkill,
  mcpSelfProtectionReason,
} from '../hooks/lib/self-protection'

const allOn = (): SwitchMap => defaultSwitches()
const withOff = (...ids: (keyof SwitchMap)[]): SwitchMap => {
  const map = allOn()
  for (const id of ids) map[id] = false
  return map
}

test('every switch has a unique id, a description and an off text, and all default to on', () => {
  expect(new Set(SWITCH_IDS).size).toBe(SWITCH_DEFS.length)
  for (const def of SWITCH_DEFS) {
    expect(def.description.length > 0).toBe(true)
    expect(def.whenOff.length > 0).toBe(true)
  }
  expect(Object.values(defaultSwitches()).every((v) => v === true)).toBe(true)
  expect(Object.keys(defaultSwitches()).sort()).toEqual([...SWITCH_IDS].sort())
})

test('a missing, malformed or partial stored value reads every unreadable switch as on', () => {
  expect(normalizeSwitches(undefined)).toEqual(allOn())
  expect(normalizeSwitches('nonsense')).toEqual(allOn())
  expect(normalizeSwitches({ switches: [false] })).toEqual(allOn())
  expect(normalizeSwitches({ switches: { taint: 'off', 'no-such-switch': false } })).toEqual(allOn())
  expect(normalizeSwitches({ switches: { taint: false } })).toEqual(withOff('taint'))
})

test('the store value round-trips, and its fingerprint ignores key order', () => {
  const map = withOff('redaction', 'mcp-guard')
  const value = toStoreValue(map)
  expect(normalizeSwitches(value)).toEqual(map)
  const reordered = { switches: Object.fromEntries(Object.entries(value.switches).reverse()), version: value.version }
  expect(canonicalJson(reordered)).toBe(canonicalJson(value))
  expect(storeFingerprint(reordered)).toBe(storeFingerprint(value))
  expect(storeFingerprint(toStoreValue(allOn()))).not.toBe(storeFingerprint(value))
})

test('tamper check: no fingerprint yet loads the store as it is', () => {
  const stored = toStoreValue(withOff('taint'))
  const check = checkStore(null, null, stored)
  expect(check.kind).toBe('load')
  expect(check.map).toEqual(withOff('taint'))
  expect(check.hash).toBe(storeFingerprint(stored))
})

test('tamper check: a store matching the recorded fingerprint is unchanged', () => {
  const known = withOff('taint')
  const stored = toStoreValue(known)
  expect(checkStore(known, storeFingerprint(stored), stored).kind).toBe('unchanged')
})

test('tamper check: a store edited elsewhere is ignored and this session restores its own value', () => {
  const known = withOff('taint')
  const knownHash = storeFingerprint(toStoreValue(known))
  const edited = toStoreValue(withOff('taint', 'self-protection', 'egress-gate'))
  const check = checkStore(known, knownHash, edited)
  expect(check.kind).toBe('restore')
  expect(check.map).toEqual(known)
  if (check.kind !== 'restore') throw new Error('expected a restore')
  expect(check.storeValue).toEqual(toStoreValue(known))
  expect(check.hash).toBe(knownHash)
})

test('tamper check: with this session\'s self-protection off, an edited store is accepted', () => {
  const known = withOff('self-protection')
  const edited = toStoreValue(withOff('self-protection', 'taint'))
  const check = checkStore(known, storeFingerprint(toStoreValue(known)), edited)
  expect(check.kind).toBe('accept')
  expect(check.map).toEqual(withOff('self-protection', 'taint'))
})

test('tamper check: an edit that turns self-protection off is still refused, because this session\'s value decides', () => {
  const known = allOn()
  const edited = toStoreValue(withOff('self-protection'))
  expect(checkStore(known, storeFingerprint(toStoreValue(known)), edited).kind).toBe('restore')
})

test('/barmkin-mod-rule arguments: list, set, and the errors', () => {
  expect(parseRuleArgs('')).toEqual({ kind: 'list' })
  expect(parseRuleArgs('  list ')).toEqual({ kind: 'list' })
  expect(parseRuleArgs('taint off')).toEqual({ kind: 'set', id: 'taint', on: false })
  expect(parseRuleArgs('Egress-Gate ON')).toEqual({ kind: 'set', id: 'egress-gate', on: true })
  expect(parseRuleArgs('no-such off').kind).toBe('error')
  expect(parseRuleArgs('taint maybe').kind).toBe('error')
  expect(parseRuleArgs('taint off now').kind).toBe('error')
  expect(parseRuleArgs(undefined)).toEqual({ kind: 'list' })
})

test('only the composer and the bridge may change a switch', () => {
  expect(originMayChangeSwitches({ kind: 'composer' })).toBe(true)
  expect(originMayChangeSwitches({ kind: 'bridge' })).toBe(true)
  for (const origin of [
    { kind: 'plugin', name: 'other' },
    { kind: 'plugin', name: 'barmkin-mod', asUser: true },
    { kind: 'sdk' },
    { kind: 'task-notification' },
    { kind: 'scheduled-trigger' },
    { kind: 'peer' },
    { kind: 'peer-send-message' },
    { kind: 'unclassified' },
    undefined,
    null,
    'composer',
  ]) {
    expect(originMayChangeSwitches(origin)).toBe(false)
  }
  expect(originKindOf({ kind: 'sdk' })).toBe('sdk')
  expect(originKindOf(undefined)).toBe('none')
})

test('egress classes follow their own switch: the destructive tier apart from the egress gate', () => {
  expect(egressClassEnabled('network-shell', withOff('egress-gate'))).toBe(false)
  expect(egressClassEnabled('destructive', withOff('egress-gate'))).toBe(true)
  expect(egressClassEnabled('history-rewrite', withOff('destructive-tier'))).toBe(false)
  expect(egressClassEnabled('network-shell', withOff('destructive-tier'))).toBe(true)
})

const legs = (untrusted: boolean, sensitive: boolean): TrifectaLegs => ({
  untrusted,
  untrustedReason: untrusted ? 'test' : null,
  sensitive,
  sensitiveReason: sensitive ? 'test' : null,
  ackRequired: false,
})

test('decideEgressWith with both escalations on is decideEgress', () => {
  for (const command of ['git push origin main', 'curl https://x.example', 'rm -rf ~', 'ls']) {
    const classes = classifyEgress({ tool: 'Bash', input: { command } })
    for (const [u, s] of [[false, false], [true, false], [false, true], [true, true]] as const) {
      expect(decideEgressWith(classes, legs(u, s), { taintBlocksEgress: true, ruleOfTwo: true })).toEqual(decideEgress(classes, legs(u, s)))
    }
  }
})

test('decideEgressWith drops an escalation whose switch is off, and never answers allow', () => {
  const push = classifyEgress({ tool: 'Bash', input: { command: 'git push origin main' } })
  expect(decideEgressWith(push, legs(true, false), { taintBlocksEgress: false, ruleOfTwo: true }).kind).toBe('pass')
  expect(decideEgressWith(push, legs(true, true), { taintBlocksEgress: false, ruleOfTwo: true }).kind).toBe('deny')
  const noRuleOfTwo = decideEgressWith(push, legs(true, true), { taintBlocksEgress: true, ruleOfTwo: false })
  expect(noRuleOfTwo.kind).toBe('deny')
  expect(noRuleOfTwo.kind === 'deny' ? noRuleOfTwo.rule : '').toBe('untrusted')
  const wipe = classifyEgress({ tool: 'Bash', input: { command: 'rm -rf ~' } })
  // A clean-session warning stays a warning: off means less suspicion, never allow.
  expect(decideEgressWith(wipe, legs(true, false), { taintBlocksEgress: false, ruleOfTwo: false }).kind).toBe('warn')
})

test('the shadow screen being off is not a switched-off protection', () => {
  expect(protectionsOff(withOff('shadow-screen'))).toEqual([])
  expect(protectionsOff(withOff('shadow-screen', 'taint'))).toEqual(['taint'])
})

test('the list names every switch and its state; a change says what off means', () => {
  const list = describeSwitchList(withOff('taint'))
  for (const id of SWITCH_IDS) expect(list).toContain(id)
  expect(list).toContain('OFF  taint')
  expect(describeSwitchChange('taint', false)).toContain('nothing marks the session tainted')
  expect(describeSwitchChange('taint', true)).toBe('barmkin-mod: taint is now on.')
})

test('protected paths: the store file, the installed copy and the marketplace clone, in any spelling', () => {
  expect(protectedPathKind('/Users/x/.claude/plugins/store/barmkin-mod_emasoft-barmkin-0123456789ab.json')).toBe('store')
  expect(protectedPathKind('~/.claude/plugins/store/barmkin-mod_inline-0123456789ab.json')).toBe('store')
  expect(protectedPathKind('plugins/store/barmkin-mod_*.json')).toBe('store')
  expect(protectedPathKind('~/.claude/plugins/store/*')).toBe('store')
  expect(protectedPathKind('barmkin-mod_inline-0123456789ab.json')).toBe('store')
  expect(protectedPathKind('/h/.claude/plugins/cache/emasoft-barmkin/barmkin-mod/0.2.2/hooks/register.ts')).toBe('install')
  expect(protectedPathKind('/h/.claude/plugins/cache/emasoft-*/x')).toBe('install')
  expect(protectedPathKind('/h/.claude/plugins/marketplaces/emasoft-barmkin/README.md')).toBe('marketplace')
  expect(protectedPathKind('/h/.claude/plugins/store/other-plugin_x-0123.json')).toBe(null)
  expect(protectedPathKind('/h/Code/barmkin-mod/hooks/register.ts')).toBe(null)
  expect(protectedPathKind('/h/.claude/plugins/cache/other-market/x')).toBe(null)
})

test('shell self-protection: uninstall, disable, marketplace removal, the switch command and the store', () => {
  for (const command of [
    'claude plugin disable barmkin-mod@emasoft-barmkin',
    'claude plugin uninstall barmkin-mod',
    '/usr/local/bin/claude plugins remove barmkin-mod --scope user',
    'claude plugin marketplace remove emasoft-barmkin',
    'claude -p "/barmkin-mod-rule taint off"',
    'rm -f ~/.claude/plugins/store/barmkin-mod_*',
    'echo {} > ~/.claude/plugins/store/barmkin-mod_inline-0123456789ab.json',
    'dd if=/dev/zero of=/h/.claude/plugins/cache/emasoft-barmkin/barmkin-mod/0.2.2/hooks/register.ts',
    'jq \'del(.enabledPlugins["barmkin-mod@emasoft-barmkin"])\' ~/.claude/settings.json',
  ]) {
    expect(shellSelfProtectionReason(command)).toContain('self-protection')
  }
  for (const command of ['git status', 'claude plugin list', 'claude plugin disable other-plugin', 'ls ~/.claude/plugins/store', 'cat ~/.claude/settings.json']) {
    expect(shellSelfProtectionReason(command)).toBe(null)
  }
})

test('file self-protection: writes into protected places and edits naming this plugin in a settings file', () => {
  const store = '/h/.claude/plugins/store/barmkin-mod_inline-0123456789ab.json'
  expect(fileSelfProtectionReason('Write', { content: '{}' }, store)).toContain('switch store')
  expect(fileSelfProtectionReason('Edit', { old_string: 'a', new_string: 'b' }, '/h/.claude/plugins/cache/emasoft-barmkin/barmkin-mod/0.2.2/hooks/register.ts')).toContain('installed copy')
  expect(
    fileSelfProtectionReason('Edit', { old_string: '"barmkin-mod@emasoft-barmkin": true', new_string: '"barmkin-mod@emasoft-barmkin": false' }, '/h/.claude/settings.json'),
  ).toContain('settings')
  expect(
    fileSelfProtectionReason('MultiEdit', { edits: [{ old_string: 'x', new_string: '"barmkin-mod@emasoft-barmkin": false' }] }, '/p/.claude/settings.local.json'),
  ).toContain('settings')
  expect(fileSelfProtectionReason('Edit', { old_string: '"model": "a"', new_string: '"model": "b"' }, '/h/.claude/settings.json')).toBe(null)
  expect(fileSelfProtectionReason('Write', { content: 'x' }, '/p/src/a.ts')).toBe(null)
})

test('a settings Write is refused only when it changes, adds or removes this plugin\'s entries', () => {
  const before = JSON.stringify({ model: 'a', enabledPlugins: { 'barmkin-mod@emasoft-barmkin': true, 'x@y': true } })
  expect(writeChangesProtectedEntries(before, JSON.stringify({ model: 'b', enabledPlugins: { 'barmkin-mod@emasoft-barmkin': true } }))).toBe(false)
  expect(writeChangesProtectedEntries(before, JSON.stringify({ model: 'a', enabledPlugins: { 'barmkin-mod@emasoft-barmkin': false } }))).toBe(true)
  expect(writeChangesProtectedEntries(before, JSON.stringify({ model: 'a', enabledPlugins: {} }))).toBe(true)
  expect(writeChangesProtectedEntries(before, '{}')).toBe(true)
  expect(writeChangesProtectedEntries(before, 'not json')).toBe(true)
  expect(writeChangesProtectedEntries(null, '{}')).toBe(false)
  expect(writeChangesProtectedEntries(null, JSON.stringify({ enabledPlugins: { 'barmkin-mod@emasoft-barmkin': false } }))).toBe(true)
  expect(writeChangesProtectedEntries('not json', '{}')).toBe(true)
})

test('the Skill tool may not run the switch command, in any spelling', () => {
  for (const skill of ['barmkin-mod-rule', '/barmkin-mod-rule', 'barmkin-mod:barmkin-mod-rule', ' barmkin-mod-rule ']) {
    expect(isSwitchCommandSkill(skill)).toBe(true)
  }
  for (const skill of ['barmkin-mod-panel', 'barmkin-mod-status', 'other', undefined]) {
    expect(isSwitchCommandSkill(skill)).toBe(false)
  }
})

test('shell self-protection: removing or moving a folder that holds this plugin, but not a project plugins folder', () => {
  for (const command of ['rm -rf ~/.claude/plugins', 'rm -rf /h/.claude/plugins/cache', 'mv ~/.claude/plugins/marketplaces /tmp/x', 'rm -rf ~/.claude/plugins/*', 'rm -rf ~/.claude']) {
    expect(shellSelfProtectionReason(command)).toContain('folder that holds barmkin-mod')
  }
  for (const command of ['rm -rf plugins', 'rm -rf /p/src/plugins/cache', 'ls ~/.claude/plugins/cache', 'cp -r ~/.claude/plugins/cache /tmp/backup']) {
    expect(shellSelfProtectionReason(command)).toBe(null)
  }
})
test('MCP self-protection: a protected path, or a settings file named beside this plugin', () => {
  expect(mcpSelfProtectionReason(['/h/.claude/plugins/store/barmkin-mod_inline-0123456789ab.json', '{}'])).toContain('self-protection')
  expect(mcpSelfProtectionReason(['/h/.claude/settings.json', '{"enabledPlugins":{"barmkin-mod@emasoft-barmkin":false}}'])).toContain('settings')
  expect(mcpSelfProtectionReason(['/p/notes.md', 'barmkin-mod is a mod'])).toBe(null)
  expect(mcpSelfProtectionReason(['/h/.claude/settings.json', '{"model":"a"}'])).toBe(null)
})
