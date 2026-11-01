// The marketplace the running copy was installed from is protected beside the
// one this plugin is published in, so a copy installed from another
// marketplace (the upstream project's, say) is covered too.
import { expect, test } from 'claude-code/testing'
import {
  configDirFromRoot,
  marketplaceFromRoot,
  protectMarketplace,
  protectedEntries,
  protectedPathKind,
  shellSelfProtectionReason,
  mcpSelfProtectionReason,
  writeChangesProtectedEntries,
} from '../hooks/lib/self-protection'

test('the marketplace is read from an installed copy\'s folder, and from no other folder', () => {
  expect(marketplaceFromRoot('/h/.claude/plugins/cache/upstream-mkt/barmkin-mod/0.3.0')).toBe('upstream-mkt')
  expect(marketplaceFromRoot('C:\\Users\\u\\.claude\\plugins\\cache\\upstream-mkt\\barmkin-mod\\0.3.0')).toBe('upstream-mkt')
  expect(marketplaceFromRoot('/work/barmkin-mod')).toBeNull()
  expect(marketplaceFromRoot('/h/.claude/plugins/cache/upstream-mkt/another-plugin/1.0.0')).toBeNull()
  expect(marketplaceFromRoot(undefined)).toBeNull()
})

test('a marketplace added at session start is protected like the published one', () => {
  expect(shellSelfProtectionReason('claude plugin marketplace remove upstream-mkt')).toBeNull()
  protectMarketplace('upstream-mkt')
  expect(shellSelfProtectionReason('claude plugin marketplace remove upstream-mkt')).toContain('marketplace')
  expect(protectedPathKind('~/.claude/plugins/cache/upstream-mkt/barmkin-mod/0.3.0/hooks/register.ts')).toBe('install')
  expect(protectedPathKind('~/.claude/plugins/marketplaces/upstream-mkt/README.md')).toBe('marketplace')
  expect(protectedPathKind('~/.claude/plugins/store/*_upstream-mkt-*.json')).toBe('store')
  expect(protectedEntries('{"extraKnownMarketplaces": {"upstream-mkt": {"source": "x"}}}')?.size).toBe(1)
  expect(shellSelfProtectionReason('grep upstream-mkt ~/.claude/settings.json')).toContain('settings')
  // A name that is not a plain marketplace name is ignored.
  protectMarketplace('a b|.*')
  expect(shellSelfProtectionReason('claude plugin marketplace remove x')).toBeNull()
})

// Review R5 of the 0.3.0 fix round: a marketplace name is matched as a whole name,
// so a copy installed from a marketplace with a common name (local) does not turn
// every mention of settings.local.json or localhost into a mention of this plugin.
test('a marketplace name counts only as a whole name, not inside a longer one', () => {
  protectMarketplace('local')
  expect(shellSelfProtectionReason('cat .claude/settings.local.json')).toBeNull()
  expect(shellSelfProtectionReason('grep localhost .claude/settings.json')).toBeNull()
  expect(mcpSelfProtectionReason(['/h/.claude/settings.local.json', 'list the keys'])).toBeNull()
  // A whole name still counts, as the marketplace itself or in a repository URL.
  expect(shellSelfProtectionReason('claude plugin marketplace remove local') ?? 'allowed').toContain('barmkin-mod:')
  expect(mcpSelfProtectionReason(['/h/.claude/settings.json', 'add github.com/Emasoft/emasoft-barmkin.git']) ?? 'allowed').toContain('barmkin-mod:')
  expect(mcpSelfProtectionReason(['/h/.claude/settings.json', 'drop barmkin-mod@local']) ?? 'allowed').toContain('barmkin-mod:')
})

// The configuration folder the hard-link check compares against (review R2) is read
// from an installed copy's folder; a copy anywhere else gives none, and register.ts
// then falls back to CLAUDE_CONFIG_DIR or HOME.
test('the configuration folder is read from an installed copy\'s folder, and from no other folder', () => {
  expect(configDirFromRoot('/h/.claude/plugins/cache/emasoft-barmkin/barmkin-mod/0.3.1')).toBe('/h/.claude')
  expect(configDirFromRoot('/srv/claude-config/plugins/cache/upstream-mkt/barmkin-mod/0.3.1')).toBe('/srv/claude-config')
  expect(configDirFromRoot('C:\\Users\\u\\.claude\\plugins\\cache\\m\\barmkin-mod\\0.3.1')).toBe('C:/Users/u/.claude')
  expect(configDirFromRoot('/work/barmkin-mod')).toBeNull()
  expect(configDirFromRoot(undefined)).toBeNull()
})

// mentionsUs compares the lower-cased command, so a marketplace name with capitals
// must be kept lower-cased too, or it never matches (review R1); a mutation that
// kept it as given survived every other test.
test('a marketplace name with capitals is matched in any case', () => {
  protectMarketplace('Mixed-Case-Mkt')
  expect(shellSelfProtectionReason('claude plugin marketplace remove mixed-case-mkt') ?? 'allowed').toContain('barmkin-mod:')
  expect(shellSelfProtectionReason('claude plugin marketplace remove Mixed-Case-Mkt') ?? 'allowed').toContain('barmkin-mod:')
  expect(shellSelfProtectionReason('claude plugin marketplace remove MIXED-CASE-MKT') ?? 'allowed').toContain('barmkin-mod:')
  expect(shellSelfProtectionReason('claude plugin marketplace remove other-mkt')).toBeNull()
})

// protectedEntries reads the JSON keys as written, while protectMarketplace keeps a
// name lower-cased, so a key is folded before it is compared (Greptile on PR #1): a
// Write that drops the entry of a marketplace registered with capitals is a change.
test('a settings Write that drops the entry of a marketplace or plugin key with capitals is a protected change', () => {
  protectMarketplace('Some-Market')
  const before = '{"extraKnownMarketplaces": {"Some-Market": {"source": {"source": "github", "repo": "o/r"}}}}'
  expect(writeChangesProtectedEntries(before, '{"extraKnownMarketplaces": {}}')).toBe(true)
  expect(writeChangesProtectedEntries('{"enabledPlugins": {"Barmkin-Mod@Some-Market": true}}', '{"enabledPlugins": {}}')).toBe(true)
  expect(writeChangesProtectedEntries('{"extraKnownMarketplaces": {"unrelated-market": {}}}', '{"extraKnownMarketplaces": {}}')).toBe(false)
})
