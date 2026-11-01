// Self-protection's settings rules beyond this plugin's own entries: the
// settings keys that turn every mod off, and shell or MCP writes of a settings
// file, which cannot be compared the way a Write or an Edit is.
import { expect, test } from 'claude-code/testing'
import { mcpSelfProtectionReason, shellSelfProtectionReason, writeChangesProtectedEntries } from '../hooks/lib/self-protection'

test('a settings write that adds, changes or removes a key turning hooks off counts as a change', () => {
  expect(writeChangesProtectedEntries(null, '{"disableAllHooks": true}')).toBe(true)
  expect(writeChangesProtectedEntries('{"model": "a"}', '{"model": "a", "disableAllHooks": true}')).toBe(true)
  expect(writeChangesProtectedEntries('{"model": "a"}', '{"model": "a", "allowManagedHooksOnly": true}')).toBe(true)
  expect(writeChangesProtectedEntries('{"model": "a"}', '{"model": "a", "allowManagedModsOnly": true}')).toBe(true)
  expect(writeChangesProtectedEntries('{"disableAllHooks": true}', '{}')).toBe(true)
  // A key left as it was, and every other key, still pass.
  expect(writeChangesProtectedEntries('{"disableAllHooks": false}', '{"disableAllHooks": false, "model": "b"}')).toBe(false)
  expect(writeChangesProtectedEntries('{"model": "a"}', '{"model": "b"}')).toBe(false)
})

test('a shell write of a Claude Code settings file is denied, whatever it names', () => {
  for (const command of [
    "jq '.enabledPlugins = {}' ~/.claude/settings.json > /tmp/s.json && mv /tmp/s.json ~/.claude/settings.json",
    "echo '{\"disableAllHooks\": true}' > ~/.claude/settings.local.json",
    "cd ~/.claude && echo '{\"disableAllHooks\": true}' > settings.json",
    "sed -i '' 's/\"model\"/\"disableAllHooks\": true, \"model\"/' ~/.claude/settings.json",
    "python3 -c \"import json; p='/h/.claude/settings.json'; d=json.load(open(p)); d['enabled' + 'Plugins'] = {}; json.dump(d, open(p, 'w'))\"",
    'cp /tmp/settings.json /proj/.claude/settings.json',
    'tee /proj/.claude/settings.local.json < /tmp/x',
    'rm ~/.claude/settings.json',
    'mv ~/.claude/settings.json ~/.claude/settings.json.bak',
  ]) {
    expect(shellSelfProtectionReason(command)).toContain('settings file')
  }
})

test('a shell read of a settings file, or a write of one that is not Claude Code\'s, runs', () => {
  for (const command of [
    'cat ~/.claude/settings.json',
    'jq .enabledPlugins ~/.claude/settings.json',
    'cp ~/.claude/settings.json /tmp/backup.json',
    'cp /tmp/a.json .vscode/settings.json',
    'grep -rn disableAllHooks docs/ 2>/dev/null',
  ]) {
    expect(shellSelfProtectionReason(command)).toBeNull()
  }
})

test('an MCP call naming a Claude Code settings file beside a key that enables plugins or turns hooks off is denied', () => {
  expect(mcpSelfProtectionReason(['/h/.claude/settings.json', '{"disableAllHooks": true}'])).toContain('settings')
  expect(mcpSelfProtectionReason(['/h/.claude/settings.json', '{"enabledPlugins": {}}'])).toContain('settings')
  expect(mcpSelfProtectionReason(['/h/.claude/settings.json'])).toBeNull()
  expect(mcpSelfProtectionReason(['/proj/.vscode/settings.json', '{"disableAllHooks": true}'])).toBeNull()
})
