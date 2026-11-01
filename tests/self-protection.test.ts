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
    'dd if=/tmp/x of=/home/u/.claude/settings.json',
    // Names only Claude Code uses, outside a folder named .claude: managed
    // settings, and a configuration folder moved by CLAUDE_CONFIG_DIR.
    'cp /tmp/m.json /etc/claude-code/managed-settings.json',
    'cp /tmp/p.json /srv/claude-config/plugins/installed_plugins.json',
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

test('the store folder named without the file is protected from writes, and from a glob that could name the store', () => {
  for (const command of [
    "find ~/.claude/plugins/store -name 'barmkin*' -exec perl -pi -e 's/true/false/g' {} +",
    'cd ~/.claude/plugins/store && sed -i s/true/false/ b*',
    'cp /tmp/evil.json ~/.claude/plugins/store/',
    "find ~/.claude -name 'barmkin*' -exec perl -pi -e 's/true/false/g' {} +",
    'rm -rf ~/.claude/plugins/store',
    // The store folder named by a glob, and a find that runs any program on it.
    "find ~/.claude/plugins/st* -name 'barmkin*' -exec perl -pi -e 's/true/false/g' {} +",
    'find ~/.claude/plugins/store -type f -exec ./patch-switches {} +',
  ]) {
    expect(shellSelfProtectionReason(command)).toContain('self-protection')
  }
})

test('the store folder may be listed, another plugin\'s store read, and the configuration folder searched', () => {
  for (const command of [
    'ls ~/.claude/plugins/store',
    // A redirection to /dev/null writes no file.
    'ls ~/.claude/plugins/store 2>/dev/null',
    'cat ~/.claude/plugins/store/other-plugin_market-0123456789ab.json',
    "find ~/.claude -name '*.md' -exec grep -l x {} +",
  ]) {
    expect(shellSelfProtectionReason(command)).toBeNull()
  }
})

// Review R6 of the 0.3.0 fix round: editors that take their commands from a flag or
// from stdin, gawk -i inplace, and plutil write the file they name.
test('a settings write through ed, ex, vim, gawk -i inplace or plutil is denied; a read runs', () => {
  for (const command of [
    'ed ~/.claude/settings.json < /tmp/script',
    "ex -sc '%s/a/b/|wq' ~/.claude/settings.json",
    "vim -es -c ':wq' ~/.claude/settings.local.json",
    "gawk -i inplace '{print}' ~/.claude/settings.json",
    'plutil -replace disableAllHooks -bool true ~/.claude/settings.json',
  ]) {
    expect(shellSelfProtectionReason(command) ?? 'allowed: ' + command).toContain('settings file')
  }
  for (const command of ["awk '{print}' ~/.claude/settings.json", 'plutil -p ~/.claude/settings.json', 'vim --version']) {
    expect(shellSelfProtectionReason(command)).toBeNull()
  }
})
