import { expect, test } from 'claude-code/testing'
import { checkPosture } from '../hooks/lib/posture'

// A copy of packaging/managed-settings.example.json: `claude plugin test` loads
// only code files, so the recipe is mirrored here, and the recipe test below
// fails if the floor it documents stops satisfying checkPosture. Keep the two
// in step; tests/workflows/test_managed_settings_recipe.py checks the JSON file itself.
const MANAGED_SETTINGS_EXAMPLE = {
  prependPlugins: ['barmkin-mod@your-marketplace', 'cc-plugin-sec-default@builtin'],
  disableSkillShellExecution: true,
  allowManagedMcpServersOnly: true,
  allowedMcpServers: [{ serverName: 'github' }],
  sandbox: {
    enabled: true,
    failIfUnavailable: true,
    allowUnsandboxedCommands: false,
    network: {
      allowManagedDomainsOnly: true,
      allowAllUnixSockets: false,
      allowedDomains: ['github.com', 'api.github.com', 'registry.npmjs.org'],
    },
    credentials: {
      envVars: [{ name: 'GITHUB_TOKEN', mode: 'mask', injectHosts: ['api.github.com'] }],
    },
  },
}

const FLOOR_SANDBOX = {
  enabled: true,
  failIfUnavailable: true,
  allowUnsandboxedCommands: false,
  network: { allowManagedDomainsOnly: true },
  credentials: { files: [{ path: '~/.netrc', mode: 'mask' }] },
}
const FLOOR_POLICY = {
  prependPlugins: ['barmkin-mod@acme', 'sec-default@builtin'],
  sandbox: FLOOR_SANDBOX,
  allowManagedMcpServersOnly: true,
  allowedMcpServers: [{ serverName: 'github' }],
}
const GOOD_SEAT = { merged: { sandbox: FLOOR_SANDBOX, disableSkillShellExecution: true }, policy: FLOOR_POLICY }

// The floor with one merged sandbox key changed, for the per-setting tests.
function withSandbox(sandbox: Record<string, unknown>) {
  return { merged: { sandbox: { ...FLOOR_SANDBOX, ...sandbox }, disableSkillShellExecution: true }, policy: FLOOR_POLICY }
}

test('warns when not seated in managed prependPlugins at all', () => {
  const warnings = checkPosture({ merged: {}, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('is not in managed prependPlugins'))).toBe(true)
})

test('warns when sec-default is seated ahead of this plugin', () => {
  const warnings = checkPosture(
    { merged: {}, policy: { prependPlugins: ['sec-default@builtin', 'barmkin-mod@acme'] } },
    'barmkin-mod',
    [],
  )
  expect(warnings.some((w) => w.includes('sec-default is seated ahead'))).toBe(true)
})

test('the sec-default seat warning names skill.prompt, the skill-body screen it hides', () => {
  const warnings = checkPosture(
    { merged: {}, policy: { prependPlugins: ['sec-default@builtin', 'barmkin-mod@acme'] } },
    'barmkin-mod',
    [],
  )
  expect(warnings.some((w) => w.includes('sec-default is seated ahead') && w.includes('skill.prompt'))).toBe(true)
})

test('does not warn about seating when this plugin is ahead of sec-default', () => {
  const warnings = checkPosture(
    { merged: { sandbox: { enabled: true }, disableSkillShellExecution: true }, policy: { prependPlugins: ['barmkin-mod@acme', 'sec-default@builtin'] } },
    'barmkin-mod',
    ['github'],
  )
  expect(warnings.some((w) => w.includes('is not in managed prependPlugins'))).toBe(false)
  expect(warnings.some((w) => w.includes('sec-default is seated ahead'))).toBe(false)
})

test('warns on bypassPermissions default mode', () => {
  const warnings = checkPosture({ merged: { permissions: { defaultMode: 'bypassPermissions' } }, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('bypassPermissions'))).toBe(true)
})

test('does not warn on a non-bypass permission mode', () => {
  const warnings = checkPosture({ merged: { permissions: { defaultMode: 'default' } }, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('bypassPermissions'))).toBe(false)
})

test('warns when the sandbox is off or unset', () => {
  expect(checkPosture({ merged: {}, policy: {} }, 'barmkin-mod', []).some((w) => w.includes('sandbox'))).toBe(true)
  expect(checkPosture({ merged: { sandbox: { enabled: false } }, policy: {} }, 'barmkin-mod', []).some((w) => w.includes('sandbox'))).toBe(true)
})

test('does not warn when the sandbox is explicitly enabled', () => {
  const warnings = checkPosture({ merged: { sandbox: { enabled: true } }, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('Bash sandbox is off'))).toBe(false)
})

test('warns when disableSkillShellExecution is unset', () => {
  expect(checkPosture({ merged: {}, policy: {} }, 'barmkin-mod', []).some((w) => w.includes('disableSkillShellExecution'))).toBe(true)
  expect(
    checkPosture({ merged: { disableSkillShellExecution: false }, policy: {} }, 'barmkin-mod', []).some((w) =>
      w.includes('disableSkillShellExecution'),
    ),
  ).toBe(true)
})

test('does not warn when disableSkillShellExecution is true', () => {
  const warnings = checkPosture({ merged: { disableSkillShellExecution: true }, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('disableSkillShellExecution'))).toBe(false)
})

test('warns when the mcp server allowlist is empty', () => {
  const warnings = checkPosture({ merged: {}, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('mcp_server_allowlist'))).toBe(true)
})

test('does not warn when the mcp server allowlist is set', () => {
  const warnings = checkPosture({ merged: {}, policy: {} }, 'barmkin-mod', ['github', 'linear'])
  expect(warnings.some((w) => w.includes('mcp_server_allowlist'))).toBe(false)
})

test('warns when sandbox.failIfUnavailable is unset or false', () => {
  expect(checkPosture(withSandbox({ failIfUnavailable: undefined }), 'barmkin-mod', ['github']).some((w) => w.includes('failIfUnavailable'))).toBe(true)
  expect(checkPosture(withSandbox({ failIfUnavailable: false }), 'barmkin-mod', ['github']).some((w) => w.includes('failIfUnavailable'))).toBe(true)
})

test('does not warn when sandbox.failIfUnavailable is true', () => {
  expect(checkPosture(withSandbox({ failIfUnavailable: true }), 'barmkin-mod', ['github']).some((w) => w.includes('failIfUnavailable'))).toBe(false)
})

test('warns when sandbox.allowUnsandboxedCommands is unset or true, since it defaults to true', () => {
  for (const value of [undefined, true]) {
    const warnings = checkPosture(withSandbox({ allowUnsandboxedCommands: value }), 'barmkin-mod', ['github'])
    expect(warnings.some((w) => w.includes('allowUnsandboxedCommands is not false'))).toBe(true)
  }
})

test('does not warn when sandbox.allowUnsandboxedCommands is false', () => {
  const warnings = checkPosture(withSandbox({ allowUnsandboxedCommands: false }), 'barmkin-mod', ['github'])
  expect(warnings.some((w) => w.includes('allowUnsandboxedCommands'))).toBe(false)
})

test('warns when sandbox.network.allowAllUnixSockets is on', () => {
  const warnings = checkPosture(
    withSandbox({ network: { allowManagedDomainsOnly: true, allowAllUnixSockets: true } }),
    'barmkin-mod',
    ['github'],
  )
  expect(warnings.some((w) => w.includes('allowAllUnixSockets is on'))).toBe(true)
})

test('does not warn about Unix sockets when allowAllUnixSockets is unset or false', () => {
  for (const network of [{}, { allowAllUnixSockets: false }, { allowUnixSockets: ['/run/app.sock'] }]) {
    const warnings = checkPosture(withSandbox({ network }), 'barmkin-mod', ['github'])
    expect(warnings.some((w) => w.includes('allowAllUnixSockets'))).toBe(false)
  }
})

test('warns about broad Unix sockets even when the sandbox is off', () => {
  const warnings = checkPosture({ merged: { sandbox: { network: { allowAllUnixSockets: true } } }, policy: {} }, 'barmkin-mod', [])
  expect(warnings.some((w) => w.includes('allowAllUnixSockets is on'))).toBe(true)
})

test('warns when sandbox.credentials has no mask entry', () => {
  for (const credentials of [
    undefined,
    {},
    { files: [] },
    { files: [{ path: '~/.netrc', mode: 'deny' }], envVars: [{ name: 'GITHUB_TOKEN', mode: 'deny' }] },
    { files: 'not-a-list' },
  ]) {
    const warnings = checkPosture(withSandbox({ credentials }), 'barmkin-mod', ['github'])
    expect(warnings.some((w) => w.includes('sandbox.credentials has no mask entry'))).toBe(true)
  }
})

test('does not warn when a credential file or environment variable is masked', () => {
  for (const credentials of [
    { files: [{ path: '~/.netrc', mode: 'mask' }] },
    { envVars: [{ name: 'GITHUB_TOKEN', mode: 'mask', injectHosts: ['api.github.com'] }] },
    { files: [{ path: '~/.aws/credentials', mode: 'deny' }], envVars: [{ name: 'NPM_TOKEN', mode: 'mask' }] },
  ]) {
    const warnings = checkPosture(withSandbox({ credentials }), 'barmkin-mod', ['github'])
    expect(warnings.some((w) => w.includes('sandbox.credentials'))).toBe(false)
  }
})

test('warns when managed allowManagedDomainsOnly is unset, false or set only outside managed settings', () => {
  for (const network of [undefined, {}, { allowManagedDomainsOnly: false }]) {
    const policy = { ...FLOOR_POLICY, sandbox: { ...FLOOR_SANDBOX, network } }
    const warnings = checkPosture({ merged: GOOD_SEAT.merged, policy }, 'barmkin-mod', ['github'])
    expect(warnings.some((w) => w.includes('allowManagedDomainsOnly is unset'))).toBe(true)
  }
  // GOOD_SEAT.merged carries it; only the managed source counts.
  const policy = { ...FLOOR_POLICY, sandbox: undefined }
  expect(checkPosture({ merged: GOOD_SEAT.merged, policy }, 'barmkin-mod', ['github']).some((w) => w.includes('allowManagedDomainsOnly is unset'))).toBe(true)
})

test('does not warn when managed allowManagedDomainsOnly is true', () => {
  const warnings = checkPosture(GOOD_SEAT, 'barmkin-mod', ['github'])
  expect(warnings.some((w) => w.includes('allowManagedDomainsOnly'))).toBe(false)
})

test('warns when the managed MCP lock is missing either half', () => {
  const variants = [
    { allowManagedMcpServersOnly: undefined },
    { allowManagedMcpServersOnly: false },
    { allowedMcpServers: undefined },
    { allowedMcpServers: 'github' },
  ]
  for (const variant of variants) {
    const warnings = checkPosture({ merged: GOOD_SEAT.merged, policy: { ...FLOOR_POLICY, ...variant } }, 'barmkin-mod', ['github'])
    expect(warnings.some((w) => w.includes('allowManagedMcpServersOnly and allowedMcpServers are not both set'))).toBe(true)
  }
})

test('the managed MCP lock is read from managed settings only', () => {
  const merged = { ...GOOD_SEAT.merged, allowManagedMcpServersOnly: true, allowedMcpServers: [{ serverName: 'github' }] }
  const policy = { ...FLOOR_POLICY, allowManagedMcpServersOnly: undefined, allowedMcpServers: undefined }
  const warnings = checkPosture({ merged, policy }, 'barmkin-mod', ['github'])
  expect(warnings.some((w) => w.includes('allowManagedMcpServersOnly and allowedMcpServers are not both set'))).toBe(true)
})

test('does not warn when the managed MCP lock is set, even with an empty allowedMcpServers list', () => {
  for (const allowedMcpServers of [[{ serverName: 'github' }], []]) {
    const warnings = checkPosture({ merged: GOOD_SEAT.merged, policy: { ...FLOOR_POLICY, allowedMcpServers } }, 'barmkin-mod', ['github'])
    expect(warnings.some((w) => w.includes('allowManagedMcpServersOnly'))).toBe(false)
  }
})

test('the packaged managed-settings recipe satisfies every posture check', () => {
  const warnings = checkPosture({ merged: MANAGED_SETTINGS_EXAMPLE, policy: MANAGED_SETTINGS_EXAMPLE }, 'barmkin-mod', ['github'])
  expect(warnings).toEqual([])
})

test('warns when cc-plugin-sec-default@builtin is seated ahead of this plugin', () => {
  const warnings = checkPosture(
    { merged: {}, policy: { prependPlugins: ['cc-plugin-sec-default@builtin', 'barmkin-mod@acme'] } },
    'barmkin-mod',
    [],
  )
  expect(warnings.some((w) => w.includes('sec-default is seated ahead'))).toBe(true)
})

test('does not warn when this plugin is ahead of cc-plugin-sec-default@builtin', () => {
  const warnings = checkPosture(
    { merged: {}, policy: { prependPlugins: ['barmkin-mod@acme', 'cc-plugin-sec-default@builtin'] } },
    'barmkin-mod',
    [],
  )
  expect(warnings.some((w) => w.includes('sec-default is seated ahead'))).toBe(false)
})

test('a fully hardened posture produces no warnings', () => {
  const warnings = checkPosture(GOOD_SEAT, 'barmkin-mod', ['github'])
  expect(warnings).toEqual([])
})

test('a failed policy read reports seating as unverified and still runs the merged checks', () => {
  const warnings = checkPosture({ merged: {}, policy: null }, 'barmkin-mod', ['github'])
  expect(warnings.some((w) => w.includes('seating, managed domain and managed MCP checks unverified'))).toBe(true)
  expect(warnings.some((w) => w.includes('allowManagedDomainsOnly is unset'))).toBe(false)
  expect(warnings.some((w) => w.includes('allowManagedMcpServersOnly and allowedMcpServers'))).toBe(false)
  expect(warnings.some((w) => w.includes('is not in managed prependPlugins'))).toBe(false)
  expect(warnings.some((w) => w.includes('Bash sandbox is off'))).toBe(true)
})

test('a failed merged read reports its checks as unverified and still checks seating', () => {
  const warnings = checkPosture({ merged: null, policy: { prependPlugins: ['sec-default@builtin', 'barmkin-mod@acme'] } }, 'barmkin-mod', ['github'])
  expect(warnings.some((w) => w.includes('unverified'))).toBe(true)
  expect(warnings.some((w) => w.includes('Bash sandbox is off'))).toBe(false)
  expect(warnings.some((w) => w.includes('failIfUnavailable'))).toBe(false)
  expect(warnings.some((w) => w.includes('sandbox.credentials'))).toBe(false)
  expect(warnings.some((w) => w.includes('sec-default is seated ahead'))).toBe(true)
})

test('every warning is a single terminal-safe line that states a fix', () => {
  const all = [
    ...checkPosture({ merged: { permissions: { defaultMode: 'bypassPermissions' } }, policy: {} }, 'barmkin-mod', []),
    ...checkPosture({ merged: null, policy: { prependPlugins: ['sec-default@builtin', 'barmkin-mod@acme'] } }, 'barmkin-mod', []),
    ...checkPosture({ merged: {}, policy: null }, 'barmkin-mod', []),
    ...checkPosture({ merged: { sandbox: { network: { allowAllUnixSockets: true } } }, policy: {} }, 'barmkin-mod', []),
  ]
  expect(all.length).toBeGreaterThan(12)
  for (const w of all) {
    expect(w).not.toMatch(/[\n\r`\x1b]/)
    expect(w.length).toBeLessThan(150)
  }
})
