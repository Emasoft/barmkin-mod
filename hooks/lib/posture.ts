// Pure helpers for the session.start posture self-check: seating in managed
// prependPlugins, plus the managed-settings floor that
// packaging/managed-settings.example.json documents: sandbox,
// permission-mode, skill-shell, credential-masking, domain and MCP allowlist
// defaults. Takes already-read settings objects and this plugin's own
// manifest name so it can be unit tested without a live $.settings.read()
// call.

// `prependPlugins`/`appendPlugins` are a managed/policy-only construct (see
// sec-default's own README): a person's settings can't set or override
// them, so seating is checked against the policy-source settings alone.
// So are `sandbox.network.allowManagedDomainsOnly` and
// `allowManagedMcpServersOnly`, which Claude Code honors only from managed
// settings, and the `allowedMcpServers` list that the latter reads from
// managed settings alone. The other checks (sandbox, permissions,
// credentials, disableSkillShellExecution) apply from whatever source set
// them, so those are checked against the merged settings
// `$.settings.read()` already returns. A null side means that read failed,
// and the checks it feeds are reported as unverified rather than silently
// passing or dropped.
export interface PostureSettings {
  merged: Record<string, unknown> | null
  policy: Record<string, unknown> | null
}

function pluginIdName(id: string): string {
  return id.split('@')[0] ?? id
}

function objectAt(value: unknown, key: string): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined
  const child = (value as Record<string, unknown>)[key]
  return child && typeof child === 'object' && !Array.isArray(child) ? (child as Record<string, unknown>) : undefined
}

function hasMaskEntry(credentials: Record<string, unknown> | undefined): boolean {
  if (!credentials) return false
  return [credentials.files, credentials.envVars].some(
    (entries) =>
      Array.isArray(entries) &&
      entries.some((entry) => entry && typeof entry === 'object' && (entry as Record<string, unknown>).mode === 'mask'),
  )
}

export function checkPosture(settings: PostureSettings, pluginName: string, mcpAllowlist: readonly string[]): string[] {
  const warnings: string[] = []

  const rawPrepend = settings.policy?.prependPlugins
  const prependPlugins = Array.isArray(rawPrepend) ? rawPrepend.filter((v): v is string => typeof v === 'string') : null

  const ourIndex = prependPlugins ? prependPlugins.findIndex((id) => pluginIdName(id) === pluginName) : -1
  const secDefaultIndex = prependPlugins ? prependPlugins.findIndex((id) => pluginIdName(id) === 'sec-default') : -1

  if (settings.policy === null) {
    warnings.push('seating, managed domain and managed MCP checks unverified: policy settings read failed.')
  } else {
    const policy = settings.policy
    if (prependPlugins === null || ourIndex === -1) {
      warnings.push(
        pluginName + ' is not in managed prependPlugins, so it cannot see skill text or CLAUDE.md: seat it (README "Seat requirements").',
      )
    } else if (secDefaultIndex !== -1 && secDefaultIndex < ourIndex) {
      warnings.push(
        'sec-default is seated ahead of ' + pluginName + ', hiding skill.prompt, prompt.context and prompt.section: seat ' + pluginName + ' first.',
      )
    }

    if (objectAt(objectAt(policy, 'sandbox'), 'network')?.allowManagedDomainsOnly !== true) {
      warnings.push(
        'managed sandbox.network.allowManagedDomainsOnly is unset, so other settings can widen sandbox egress: set it to true.',
      )
    }

    if (policy.allowManagedMcpServersOnly !== true || !Array.isArray(policy.allowedMcpServers)) {
      warnings.push(
        'managed allowManagedMcpServersOnly and allowedMcpServers are not both set, so users can add MCP servers: set them.',
      )
    }
  }

  if (settings.merged === null) {
    warnings.push('sandbox, credential, defaultMode and disableSkillShellExecution checks unverified: settings read failed.')
  } else {
    const merged = settings.merged
    const defaultMode = objectAt(merged, 'permissions')?.defaultMode
    if (defaultMode === 'bypassPermissions') {
      warnings.push('permissions.defaultMode is bypassPermissions, skipping every tool.check prompt: use default.')
    }

    const sandbox = objectAt(merged, 'sandbox')
    if (sandbox?.enabled !== true) {
      warnings.push('Bash sandbox is off, so no OS egress floor backs taint-gated denies: set sandbox.enabled to true.')
    }

    if (sandbox?.failIfUnavailable !== true) {
      warnings.push('sandbox.failIfUnavailable is unset, so a sandbox that cannot start runs commands unsandboxed: set it to true.')
    }

    if (sandbox?.allowUnsandboxedCommands !== false) {
      warnings.push('sandbox.allowUnsandboxedCommands is not false, so a command can opt out of the sandbox: set it to false.')
    }

    if (objectAt(sandbox, 'network')?.allowAllUnixSockets === true) {
      warnings.push(
        'sandbox.network.allowAllUnixSockets is on, so sandboxed commands can reach any local Unix socket: set it to false.',
      )
    }

    if (!hasMaskEntry(objectAt(sandbox, 'credentials'))) {
      warnings.push('sandbox.credentials has no mask entry, so sandboxed commands see real tokens: mask the credentials you use.')
    }

    if (merged.disableSkillShellExecution !== true) {
      warnings.push('disableSkillShellExecution is unset, so skill inline shell bypasses tool.call guards: set it to true.')
    }
  }

  if (mcpAllowlist.length === 0) {
    warnings.push('mcp_server_allowlist is empty, so any MCP server may run tools (audit-only): list trusted servers.')
  }

  return warnings
}
