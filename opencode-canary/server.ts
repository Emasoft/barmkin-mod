// Server half of the barmkin-opencode canary: deliberately empty.
//
// OpenCode only loads a plugin's TUI half after its server half has loaded
// (a TUI-only directory is rejected: "Plugin entrypoint not found"), so the
// canary needs a server entry. It registers no hook and touches nothing, so it
// cannot fail in a way that matters and cannot weaken or strengthen any
// session. All of the canary's work is in tui.tsx.
export default {
  id: 'barmkin-opencode-canary',
  setup() {},
}
