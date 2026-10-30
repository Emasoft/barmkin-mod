// $.state shape for barmkin-mod. Declared here so `claude plugin validate`
// can check hooks/register.ts against it (see plugin.json's "types" field).
declare module 'claude-code' {
  interface PluginState {
    'barmkin-mod': {
      // Untrusted-content taint (capability: taint + injection screen).
      // Set after WebFetch/WebSearch/mcp__*/out-of-cwd Read results score
      // above the injection threshold. Cleared by a prompt a human sent
      // (composer or bridge origin) in the default human-origin posture; in
      // sticky posture, only by a compaction, a /clear or
      // /barmkin-mod-clear-taint.
      tainted: boolean
      taintReason: string | null
      // Non-null when the taint needs a person's /barmkin-mod-clear-taint to
      // clear (content past the classifier's window with Jev configured): a
      // prompt, compaction or /clear leaves it standing. Holds why.
      taintAckReason: string | null

      // Rule-of-Two tracker. Leg A is `tainted` above; leg C is evaluated
      // per call against the egress classes. Leg B (sensitive access) is set
      // when a secret path is named in a call, a tool result trips a
      // redaction rule, or content scores on the credential question. Cleared
      // together with A, by the same events.
      sensitiveAccess: boolean
      sensitiveReason: string | null

      // The last egress call the gate denied or warned on, for the status
      // surface.
      lastEgress: {
        tool: string
        classIds: string[]
        decision: 'deny' | 'warn'
        rule: string
        at: number
      } | null

      // Last Jev System One verdict, for the explanation surface (HUD band
      // and $.ui.notice under the permission dialog).
      lastVerdict: {
        toolUseId: string
        question: string
        probability: number
        decision: 'pass' | 'escalate' | 'deny'
        model: string
        at: number
      } | null

      // Warm breaker mirror (session-scoped). barmkin's own file breaker is
      // authoritative for the managed hook; this is only for the mod's own
      // classifier calls and the HUD's "semantic check unavailable" state.
      breakerOpenUntil: number
      breakerFailureCount: number

      // The four-question shadow screen's own breaker. Separate from the pair
      // above so a shadow failure never degrades the real screen or the HUD.
      shadowBreakerOpenUntil: number
      shadowBreakerFailureCount: number

      // What the shadow screen answered for the last piece of content, per
      // wording arm. Annotation only: nothing taints, withholds or gates on it.
      lastShadow: {
        toolUseId: string
        label: string
        arms: {
          arm: string
          answered: number
          windows: number
          model: string | null
          scores: Record<string, number>
        }[]
        at: number
      } | null

      // The security switches (hooks/lib/switches.ts) as this session last wrote
      // or loaded them, one entry per switch id, true = on. Null until loaded
      // from $.store at session.start (or after /clear, /resume, /branch, which
      // reset $.state); every gate reads a null as all switches on.
      switches: { [id: string]: boolean } | null
      // Fingerprint of the $.store value this session last wrote or loaded: the
      // tamper check compares the store against it before every write and on
      // /barmkin-mod-rule and /barmkin-mod-panel.
      switchesHash: string | null
      // The last switch notice (a tamper restore, an accepted external value),
      // shown at the top of the switch panel.
      switchesNotice: string | null
    }
  }
}
