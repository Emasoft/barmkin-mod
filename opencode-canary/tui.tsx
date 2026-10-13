// Canary TUI half. Not a mitigation: it reads the plugin inventory and tells
// the person, honestly, when the barmkin-opencode guard is not in it.
//
// Why a separate plugin (re-scout V35): the guard's own TUI half is loaded
// only after its server half set up, so a guard that failed to start, or was
// unloaded by a `-barmkin-opencode` entry in a repository's opencode.json,
// reports nothing about itself. This plugin has no dependency on the guard
// and carries no guard logic, so it is still running when the guard is not.
//
// What it can and cannot know: the inventory says whether the guard is listed
// as active or failed. It cannot say the guard works, and it says so.
// Self-contained on purpose (no imports from ../opencode): it ships and is
// seated separately.

import type { Plugin } from '@opencode/plugin/tui'
import { createSignal, Show } from 'solid-js'

const CANARY_ID = 'barmkin-opencode-canary'
const DEFAULT_GUARD_ID = 'barmkin-opencode'
const POLL_MS = 10_000

type Context = Plugin.Context

type State =
  | { kind: 'unchecked' }
  | { kind: 'unreadable'; why: string }
  | { kind: 'listed' }
  | { kind: 'failed'; error?: string }
  | { kind: 'absent' }

interface Entry {
  readonly id?: string
  readonly source: { readonly type: string; readonly path?: string; readonly target?: string }
  readonly state: { readonly status: string; readonly error?: string }
}

// Matches by plugin id. A plugin that failed before its module was read has no
// id, so a failed entry is also matched by a source path or package name that
// contains the guard id.
export function classify(entries: readonly Entry[], guardId: string): State {
  const mine = entries.filter((entry) => entry.id === guardId || (entry.state.status === 'failed' && (entry.source.path ?? entry.source.target ?? '').includes(guardId)))
  if (mine.length === 0) return { kind: 'absent' }
  const failed = mine.find((entry) => entry.state.status === 'failed')
  if (failed) return { kind: 'failed', error: failed.state.error?.split('\n').find((line) => line.trim())?.trim().slice(0, 200) }
  return { kind: 'listed' }
}

export function describe(state: State): { bad: boolean; chip?: string; banner?: string } {
  switch (state.kind) {
    case 'absent':
      return { bad: true, chip: 'BARMKIN GUARD ABSENT', banner: 'BARMKIN GUARD ABSENT: this session is UNGUARDED. No barmkin-opencode plugin is loaded (not installed, or removed by a project config).' }
    case 'failed':
      return { bad: true, chip: 'BARMKIN GUARD FAILED', banner: 'BARMKIN GUARD FAILED: this session is UNGUARDED.' + (state.error ? ' ' + state.error : '') }
    case 'listed':
      return { bad: false, chip: 'barmkin guard listed (canary cannot verify it works)' }
    case 'unreadable':
      return { bad: false, chip: 'barmkin canary: cannot read plugin list' }
    default:
      return { bad: false }
  }
}

export default {
  id: CANARY_ID + '.tui',
  setup(context: Context) {
    const guardId = typeof context.options.guardId === 'string' && context.options.guardId ? context.options.guardId : DEFAULT_GUARD_ID
    const quiet = context.options.quiet === true
    const [state, setState] = createSignal<State>({ kind: 'unchecked' })
    let disposed = false
    let inflight = false
    let last: State['kind'] = 'unchecked'

    const refresh = async () => {
      if (disposed || inflight) return
      inflight = true
      try {
        const location = context.location ?? context.data.location.default()
        let next: State
        try {
          next = classify((await context.client.plugin.list({ location })).data, guardId)
        } catch (error) {
          next = { kind: 'unreadable', why: error instanceof Error ? error.message : String(error) }
        }
        if (disposed) return
        setState(next)
        if (next.kind !== last) {
          // Toast the bad states, and the recovery from one. A first sight of "listed" is silent.
          const view = describe(next)
          if (view.bad && view.banner) context.ui.toast.show({ variant: 'error', title: next.kind === 'failed' ? 'BARMKIN GUARD FAILED' : 'BARMKIN GUARD ABSENT', message: view.banner, duration: 20_000 })
          else if (next.kind === 'listed' && (last === 'absent' || last === 'failed')) context.ui.toast.show({ variant: 'info', title: 'barmkin guard listed again', message: 'The canary sees barmkin-opencode in the plugin list; it cannot verify that it works.' })
          last = next.kind
        }
      } finally {
        inflight = false
      }
    }

    context.ui.slot({
      append: 'prompt.footer.status',
      render: () => {
        const view = () => describe(state())
        return (
          <Show when={view().chip && !(quiet && !view().bad)}>
            <box flexShrink={0}>
              <text fg={view().bad ? context.theme.text.feedback.error.base : context.theme.text.muted} wrapMode="none">
                {view().chip}
              </text>
            </box>
          </Show>
        )
      },
    })

    context.ui.slot({
      prepend: 'session.composer.top',
      render: () => {
        const view = () => describe(state())
        return (
          <Show when={view().bad && view().banner}>
            <box flexShrink={0}>
              <text fg={context.theme.text.feedback.error.base} wrapMode="word">
                {view().banner}
              </text>
            </box>
          </Show>
        )
      },
    })

    const off = context.data.on('plugin.updated', () => void refresh())
    const timer = setInterval(() => void refresh(), POLL_MS)
    void refresh()

    return () => {
      disposed = true
      clearInterval(timer)
      off()
    }
  },
} satisfies Plugin.Definition
