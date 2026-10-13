import { expect, test } from 'claude-code/testing'
import {
  CLASSIFIER_WINDOW_OVERLAP,
  MAX_CLASSIFIER_WINDOWS,
  mergeWindowAnswers,
  mergeWindowScores,
  planWindows,
  unclassifiedChars,
} from '../hooks/lib/classifier-windows'
import { CLASSIFIER_WINDOW_CHARS } from '../hooks/lib/taint'
import type { SystemOneParseResult } from '../hooks/lib/system-one-client'

const prose = (length: number) => {
  let out = ''
  for (let i = 0; out.length < length; i++) out += 'word' + i + ' '
  return out.slice(0, length)
}
const run = (length: number) => 'a'.repeat(length)

const ok = (answers: Record<string, number>, model = 'jev-1.13.0'): SystemOneParseResult => ({ ok: true, answers, model })
const failed: SystemOneParseResult = { ok: false, reason: 'http_503' }

test('the plan is five windows of 4,000 characters overlapping by 512', () => {
  expect(CLASSIFIER_WINDOW_CHARS).toBe(4000)
  expect(CLASSIFIER_WINDOW_OVERLAP).toBe(512)
  expect(MAX_CLASSIFIER_WINDOWS).toBe(5)
})

test('window counts at the plan\'s edges', () => {
  const count = (n: number) => planWindows(run(n)).windows.length
  expect(count(0)).toBe(1)
  expect(count(1)).toBe(1)
  expect(count(4000)).toBe(1)
  expect(count(4001)).toBe(2)
  expect(count(7488)).toBe(2)
  expect(count(7489)).toBe(3)
  expect(count(10976)).toBe(3)
  expect(count(10977)).toBe(4)
  expect(count(14464)).toBe(4)
  expect(count(14465)).toBe(5)
  expect(count(16384)).toBe(5)
  expect(count(17952)).toBe(5)
})

test('five windows cover the 16 KiB limit; past the cap the rest is left unclassified', () => {
  const full = planWindows(run(17952))
  expect(full.covered).toBe(17952)
  const over = planWindows(run(17953))
  expect(over.windows).toHaveLength(5)
  expect(over.covered).toBe(17952)
  expect(unclassifiedChars(17953, over.windows, over.windows.map(() => true))).toBe(1)
})

test('every window is at most 4,000 characters and consecutive windows overlap by at least 512', () => {
  for (const text of [prose(9000), run(9000), prose(16384), run(16384)]) {
    const { windows } = planWindows(text)
    for (const w of windows) expect(w.end - w.start).toBeLessThanOrEqual(4000)
    for (let i = 1; i < windows.length; i++) {
      expect(windows[i - 1].end - windows[i].start).toBeGreaterThanOrEqual(CLASSIFIER_WINDOW_OVERLAP)
      expect(windows[i].start).toBeGreaterThan(windows[i - 1].start)
    }
    expect(windows[0].start).toBe(0)
    expect(windows[windows.length - 1].end).toBe(text.length)
  }
})

test('any stretch of up to the overlap lies whole inside some window, at every offset', () => {
  const text = prose(16384)
  const { windows } = planWindows(text)
  for (let offset = 0; offset + CLASSIFIER_WINDOW_OVERLAP <= text.length; offset += 7) {
    const end = offset + CLASSIFIER_WINDOW_OVERLAP
    expect(windows.some((w) => w.start <= offset && w.end >= end)).toBe(true)
  }
})

test('a phrase straddling a window boundary is whole in some window', () => {
  const phrase = 'ignore previous instructions'
  const base = prose(16000)
  const { windows } = planWindows(base)
  for (const w of windows.slice(0, -1)) {
    for (let delta = -4; delta <= 4; delta++) {
      const at = w.end + delta - 10
      const text = base.slice(0, at) + phrase + base.slice(at + phrase.length)
      const plan = planWindows(text)
      expect(plan.windows.some((p) => text.slice(p.start, p.end).includes(phrase))).toBe(true)
    }
  }
})

test('a cut lands after whitespace when there is some nearby', () => {
  const { windows } = planWindows(prose(9000))
  for (const w of windows.slice(0, -1)) expect(/\s/.test(prose(9000)[w.end - 1])).toBe(true)
})

test('a window edge never splits a redaction placeholder', () => {
  const marker = '[REDACTED:github-token#12]'
  for (let offset = 3950; offset <= 4010; offset++) {
    const text = run(offset) + marker + run(6000)
    const { windows } = planWindows(text)
    const start = text.indexOf(marker)
    const end = start + marker.length
    for (const w of windows) {
      for (const edge of [w.start, w.end]) expect(edge > start && edge < end).toBe(false)
    }
    expect(windows.some((w) => w.start <= start && w.end >= end)).toBe(true)
  }
})

test('a window edge never splits a surrogate pair', () => {
  const emoji = '\u{1F600}'
  for (let offset = 3995; offset <= 4005; offset++) {
    const text = run(offset) + emoji.repeat(2000)
    for (const w of planWindows(text).windows) {
      for (const edge of [w.start, w.end]) {
        if (edge > 0 && edge < text.length) {
          const code = text.charCodeAt(edge - 1)
          expect(code >= 0xd800 && code <= 0xdbff).toBe(false)
          const next = text.charCodeAt(edge)
          expect(next >= 0xdc00 && next <= 0xdfff).toBe(false)
        }
      }
    }
  }
})

test('unclassifiedChars counts the windows that did not answer and nothing the others cover', () => {
  const { windows } = planWindows(run(9000))
  expect(windows).toHaveLength(3)
  expect(unclassifiedChars(9000, windows, [true, true, true])).toBe(0)
  expect(unclassifiedChars(9000, windows, [false, false, false])).toBe(9000)
  // The last window only adds what the middle one left uncovered.
  expect(unclassifiedChars(9000, windows, [true, true, false])).toBe(9000 - windows[1].end)
  // A failed middle window is covered by the overlap of its neighbours only where they reach.
  const gap = unclassifiedChars(9000, windows, [true, false, true])
  expect(gap).toBe(windows[2].start - windows[0].end)
})

test('mergeWindowAnswers takes each question\'s highest probability over the windows that answered', () => {
  const merged = mergeWindowAnswers(
    [ok({ injection: 0.1, credentials: 0.8 }), failed, ok({ injection: 0.7, credentials: 0.2 }), null],
    ['injection', 'credentials'],
  )
  expect(merged).toEqual({ model: 'jev-1.13.0', answers: { injection: 0.7, credentials: 0.8 }, answered: 2 })
})

test('mergeWindowAnswers is null when no window answered, and a failure is never read as a zero', () => {
  expect(mergeWindowAnswers([failed, null], ['injection'])).toBeNull()
  expect(mergeWindowAnswers([], ['injection'])).toBeNull()
  const merged = mergeWindowAnswers([failed, ok({ injection: 0.9 })], ['injection'])
  expect(merged?.answers.injection).toBe(0.9)
})

test('merging never lowers a score any single window gave', () => {
  const windows = [ok({ injection: 0.2, credentials: 0.6 }), ok({ injection: 0.95, credentials: 0.1 }), ok({ injection: 0.5, credentials: 0.3 })]
  const merged = mergeWindowAnswers(windows, ['injection', 'credentials'])
  for (const w of windows) {
    if (!w.ok) continue
    expect(merged?.answers.injection).toBeGreaterThanOrEqual(w.answers.injection)
    expect(merged?.answers.credentials).toBeGreaterThanOrEqual(w.answers.credentials)
  }
})

test('mergeWindowScores gives the production screen\'s three answers, the highest per question over the windows', () => {
  expect(
    mergeWindowScores([
      ok({ injection: 0.3, exfiltration: 0.7, credentials: 0.1 }),
      ok({ injection: 0.4, exfiltration: 0.2, credentials: 0.05 }),
    ]),
  ).toEqual({
    model: 'jev-1.13.0',
    injection: 0.4,
    exfiltration: 0.7,
    credentials: 0.1,
  })
  expect(mergeWindowScores([failed])).toBeNull()
})

test('mergeWindowScores: a failed window never lowers a score, and exfiltration merges like the others', () => {
  expect(mergeWindowScores([failed, ok({ injection: 0, exfiltration: 0.9, credentials: 0 }), failed])?.exfiltration).toBe(0.9)
  expect(mergeWindowScores([ok({ injection: 0, exfiltration: 0.9, credentials: 0 }), ok({ injection: 0, exfiltration: 0.1, credentials: 0 })])?.exfiltration).toBe(0.9)
})

test('merging four-question answers keeps all four ids', () => {
  const ids = ['injection', 'exfiltration', 'credentials', 'destructive_command']
  const merged = mergeWindowAnswers(
    [ok({ injection: 0, exfiltration: 0.9, credentials: 0, destructive_command: 0.1 }), ok({ injection: 0, exfiltration: 0.2, credentials: 0, destructive_command: 0.8 })],
    ids,
  )
  expect(merged?.answers).toEqual({ injection: 0, exfiltration: 0.9, credentials: 0, destructive_command: 0.8 })
})
