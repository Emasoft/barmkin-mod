// How redacted untrusted content is cut into the classifier's windows, and how
// the windows' answers combine into one score. Pure: register.ts makes the
// calls. The text handed in is already redacted (classifierInput), so a cut
// never splits a secret, only at worst a placeholder, which planWindows avoids.
import { CLASSIFIER_WINDOW_CHARS, type ScoreSource } from './taint'
import type { SystemOneParseResult } from './system-one-client'

// Consecutive windows share this many characters, so any stretch of text this
// long or shorter lies whole inside at least one window. The longest match of
// any injection heuristic is 178 characters (the AI-addressed notice), and the
// longest redaction placeholder is 34.
export const CLASSIFIER_WINDOW_OVERLAP = 512

// Five windows cover 4,000 + 4 x 3,488 = 17,952 characters: the 16 KiB limit
// of the screened surfaces, plus room for placeholders longer than what they
// replaced. Text past the last window is never classified.
export const MAX_CLASSIFIER_WINDOWS = 5

// A window's end moves back by at most this many characters to land after
// whitespace rather than inside a word.
const BOUNDARY_SLACK = 128

const PLACEHOLDER = /\[REDACTED:[a-z-]+#\d+\]/y
const PLACEHOLDER_MAX = 48

export interface ClassifierWindow {
  start: number
  end: number
}

// Moves a cut back so it falls after whitespace when there is some nearby, and
// never inside a placeholder or between the halves of a surrogate pair.
function snapCut(text: string, cut: number): number {
  let c = cut
  for (let i = cut; i > Math.max(cut - BOUNDARY_SLACK, 0); i--) {
    if (/\s/.test(text[i - 1])) {
      c = i
      break
    }
  }
  const open = text.lastIndexOf('[REDACTED:', c - 1)
  if (open !== -1 && open > c - PLACEHOLDER_MAX) {
    PLACEHOLDER.lastIndex = open
    const m = PLACEHOLDER.exec(text)
    if (m && open + m[0].length > c) c = open
  }
  const code = text.charCodeAt(c - 1)
  if (code >= 0xd800 && code <= 0xdbff) c--
  return c
}

// Moves a window's start back so it does not begin inside a placeholder or on
// the second half of a surrogate pair; the overlap only grows.
function snapStart(text: string, start: number): number {
  let s = start
  const open = text.lastIndexOf('[REDACTED:', s)
  if (open !== -1 && open > s - PLACEHOLDER_MAX) {
    PLACEHOLDER.lastIndex = open
    const m = PLACEHOLDER.exec(text)
    if (m && open + m[0].length > s) s = open
  }
  const code = text.charCodeAt(s)
  if (code >= 0xdc00 && code <= 0xdfff) s--
  return s
}

// Windows of at most `size` characters, each starting `overlap` characters
// before the previous one ended, from the start of the text until it is
// covered or `max` windows are planned. `covered` is where the last ends.
export function planWindows(
  text: string,
  size = CLASSIFIER_WINDOW_CHARS,
  overlap = CLASSIFIER_WINDOW_OVERLAP,
  max = MAX_CLASSIFIER_WINDOWS,
): { windows: ClassifierWindow[]; covered: number } {
  const windows: ClassifierWindow[] = []
  let start = 0
  while (windows.length < max) {
    const end = start + size >= text.length ? text.length : snapCut(text, start + size)
    windows.push({ start, end })
    if (end >= text.length) break
    start = Math.max(snapStart(text, end - overlap), start + 1)
  }
  return { windows, covered: windows.length === 0 ? 0 : windows[windows.length - 1].end }
}

// Characters of the text that no answered window covered: the windows that
// failed or were not asked, and anything past the last window.
export function unclassifiedChars(length: number, windows: ClassifierWindow[], answered: boolean[]): number {
  let covered = 0
  let reach = 0
  windows.forEach((w, i) => {
    if (!answered[i]) return
    const from = Math.max(w.start, reach)
    if (w.end > from) covered += w.end - from
    reach = Math.max(reach, w.end)
  })
  return length - covered
}

// Each question's highest probability over the windows that answered, with the
// model that answered first. A window that failed contributes nothing: it is
// never read as a 0, so a failure cannot lower a score. Null when no window
// answered.
export function mergeWindowAnswers(
  results: (SystemOneParseResult | null)[],
  ids: readonly string[],
): { model: string; answers: Record<string, number>; answered: number } | null {
  let merged: { model: string; answers: Record<string, number>; answered: number } | null = null
  for (const r of results) {
    if (!r || !r.ok) continue
    if (merged === null) {
      merged = { model: r.model, answers: {}, answered: 0 }
      for (const id of ids) merged.answers[id] = 0
    }
    merged.answered++
    for (const id of ids) merged.answers[id] = Math.max(merged.answers[id], r.answers[id] ?? 0)
  }
  return merged
}

// The production pair's windows as one score source, so composeScreen still
// reads "local versus Jev" and Jev can only raise a score. Null when no
// window answered.
export function mergeWindowScores(results: (SystemOneParseResult | null)[]): ScoreSource | null {
  const merged = mergeWindowAnswers(results, ['injection', 'credentials'])
  if (merged === null) return null
  return { model: merged.model, injection: merged.answers.injection, credentials: merged.answers.credentials }
}
