// The in-place and inline-code rules of self-protection reach only their own shell
// segment (TRDD-QAT87NRF, review R3 of the 0.3.0 fix round). Which file an in-place
// sed or an interpreter one-liner writes cannot be read from the text, so every
// file named in its segment counts; a settings file named in another segment, such
// as a cat after &&, is only read.
import { expect, test } from "claude-code/testing"
import { shellSelfProtectionReason } from "../hooks/lib/self-protection"

test("an in-place edit or inline code in one segment does not turn a read in another into a write", () => {
  for (const command of [
    "sed -i \"\" \"s/a/b/\" notes.txt && cat ~/.claude/settings.json",
    "perl -pi -e \"s/a/b/\" notes.txt; jq .enabledPlugins ~/.claude/settings.json",
    "python3 -c \"print(1)\" | cat ~/.claude/settings.json",
  ]) {
    expect(shellSelfProtectionReason(command)).toBeNull()
  }
})

test("a separator inside the quoted code or script keeps it one segment, so the write is still denied", () => {
  for (const command of [
    "sed -i \"s/a/b/; s/c/d/\" ~/.claude/settings.json",
    "python3 -c \"import json; p=\x27/h/.claude/settings.json\x27; d=json.load(open(p)); json.dump(d, open(p, \x27w\x27))\"",
    "bash -c \"sed -i s/a/b/ ~/.claude/settings.local.json\"",
  ]) {
    expect(shellSelfProtectionReason(command) ?? "allowed: " + command).toContain("barmkin-mod:")
  }
})

test("inline code that names a settings file is denied, and the reason says how to read it instead", () => {
  expect(shellSelfProtectionReason("node -e \"console.log(require(\x27/h/.claude/settings.json\x27))\"") ?? "allowed").toContain("cat or jq")
})
