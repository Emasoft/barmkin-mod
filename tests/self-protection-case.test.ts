// Self-protection against case spellings (TRDD-QAT87NRF, review R1 of the 0.3.0
// fix round): the default volumes of macOS and Windows are case-insensitive, so
// ~/.claude/Settings.json, ~/.CLAUDE and RM name the same files and commands as
// their lower-case spelling, and must be denied the same way.
import { expect, test } from "claude-code/testing"
import {
  isSettingsFile,
  mcpSelfProtectionReason,
  protectedPathKind,
  shellSelfProtectionReason,
} from "../hooks/lib/self-protection"

test("a case spelling of a settings file, a protected folder or a command is denied like the lower-case one", () => {
  for (const command of [
    "echo {\"disableAllHooks\":true} > ~/.claude/Settings.json",
    "echo {\"disableAllHooks\":true} > ~/.CLAUDE/settings.LOCAL.json",
    "cp /tmp/p.json /srv/claude-config/plugins/Installed_Plugins.json",
    "rm -rf ~/.CLAUDE",
    "rm -rf ~/.claude/Plugins",
    "rm -rf ~/.claude/plugins/CACHE/emasoft-barmkin",
    "rm -rf ~/.claude/plugins/cache/EMASOFT-BARMKIN",
    "rm -rf ~/.claude/plugins/Marketplaces/Emasoft-Barmkin",
    "echo {} > ~/.claude/plugins/Store/Barmkin-Mod_emasoft-barmkin-0123456789ab.json",
    "RM -rf ~/.claude",
    "CLAUDE plugin uninstall BARMKIN-MOD",
    "claude plugin Disable Barmkin-Mod@Emasoft-Barmkin",
  ]) {
    expect(shellSelfProtectionReason(command) ?? "allowed: " + command).toContain("barmkin-mod:")
  }
  expect(isSettingsFile("/h/.claude/Settings.JSON")).toBe(true)
  expect(protectedPathKind("/h/.CLAUDE/Plugins/Cache/Emasoft-Barmkin/barmkin-mod/0.3.0")).toBe("install")
  expect(protectedPathKind("Barmkin-Mod_inline-0123456789ab.json")).toBe("store")
  expect(mcpSelfProtectionReason(["/h/.claude/Settings.json", "{\"disableAllHooks\": true}"]) ?? "allowed").toContain("barmkin-mod:")
})

test("a read of a case spelling of a settings file still runs", () => {
  for (const command of ["cat ~/.claude/Settings.json", "jq .enabledPlugins ~/.CLAUDE/settings.json", "ls ~/.claude/Plugins/Cache"]) {
    expect(shellSelfProtectionReason(command)).toBeNull()
  }
})

// The fold keeps option letters as typed, since their case can change what a command
// does (Greptile on PR #1): cp -L copies through a link and cp -l makes one; yq -I sets
// the indent and perl -I an include folder, while yq -i and perl -i edit in place.
// BSD sed takes -I for an in-place edit as well as -i.
test("option letters keep their case: a read with -L or -I runs, a link or an in-place edit is still denied", () => {
  for (const command of [
    "cp -L ~/.claude/settings.json /tmp/backup.json",
    "cp -RL ~/.claude /tmp/claude-backup",
    "yq -I 2 . ~/.claude/settings.json",
    "perl -I lib ~/tools/show.pl ~/.claude/settings.json",
  ]) {
    expect(shellSelfProtectionReason(command)).toBeNull()
  }
  for (const command of [
    "cp -l ~/.claude/settings.json /tmp/s.json",
    "cp -Rl ~/.claude /tmp/c",
    "CP -l ~/.CLAUDE/Settings.json /tmp/s.json",
    "sed -I \"\" s/a/b/ ~/.claude/settings.json",
    "yq -i .a=1 ~/.claude/settings.json",
  ]) {
    expect(shellSelfProtectionReason(command) ?? "allowed: " + command).toContain("barmkin-mod:")
  }
})
