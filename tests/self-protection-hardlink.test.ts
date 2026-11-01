// Self-protection against a hard link (TRDD-QAT87NRF, review R2): a hard link
// gives a settings file a second name that the file tools never resolve, so
// making one in the shell is denied.
import { expect, test } from "claude-code/testing"
import { shellSelfProtectionReason } from "../hooks/lib/self-protection"

test("a hard link to a settings file or into a protected folder is denied, in every spelling", () => {
  for (const command of [
    "ln ~/.claude/settings.json /tmp/s.json",
    "ln -f ~/.claude/settings.local.json /tmp/x",
    "link ~/.claude/settings.json /tmp/s.json",
    "cp -l ~/.claude/settings.json /tmp/s.json",
    "cp --link ~/.claude/settings.json /tmp/s.json",
    "cp -al ~/.claude /tmp/claude-copy",
    "rsync -a --link-dest=/h/.claude /tmp/src/ /tmp/dst/",
    "ln /proj/.claude/settings.json ./s.json",
    "ln /etc/claude-code/managed-settings.json /tmp/m.json",
    "ln ~/.claude/plugins/store/barmkin-mod_emasoft-barmkin-0123456789ab.json /tmp/st.json",
  ]) {
    expect(shellSelfProtectionReason(command) ?? "allowed: " + command).toContain("barmkin-mod:")
  }
})

test("a link or a copy that touches no protected file still runs", () => {
  for (const command of [
    "ln -s /tmp/a /tmp/b",
    "cp -l /tmp/a /tmp/b",
    "rsync -a --link-dest=/tmp/prev /tmp/src/ /tmp/dst/",
    "cp ~/.claude/settings.json /tmp/backup.json",
  ]) {
    expect(shellSelfProtectionReason(command)).toBeNull()
  }
})
