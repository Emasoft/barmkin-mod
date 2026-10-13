// Stands in for the Claude Code test kit's 'claude-code/testing' module when
// the host-neutral library tests run on Bun (see ../tsconfig.json). Only the
// plain assertion surface is mapped; tests that take the kit's ($, on)
// arguments exercise hooks/register.ts and run under `claude plugin test`.
export { expect, test } from 'bun:test'
