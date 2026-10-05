# Contributing

Thank you for considering a contribution. This document is short on purpose: the codebase
encodes most of its own rules, and repeating them here would only create a second thing to keep
in sync.

## Before you write code

Read [ARCHITECTURE.md](ARCHITECTURE.md). Then read one file in the area you intend to change and
match its style. The conventions below are the ones that are easy to get wrong.

## The rules that matter

**The engine owns every decision.** The CLI and the desktop app are clients. If you find yourself
computing a number, a threshold, a sort key or a verdict in a frontend, that logic belongs in
the engine, and the frontend should ask for it.

**One owner of mutable state.** The engine task owns the flow table. Do not add a lock around
the packet path to work around a design you have not understood yet.

**`cfg(target_os)` belongs to `sentinel-platform`.** Every other crate consumes normalized types.
If you need a platform fact, add a function there.

**Every error explains itself.** An error carries a title, a plain-language summary and concrete
next steps. A raw driver string is never the only thing a user sees. When you add an error
variant, write the user-facing text as part of adding it.

**Incomplete data is labelled.** If Sentinel dropped packets, every surface that shows totals
says so. A number derived from lossy data, presented as complete, is a correctness bug.

**No placeholders.** Do not commit a stub, a `todo!()`, a hard-coded sample array or a mock that
makes an unimplemented feature look present. If a feature is not implemented, the interface
should not offer it. This was a deliberate decision about v0.1 and it should not be quietly
reversed.

**No `unwrap()` in a production path.** Handle the case or propagate it. `unwrap_or`,
`unwrap_or_else` and explicit `match` are all fine.

**Write the test that encodes the behaviour.** If you fix a bug, the test that fails before your
fix and passes after it is part of the fix. If a test fails, first work out which of the test or
the code is wrong; do not edit the expectation to match the code without deciding that the code
is right.

## Style

Follow what is already there. Concretely: `cargo fmt`, `cargo clippy -D warnings`, doc comments
on every public item explaining *why* rather than restating the signature, and comments that
explain the reasoning behind a non-obvious choice rather than narrating the code.

Comments earn their place by answering "why would someone do it this way?". A comment that
restates the next line is noise.

## Commit messages

Describe what changed and why, in the imperative:

```text
feat: reconstruct bidirectional flows from port roles

Canonical endpoint ordering means a reply's key is not derivable from the
initiator's, so the flow table keeps both orientations and the direction is
inferred from which side used an ephemeral port.

Fixes the split visible in the connections table.
```

A commit that changes the contract between the engine and the frontend must change the
TypeScript mirror in `packages/types` in the same commit.

## Pull requests

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test`
- `cd apps/desktop/frontend && npm run typecheck && npm run lint && npm run build`

All must pass. One concern per pull request. Describe what you changed, why, and how you tested
it — including what you did *not* test and why.

## Reporting bugs

Open an issue with: what you did, what happened, what you expected, your platform
(`sentinel doctor` output), and the version or commit. A capture file that reproduces the problem
is worth more than a description of it, and you can check what it contains first with
`sentinel analyze`.

## Security

Do not open a public issue for a security problem. See [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under the Apache-2.0 licence that covers this project. See
[LICENSE](LICENSE).