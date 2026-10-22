# Project instructions

Act as a senior systems engineer. Prefer small, explicit, maintainable changes.

Clean up obsolete task branches after their work is merged or retired. Before
deletion, preserve required unmerged changes and evidence commits under durable
refs. Keep active task branches and uncommitted work intact.

This project is evidence-first:

- Treat the exact OpenWrt image as the deployment specification.
- Treat its matching upstream source revision as the implementation reference.
- Treat redacted runtime observations as the behavioural authority.
- Do not import the previous project's code or abstractions wholesale.
- Do not design a replacement component before identifying its existing
  interface, callers, failure boundary and compatibility requirements.
- Preserve the OpenWrt kernel, hardware drivers and mature execution-plane
  components unless concrete evidence justifies reconsideration.
- Never modify or flash physical router state without a separate explicit user
  request and a verified recovery gate.
- Wi-Fi management is authorized; a LAN cable is not a deployment prerequisite.
  Verify offline backups, artifact identities, automatic rollback and client
  health before confirming a deployment.
- Keep firmware images, extracted files, device dumps, backups and secrets out
  of Git. Commit only tooling, manifests without secrets, and derived reports.

## Research method

Before any performance research, algorithm research, or difficult debugging,
read `docs/RESEARCH_GUIDANCE_FROM_FABLE.md`. Before each experiment, apply its
pre-experiment checklist.

## Rust development standard

All Rust development, refactoring, reviews and maintenance follow Microsoft's
[Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/agents/all.txt).
Read `docs/RUST_GUIDELINES.md` before Rust work; it records the reviewed upstream
revision, project applicability, review gates and incremental adoption priorities.
Consult the relevant official rules when changing a subsystem. Apply them to new
and changed code; improve existing code in focused, behavior-preserving steps.
Do not turn guideline adoption into unrelated rewrites or dependency churn.
Soundness requirements admit no compatibility exception.

Run Rust build, check, test, benchmark and lint commands through `mbx` on
`ssh oracle` or in CI; never invoke plain Cargo for compilation. If a build
appears uncached, run `mbx explain --last`. The Mac remains an editing and
formatting host; do not create local build targets for this work.
