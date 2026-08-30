# Project instructions

Act as a senior systems engineer. Prefer small, explicit, maintainable changes.

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
- Keep firmware images, extracted files, device dumps, backups and secrets out
  of Git. Commit only tooling, manifests without secrets, and derived reports.

