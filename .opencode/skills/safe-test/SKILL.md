---
name: Safe Testing (Agentic-Recon)
description: The checklist and workflow for running or writing tests for Agentic-Recon so nothing ever reaches the internet or a third-party data source. Use when running the test suite, writing a new test, or doing a manual smoke run.
---

# Safe Testing (Agentic-Recon)

Recon tooling *wants* to reach the network by design — that is exactly why
tests must never do it. A test failure is recoverable; a stray query to
crt.sh about a client domain is not.

## Hard rules

- **Zero third parties**: no crt.sh, no NVD, no public DNS resolvers, no web
  APIs, no internet — not even "just to check the parser works".
- **Loopback only**: bind `127.0.0.1` ephemeral ports; use
  `net/http/httptest` for everything HTTP and fixture JSON for third-party
  response shapes.
- **No real scope files**: tests build their scope structs inline or from
  `t.TempDir()` files; a real `scope.yaml` (client data) never enters tests.
- **SQLite in `t.TempDir()`**; teardown with `t.Cleanup`; no fixed ports.

## Running the suite

```bash
gofmt -l .          # must print nothing
go vet ./...
go test ./...       # locally on Windows without a cgo toolchain;
                    # CI (Linux) enforces -race
```

Fix lint/vet/test failures before declaring a task done. Report real results —
if a test fails, say so with the output; don't claim green when it isn't.

## Writing a new module's tests

- Reproduce the tool's output shape as a fixture and run the module against
  a local `httptest` server (or a fake source reader).
- Assert policy verdicts: in-scope targets pass; excluded and out-of-scope
  targets are refused and never persisted as actionable.
- If a module would normally call a third party, inject the source as an
  interface — the real client is one thin adapter, exercised only in manual
  lab runs against assets you own.
- Timing-sensitive policy behavior (rate, jitter) is tested with fake clocks,
  never real sleeps on the critical path.

## Manual smoke run

Only against assets you own, with a `scope.yaml` whose
`authorization.reference` you can cite, and only after the
`authorization-scope` checklist passes. Keep `risk_levels` to `PASSIVE` for
first runs.
