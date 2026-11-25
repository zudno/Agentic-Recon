# Agentic-Recon

An offensive-side attack-surface discovery and validation platform ("agentic
recon") built for **authorized security testing, education, and CTF practice**.
It is the pre-access sibling of ReverseShell: it discovers and validates the
attack surface of a *signed scope* (`scope.yaml`), producing prioritized paths
toward initial access — a deterministic policy engine enforces the scope on
every action, and optional LLM agents accelerate triage over structured data.
This tool does recon and validation only: no exploitation, no credential
attacks, no post-exploitation (that is ReverseShell's job, post-access).

This file is the shared contract for any agent (opencode, Claude, etc.)
working in this repo. Read it fully before editing code or running anything.

---

## ⚠️ Authorized use only — non-negotiable

This is a dual-use offensive-security tool. It is written and maintained
**only** for:

- Systems you personally own.
- Lab / CTF / training environments.
- Engagements with **written authorization** and an explicit, signed scope
  (rules of engagement).

Hard rules for every contributor and every agent:

1. **Never** run any module, wrapper, tool, or agent against a host, network,
   or account you do not own or are not explicitly authorized (in writing) to
   test. If authorization or scope is unclear, **stop and ask the user** — see
   the `authorization-scope` skill.
2. **`scope.yaml` is the contract.** No campaign starts without
   `authorization.reference`. Never widen the scope on your own initiative;
   `exclude` entries always win over inclusions; third-party data sources are
   an allow-list (absent = forbidden).
3. **Tests never touch the internet or any third party** — no crt.sh, no NVD,
   no public DNS, no web APIs. See the `safe-test` skill.
4. **Out of scope for this project** (do not add, even if asked to "make it
   better"): exploitation or PoC code, credential attacks (spraying, stuffing,
   brute force), self-propagation, scanning beyond the signed scope, and
   stealth/evasion features meant to hide activity from a system's legitimate
   owner. The campaign "noise profile" is an RoE parameter to comply with, not
   a hiding feature.

If a requested change would cross these lines, say so plainly and propose the
in-scope alternative instead of implementing it.

---

## Project status

R0 and R1 are landed. R0: skeleton, contract, quality gates. R1: the
deterministic policy engine — scope.yaml validation (authorization.reference
mandatory, mixed domain/IP exclusions, sources allow-list, risk levels),
dual token-bucket rate limiter with jitter, the egress choke point
(injectable Egress, DefaultEgress is the only net/http client in the
codebase — enforced by TestNativeEgressOnlyInPolicy), and evidence-everything
via request_log sinks (JSONL + memory; the store-backed sink lands in R2).
INTRUSIVE fails closed until the approval gate arrives in R4. Next: R2, the
SQLite store with the asset state machine (README §14). Update this file when
reality drifts (prefer opencode's `/init` or edit in place).

---

## Stack & layout

- **Language:** Go 1.23+ (standard library first).
- **Allowed dependencies (pinned):** `gopkg.in/yaml.v3` (scope.yaml — stdlib
  has no YAML) and `modernc.org/sqlite` (pure-Go SQLite: keeps `CGO_ENABLED=0`
  and cross-compilation intact). Anything else needs explicit justification.
- **LLM:** plain REST over `net/http` (Anthropic or OpenAI-compatible). No
  SDKs. API keys only via env vars named in config — never in files.
- **Binaries:** static (`CGO_ENABLED=0`).

```
Agentic-Recon/
├── AGENTS.md
├── README.md
├── go.mod / go.sum
├── Makefile
├── scope.example.yaml      # template; the real scope.yaml is gitignored
├── .github/workflows/ci.yml
├── cmd/recon/main.go        # operator CLI
├── internal/
│   ├── policy/              # scope, rate+jitter, risk, approval, request_log
│   ├── store/               # SQLite schema, repos, asset state machine
│   ├── pipeline/            # deterministic modules (native + wrappers)
│   ├── toolbox/             # typed tool catalog (CLI + agents)
│   ├── agent/               # LLM REST client + triage/specialist loops
│   └── report/              # md/json export from the store
└── .opencode/skills/        # reusable workflows (see "Skills" below)
```

---

## Commands

```bash
# Environment
go version                 # Go 1.23+

# CLI (R1): scaffold and validate the signed contract
go run ./cmd/recon init --scope scope.yaml
go run ./cmd/recon run --scope scope.yaml

# Quality gates — run these before declaring a task done
gofmt -l .                 # must print nothing
go vet ./...
go test -race ./...        # on Windows -race needs cgo (gcc/mingw); without a C
                           # toolchain run `go test ./...` locally — CI enforces -race
go build ./...
```

If the real commands differ, update this block — never leave agents guessing.

---

## Conventions

- **Scope-first.** Every network-touching function goes through
  `internal/policy`. Native egress lives inside the policy engine (it hands
  validated requests to a single transport); modules and tools never open
  sockets on their own. Wrapped binaries get pre-flight validation of their
  whole target list plus their own rate flags (README §6.1).
- **Evidence-everything.** Every request — human, module, or agent — writes a
  `request_log` line. Never build a network path that skips it.
- **Deterministic policy, optional LLM.** No AI in the control plane; agents
  propose, the engine disposes. The system must be fully usable with no LLM
  configured at all.
- **Out-of-scope assets are inert.** The store marks them OUT_OF_SCOPE for the
  exclusions report; no tool may return them.
- **Idiomatic Go, enforced by tooling.** `gofmt`; `go vet`; `-race` in CI.
  Doc comments on exported identifiers. Wrap errors with `%w`; respect
  `context.Context`; `defer` every resource acquisition.
- **No commented-out code**; comment the *why* when it is not obvious.
- **Errors over silent failures** — the policy engine always fails closed.

---

## Testing & safety

- **Loopback + httptest only.** A test must never: query crt.sh, NVD, any DNS
  resolver, any public API, or otherwise reach the internet or a third party.
- Recon modules are tested against local `httptest` fixtures reproducing
  recorded response shapes — never live services.
- SQLite files in `t.TempDir()`; teardown with `t.Cleanup`; bind
  `127.0.0.1:0` (never fixed ports).
- Real `scope.yaml` files never appear in tests or in the repo.
- Rate/policy timing behavior is unit-tested with fake clocks.

See the `safe-test` skill for the checklist and the `authorization-scope`
skill for the pre-flight gate before any non-loopback run.

---

## Git

- Git initialized on `main`; no commits yet. First commit: `AGENTS.md`,
  `README.md`, `.gitignore`, `.opencode/`, `go.mod`, `Makefile`,
  `scope.example.yaml`, CI, and the `cmd/recon` skeleton. **Never** commit:
  `scope.yaml` (client names/IPs), `*.db`, evidence from real engagements,
  logs, or API keys.
- Do not commit unless the user explicitly asks.

---

## Skills

Reusable workflows live in `.opencode/skills/`. Load the matching skill
instead of improvising:

| Skill | Use it when |
|-------|-------------|
| `authorization-scope` | **Before** any run or test that could touch a host you don't own. Pre-flight authorization & scope gate. |
| `safe-test` | Running or writing tests — loopback-only, zero third parties. |

When a task matches a skill's description, load it first — it carries the
detailed, up-to-date steps that this file only summarizes.
