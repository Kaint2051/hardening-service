# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Linux Hardening Service Tool — a web console for VNNIC that manages security
hardening/compliance across a fleet of Linux hosts (≤50 machines by design).
Full architecture rationale lives in
[`docs/architecture-proposal.md`](docs/architecture-proposal.md) — read it
before making non-trivial changes. `README.md` is a long, chronological
build log (Vietnamese) of every phase, bug, and fix discovered through real
testing; treat it as project history/context, not as a spec.

Ignore the untracked `combined/` and `demo-html/` directories in the repo
root — they belong to an unrelated project that happens to share this
working directory.

## Development environment

**There is no local dev environment for this stack.** Everything (Docker,
Python, Go toolchains) is built and tested on a remote lab server over SSH
— the code is synced there via `scp`, not `git pull` (the deployed path is
not a git repo). Concretely, the loop is: edit locally → `scp` changed files
to the server → `docker compose build <service>` → `docker compose up -d
<service>` → run tests over SSH. Re-running `docker compose run`/`up`
against a stale image after only `scp`-ing files is the single most common
source of "fixed the bug but tests still fail" confusion in this repo —
always rebuild first.

`apps/execution-env` is **not** a docker-compose service — job-dispatcher
invokes it via plain `docker run` using the image tag in `ALLOWED_EXECUTION_IMAGE`.
Rebuild it directly: `docker build -t hardening-console-execution-env:latest ./apps/execution-env`.

Comments and docs throughout this codebase are written in Vietnamese —
match that convention when adding non-obvious comments.

## Common commands

Orchestrator (FastAPI/Python, `apps/orchestrator`):
```bash
docker compose build orchestrator
docker compose run --rm -e PYTHONPATH=/app orchestrator pytest -q
docker compose run --rm -e PYTHONPATH=/app orchestrator pytest tests/test_jobs.py::test_name -q
```
`PYTHONPATH=/app` is required — the Dockerfile's WORKDIR is `/app` but pytest's
default rootdir insertion doesn't add it to `sys.path` on its own.

Migrations (Alembic, `apps/orchestrator/app/migrations`):
```bash
docker compose run --rm orchestrator alembic upgrade head
docker compose run --rm orchestrator alembic revision -m "description" --rev-id 00NN
```

job-dispatcher (Python, `apps/job-dispatcher`) — has no pytest baked into the
production image (it's the one service holding `/var/run/docker.sock`, kept
minimal on purpose); run its test suite in a throwaway container instead:
```bash
docker run --rm -v "$(pwd)/apps/job-dispatcher:/src" -w /src python:3.12-slim \
  sh -c "pip install -q -r requirements.txt pytest && pytest -q"
```

web (React + TS + Vite + MUI, `apps/web`):
```bash
docker compose build web        # runs `tsc && vite build` inside the image
npm --prefix apps/web run dev   # local dev server, if Node is available
```

Agent / Agent Executor (Go, `apps/agent`, `apps/agent/executor`) — compiled
inside a `golang:1.22-alpine` container, never on the host:
```bash
./apps/agent/build.sh            # static linux/amd64 binary, apps/agent/agent
./apps/agent/executor/build.sh   # static linux/amd64 binary, apps/agent/executor/executor
docker run --rm -v "$(pwd)/apps/agent:/src" -w /src golang:1.22-alpine go test ./...
```

Agent Manager (Go, `apps/agent-manager`):
```bash
docker compose build agent-manager
docker run --rm -v "$(pwd)/apps/agent-manager:/src" -w /src golang:1.22-alpine go test ./...
```

## Architecture

### Services and network isolation (`docker-compose.yml`)

Six services, deliberately segmented across four Docker networks so that no
single compromised service has fleet-wide reach:

- **postgres** — app DB + a separate `orchestrator_audit` Postgres role that
  can only `INSERT`/`SELECT` on `audit_log` (no `UPDATE`/`DELETE`, enforced by
  Postgres `GRANT`, not just application code).
- **keycloak** — SSO/OIDC, 6 realm roles (`viewer`, `auditor`, `rule-editor`,
  `approver`, `operator`, `admin`), MFA required.
- **step-ca** — issues short-lived SSH certs (5-15 min TTL) for job SSH
  sessions. On `ca-net`, reachable only from `orchestrator`.
- **orchestrator** — the FastAPI core (`apps/orchestrator/app`); the only
  service on `ca-net` (mints certs) *and* `job-net` (talks to job-dispatcher).
  Has no Docker access itself.
- **job-dispatcher** — the **only** service that mounts `/var/run/docker.sock`.
  Not exposed on any public port; only reachable from `orchestrator` over
  `job-net`; only allowed to run one allowlisted image
  (`hardening-console-execution-env:latest`).
- **agent-manager** — mTLS relay for the self-built Go Agent running on
  fleet hosts; publishes a port to the LAN (agents live outside the compose
  network) but is not on `ca-net` — it requests its own server cert from
  Orchestrator rather than talking to step-ca directly.
- **web** — static SPA served by nginx, no business logic; nginx
  reverse-proxies `/api/*` to `orchestrator` so the browser only ever talks
  to one port.

### Job pipeline — the core execution model

Orchestrator never touches target hosts directly. For any SSH-based job it:
1. Determines SSH credentials for the target (see "SSH dispatch auth" below).
2. Calls **job-dispatcher** (the sole Docker-capable service) over `job-net`.
3. job-dispatcher spawns a short-lived **execution-env** container
   (`apps/execution-env/*.sh`), one job = one container, then removes it.
4. The script SSHes into the target host, does the work, prints a structured
   result to stdout, and exits; job-dispatcher streams that back as `Job.logs`.
5. Orchestrator parses `logs` into `Job.result_summary` and writes an audit
   event.

There are seven such SSH-dispatching job types today: scan, ssh-check,
remediate (dry-run/apply), restore, ssh-port-change, agent-install,
agent-uninstall — each with its own script in `apps/execution-env/`.

**SSH dispatch auth** is centralized in
`app/jobs.py:_get_ssh_dispatch_environment(host, principal)` — every one of
the seven call sites (spread across `jobs.py`, `agents.py`, `hosts.py`) goes
through it rather than deciding auth inline. It picks one of two mechanisms
per host:
- **Default: ephemeral CA cert** — mints a fresh SSH cert per job via
  `app/ca_client.py` → step-ca, scoped to `principal`, never stored.
- **Opt-in: static key** (`Host.static_ssh_private_key_encrypted`) — a
  permanent keypair generated once via `POST
  /hosts/{hostname}/bootstrap-static-ssh-key` and reused for every future
  job to that host, installed in `authorized_keys` for both `root` and
  `host.ssh_user` (a static key carries no principal claim the way a CA cert
  does, so both accounts actually used across the 7 call sites need it).
  This is a deliberately-accepted regression from the "no standing access"
  model, added per explicit user request — never modifies `sshd_config`, and
  additive only: the CA-cert path (`bootstrap-ca-trust`) is untouched so any
  host can still use it instead.

Host credential secrets (`ssh_password_encrypted`,
`static_ssh_private_key_encrypted`) are Fernet-encrypted via
`app/secrets_crypto.py` using `HOST_CREDENTIAL_ENCRYPTION_KEY` — that module
exists specifically as a dependency-free leaf so both `hosts.py` and
`jobs.py` can import it without creating a circular import (`hosts.py`
already imports from `jobs.py`). There is no reveal endpoint for either
secret — only clear/rotate.

### RBAC and audit

Six Keycloak roles, enforced in `app/auth.py` via `require_roles(...)` on
every mutating endpoint (never trust the UI to hide a button — it doesn't
enforce anything). There is **no four-eyes/two-person-integrity rule
anywhere in the system** — it was removed entirely per explicit user
request (previously: the user who performed step 1 of a two-step change on
a Tier 0/1 host couldn't themselves perform step 2 — control maturity
draft→production approval, `ca_migration_status` trust_deployed→migrated,
remediate dry-run→apply/the `RemediationRequest` approve-queue). A single
user holding the right role can now propose AND approve/apply the same
change, on any host tier. Don't reintroduce a four-eyes check without
explicit user request — this was a deliberate rollback, not an oversight.

`audit_log` (`app/audit.py`) is an append-only SHA-256 hash chain (each row
hashes in the previous row's hash) written through a Postgres role with
`INSERT`/`SELECT` only — tamper-evidence is enforced at the DB grant level,
not just in application code. Verify integrity via `GET
/internal/audit-events/verify`. Any endpoint that mutates state should write
an audit event with a minimal, secret-free payload (status/ids only — never
raw logs, diffs, or key material; see `trigger_ca_bootstrap` for the
reference shape).

### Control Registry and content trust

`Control` records (`app/controls.py`) carry a `maturity` state
(`draft`/`reviewed`/`production`) — the approver role gate still applies
(`rule-editor` proposes, `approver`/`admin` promotes) but not four-eyes; an
approver can promote a control they created themselves — plus `risk_group`
(`"A"`/`"B"`) which can only be `"A"` while
`maturity == "production"` and auto-resets to `"B"` on any path that leaves
production. Editing a `production` control's `StandardMapping` or
`RemediationVariant` auto-demotes it back to `draft` — content changes must
re-earn approval, maturity can't silently drift from what was actually
reviewed. `control_versions` (migration 0006) records history in the same
DB transaction as the underlying change (not the separate audit-log
mechanism), so it can never desync from real state.

Remediation content itself flows through a separate 3-role process
(Puller/Reviewer/Signer, `scripts/content-signing/`) and is GPG-signature
verified inside the execution-env container before `remediate.sh` runs
anything — the trusted signer fingerprint is baked into the image at build
time (`apps/execution-env/trusted-signer-pubkey.asc`), since each job
container starts with an empty keyring.

### Agent (Go, `apps/agent`)

A separately-installable Reporter+Executor pair for hosts that opt into
continuous monitoring/Active Response instead of (or alongside) pull-based
SSH jobs. Reporter and Executor are built as two distinct static binaries
from the same Go module, communicate with `agent-manager` over mTLS, and are
deployed via systemd (`hardening-agent.service` / `hardening-executor.service`
+ `provision.sh`), not as containers. `ACTIVE_RESPONSE_ENABLED` (global) and
`Host.active_response_enabled` (per-host) are both off by default — Active
Response is wired and tested end-to-end but intentionally kept disabled
pending a dedicated pentest.

### Internal TLS bootstrapping

Every service gets its TLS server cert from **Orchestrator**, not from
step-ca directly — only Orchestrator sits on `ca-net`. Orchestrator itself
mints its own cert straight from step-ca (`app/serve.py`); job-dispatcher,
agent-manager, keycloak, and web each call one of
`POST /internal/{job-dispatcher,agent-manager,keycloak,web}/server-cert`
(`app/jobs.py`, `app/agents.py`) to get theirs, authenticated by their own
per-service shared secret (`JOB_DISPATCHER_SHARED_SECRET`,
`AGENT_MANAGER_SHARED_SECRET`, `KEYCLOAK_TLS_SHARED_SECRET`,
`WEB_TLS_SHARED_SECRET`) and renew on a loop. This is why Orchestrator runs
**two listeners** (`app/serve.py`): port 8000 (HTTPS, published, browser/API
traffic) and port 8001 (plain HTTP, not published — internal-only, exists
solely so services whose base images lack a TLS client, e.g. Keycloak/web's
wrapper scripts, can still fetch a cert without a chicken-and-egg "need a
valid cert to request a cert" problem). Keycloak's `sslRequired` is
`"external"` in `infra/keycloak/realm-export.json` — real TLS is live end
to end, not the earlier dev-only `"none"` state.

### Test isolation gotcha (orchestrator pytest suite)

`app.dependency_overrides` is a single global dict keyed by the dependency
function object, but `app` is one FastAPI singleton shared across every test
file in the process. Each router module's `_get_db` (e.g.
`hosts_module._get_db`, `jobs_module._get_db`) is therefore effectively
"owned" by exactly one test file:

| Key | Owning test file |
|---|---|
| `hosts_module._get_db` | `test_hosts.py` |
| `jobs_module._get_db` | `test_jobs.py` |
| `agents_module._get_db` | `test_agents.py` |
| `canary_module._get_db`, `controls_module._get_db` | `test_canary.py` (temporarily overrides and restores) |
| `rr_module._get_db` | `test_remediation_requests.py` |
| `controls_module._get_db` | `test_controls.py` |
| `control_templates_module._get_db` | `test_control_templates.py` |

If a second file assigns the same key, pytest's collection order (which
runs at import time, before any test executes) determines which override
wins for the *entire session*, silently redirecting that router's DB access
for every other test file too. Never add a new standalone test file that
overrides an already-owned key — extend the owning file instead.

### Known accepted gaps (don't "fix" these without checking `docs/architecture-proposal.md` first)

- SCAP scan content (`ssg-debderived`/`ssg-debian` packages) is open-source
  SCAP Security Guide content, not CIS-certified benchmark content — fine
  technically, but not yet cleared as an official compliance basis.
  Ubuntu 24.04 targets scanned with 22.04-era datastreams correctly report
  everything `notapplicable` (correct SCAP behavior, not a bug).
- Root CA currently runs online in a container (dev-only); the air-gapped
  root CA runbook/scripts (`infra/step-ca/root-ca-airgap-runbook.md`) are
  rehearsed and ready but not yet run for real on physical air-gapped
  hardware.
- `ACTIVE_RESPONSE_ENABLED` stays off pending an independent pentest of the
  Agent even though the plumbing is fully wired and E2E-tested.
- `README.md` lags real code state at times — it's a manually-written build
  log, not generated docs. When in doubt about current behavior (e.g. "is
  TLS real yet"), check the code/config directly (e.g.
  `infra/keycloak/realm-export.json`, `docker-compose.yml`) rather than
  trusting the latest README checklist entry.
