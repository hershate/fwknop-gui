# fwknop-dashboard — operations web panel (Stage 5+)

A lightweight read-mostly web panel for fwknopd. It visualizes the structured
audit log and Prometheus metrics produced by Phase 4b (`<run_dir>/fwknopd_audit.log`
and `fwknopd.metrics`) and wraps the `fwknopd-admin` CLI (Phase 4c) for
issuing credentials. The UI is a single embedded HTML page (`go:embed`), so the
whole panel ships as one self-contained binary.

See `REF/plan/Port Knocking.md §7.4/§7.6`.

## Build

```bash
cd server/dashboard
go build -o fwknop-dashboard .
```

Go 1.21+ (uses `net/http` standard library + `embed`; no external deps).

## Run

```bash
# read-only, localhost (default)
./fwknop-dashboard -run-dir /var/run/fwknop -addr 127.0.0.1:8088

# enable management (issue credentials via the UI); protect with a token
DASHBOARD_TOKEN=secret ./fwknop-dashboard -run-dir /var/run/fwknop -enable-write
```

Then open http://127.0.0.1:8088.

## What it shows

- **Counter tiles**: open / close / reject / replay / unknown_fingerprint /
  port_mismatch / aged / tofu_bind (from the metrics file, refreshed every 5s).
- **Recent SPA events** table (last 200 audit lines, newest first).
- **TOFU device bindings** (from `fwknop_tofu.state`).
- **Management** (optional, `-enable-write`): a form that calls
  `fwknopd-admin user add` to issue a new credential. The dashboard never
  handles key material itself — it shells out to `fwknopd-admin`, which remains
  the single source of truth.

## API

| Endpoint | Method | Description |
| --- | --- | --- |
| `/api/metrics` | GET | parsed Prometheus counters `{counters:{...}}` |
| `/api/events` | GET | last 200 audit events (newest first) |
| `/api/tofu` | GET | TOFU state file lines |
| `/api/admin/add` | POST | wraps `fwknopd-admin user add` (requires `-enable-write` + token) |

## Security notes

- Binds **localhost by default**; do not expose directly to untrusted networks.
- Write actions are disabled unless `-enable-write` is passed; with a
  `DASHBOARD_TOKEN` they require `Authorization: Bearer <token>`.
- The panel is a **view + thin wrapper**: all crypto and key handling stay in
  fwknopd / fwknopd-admin. The panel never reads raw keys from access.conf.

## Test

Covered by `test/run_fork_tests.sh` (builds the binary, probes the three APIs
and the served UI against sample data).
