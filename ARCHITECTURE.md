# Architecture

Abyssal SecLog is two deployables sharing one Rust crate (`seclog`):

- **`seclog`** (`src/main.rs`) — the server: an axum API, a static-file
  host for the dashboard, and the log ingestion/classification pipeline.
  Runs in Docker alongside MariaDB.
- **`shipper`** (`src/bin/shipper.rs`) — a standalone, dependency-free
  binary that runs on a monitored machine, tails configured log sources,
  classifies each line, and POSTs it to the server. Built for Linux,
  macOS, and Windows (`.github/workflows/release.yml`) and distributed as
  a single static-ish binary, not a container.

Both binaries link the shared library code in `src/lib.rs` — `parser`
(detection rules + severity classification) and `models` (wire types) —
so a log line is classified identically regardless of which side of the
wire it happens on.

## Server (`src/main.rs`, `src/db.rs`, `src/auth.rs`, `src/notify.rs`)

- **`main.rs`** — the axum `Router`, all HTTP handlers, and two
  `FromRequestParts` extractors that double as auth middleware:
  - `AuthUser` — validates the `__Host-seclog_session` cookie against the
    `sessions` table. Also enforces same-origin on state-changing
    requests (`check_same_origin`) and blocks all but `/change-password`
    and `/me` while `must_change_password` is set. Getting a session in
    the first place, via `login()`, branches on `users.auth_source`:
    a `'local'` row is verified with `auth::verify_password` exactly as
    always; an `'ldap'` row (or no row at all, if directory login is
    enabled) is verified live via `directory::authenticate_user` instead
    — see `directory.rs` below. A `'local'` row for a given username
    always short-circuits before the directory is ever consulted, so a
    directory entry can never shadow an existing local account.
  - `AgentAuth` — validates the `X-Agent-Key` header against the `agents`
    table. Used by every shipper-facing endpoint (`/logs` POST,
    `/agents/config`, `/agents/ping`). Deliberately a separate credential
    type from session cookies: it's a long-lived machine credential, not
    a human login.
  - `AdminUser` wraps `AuthUser` and additionally requires `role ==
    "admin"`.
  - `AuditAccess` wraps `AuthUser` and accepts `role == "admin" ||
    role == "auditor"` — the narrower role that can view and review
    log/audit data but administers nothing. Used only on `list_logs`,
    `logs_summary`, the audit-log/checkpoints endpoints, and
    `set_log_review_handler`; every other admin-gated endpoint (Agents,
    Directory, Settings, notifications, user management) stays on
    `AdminUser`. `role` is validated against
    `admin`/`user`/`auditor` at account-creation time
    (`admin_create_user`) — previously unchecked.
- **`db.rs`** — all SQL (via `sqlx`, MariaDB). Owns schema creation and
  idempotent migrations (`init_*_schema` functions, run on every
  startup — see `main()`). No ORM; queries are hand-written and mostly
  return tuples or `#[derive(FromRow)]` structs.
- **`auth.rs`** — password hashing (Argon2id), session/API-key token
  generation and hashing (tokens are stored as SHA-256 digests, never in
  plaintext — see `hash_token`), TOTP/MFA, and the in-memory
  `LoginRateLimiter`.
- **`notify.rs`** — fans a classified event out to enabled notification
  channels (email, Slack, Discord, Telegram, ntfy, generic webhook) by
  severity threshold. Fire-and-forget: dispatch runs on a detached
  `tokio::spawn` from `create_log` so a slow/dead webhook never delays
  the HTTP response back to the shipper that sent the event.
- **`directory.rs`** — the LDAP/Active Directory connector (via the
  `ldap3` crate), with two consumers:
  - Discovery: `test_connection` does a bind-only check, `sync_computers`
    binds then walks `computer_filter` under `base_dn` with the
    paged-results control (AD caps an unpaged search at 1000 entries)
    and upserts what it finds into `discovered_hosts`. Never connects
    to, or executes anything on, a discovered machine — see
    [README § Directory sync](README.md#directory-sync-ldap--active-directory)
    for why that's a deliberate boundary, not a missing feature.
  - Login: `authenticate_user` binds as the read-only service account,
    searches `user_base_dn` for `user_filter_template` with `{username}`
    substituted via `ldap3::ldap_escape` (never raw user input in a
    filter string), then opens a **second** connection and binds AS
    THAT ENTRY with the password just submitted -- that second bind is
    what actually proves the password, the search alone proves nothing.
    An empty password is rejected before any network call, since a
    blank simple-bind password is frequently accepted by directory
    servers as an anonymous bind. `is_admin` comes from checking the
    entry's `memberOf` against a configured `admin_group_dn`; no
    config means nobody is ever auto-admin this way.
- **Deployment packages (GPO / Intune)** — `enrollment_tokens` grew
  `max_uses`/`use_count`/`expires_at`/`label` columns, generalizing what
  was a strictly single-use table. `db::consume_enrollment_token` is one
  atomic conditional `UPDATE ... WHERE use_count < max_uses AND
  (expires_at IS NULL OR expires_at > NOW())` that covers both shapes —
  a single-use Agents-page token (`max_uses=1`, unchanged behavior) and
  a bulk one from `db::create_bulk_enrollment_token`, uniformly, with no
  separate code path and no call-site changes at `self_register_agent`.
  `main::windows_unattended_install_script` is a **separate** function
  from the interactive `windows_install_script`, not a shared code path
  with a flag — the two have genuinely different requirements
  (`Read-Host` vs. a literal embedded token; a human watching stdout vs.
  `Start-Transcript` to a file) and forcing them into one function would
  just be a branch that makes both harder to read. It registers the
  shipper as a Scheduled Task (`Register-ScheduledTask` with
  `-RestartCount`/`-RestartInterval`) rather than a real Windows service
  via `sc.exe`, because the shipper binary doesn't link the
  `windows-service` crate or implement the Service Control Manager's
  start/stop handshake — `sc.exe start` against a plain console binary
  fails with error 1053 ("did not respond in a timely fashion"); a
  Scheduled Task just launches and monitors the process, no SCM protocol
  required. See
  [README § Deployment packages](README.md#deployment-packages-gpo--intune).
- **`crypto.rs`** — AES-256-GCM encrypt/decrypt for secrets in this
  codebase that have to be *recoverable* rather than one-way hashed:
  the Directory feature's LDAP bind password (hand back to the
  directory server on every sync) and, since archival storage (below),
  the S3 secret key and SFTP password/private key (hand back to the
  archive backend on every upload). Keyed by `SECLOG_MASTER_KEY`
  (`crypto::MasterKey::from_env`), read once at startup and optional
  unless one of those features is actually configured. Kept
  deliberately separate from `auth.rs`, which only ever does one-way
  hashing/verification.
- **Audit trail** (CJIS AU-2, AU-3, AU-3(1), AU-9) — `db::record_audit_event`,
  called from every login/logout/password-change/MFA and every
  admin-gated state-changing handler (plus `list_logs`/`logs_summary`,
  so read access to log data is itself logged). Fire-and-forget from the
  caller's side — a write failure here never blocks the action it's
  recording — but not silent: a failed write raises a `[SYSTEM]` alert
  via `notify::trigger_alert` (see AU-5 below), since a broken audit
  pipeline is exactly the failure that control exists to catch. Never
  records a secret — e.g. a Directory config update logs that the bind
  password changed, not what it is. `audit_log` is a real hash chain
  (`prev_hash`/`row_hash`, computed inside a transaction that locks the
  current chain tip via `SELECT ... FOR UPDATE` on the last row, viable
  specifically because this table is low-volume and nothing ever
  deletes from it): `occurred_at` is computed in Rust and truncated to
  whole seconds (`.trunc_subsecs(0)`) *before* hashing, matching what
  the `TIMESTAMP` column can actually store — without that, the hash
  computed at write time and the value read back later would never
  match, and every row would falsely report as tampered (caught via
  live testing while building this, not just by inspection).
  `verify_audit_log_chain`/`GET /audit-log/verify` re-derives each row's
  hash plus checks id sequentiality (safe to assert strictly here, since
  nothing deletes). Readable at `AuditAccess`-gated `GET /audit-log`
  (Audit Log page).
- **Alert review** (CJIS AU-6) — `logs` carries `review_status`
  (open/reviewed/false_positive), `reviewed_by`, `reviewed_at`,
  `review_note`; `POST /logs/{id}/review` updates them and is itself an
  audited action. Surfaced as a clickable status pill on the Dashboard's
  per-host detail table.
- **`logs` integrity via checkpoints, not a chain** (CJIS AU-9) —
  `logs` is the actual write-throughput target (one insert per shipper
  per line; the 600k-row-crash/row-cap work elsewhere in this codebase
  exists because of exactly this table's volume), so a linear per-row
  chain would serialize every insert on reading the previous row's hash.
  Instead, an hourly background loop (`db::create_log_checkpoint`)
  hashes every row's existing `line_hash` (already computed per row for
  dedup, see `parser::hash_line`) for the range since the last
  checkpoint, storing one row in `log_checkpoints`.
  `list_log_checkpoints_with_status`/`GET /logs/checkpoints` re-hashes
  each checkpoint's range against current data on every read: exact
  row-count match + matching hash → `verified`; fewer rows than
  checkpointed → `unverifiable` (retention purged some of them —
  expected, not tampering); same count but different hash → `broken`.
- **Storage byte-visibility** (CJIS AU-11) — `db::get_table_size_bytes`
  reads `information_schema.tables` for a table's real on-disk size.
  No filesystem access needed or available: the `app` and `mariadb`
  containers don't share a volume in `docker-compose.yml`, so a
  `std::fs`/`statvfs` disk-free check from the server process would be
  checking the wrong, irrelevant container's filesystem. Folded into
  the existing row-cap capacity alert's message and shown read-only in
  Settings.
- Nine background loops started in `main()`: hourly expired
  session/MFA-pending cleanup; a 15-minute retention sweep (age- and
  row-count-based, configurable via **Settings**) that also checks row
  count against the cap and raises a `[SYSTEM]` alert (CJIS AU-5) once
  utilization crosses 90%, not repeatedly while still over — and, when
  archival storage (below) is enabled, archives before each delete
  actually runs; a 5-minute-cadence agent-staleness sweep (CJIS AU-5)
  that alerts once per staleness episode on an agent whose `last_seen`
  has passed `stale_agent_minutes` (Settings), via
  `agents.stale_alert_sent` — cleared on the agent's next check-in, so a
  recovered-then-relapsed agent alerts again; an hourly `logs` integrity
  checkpoint (above); a 5-minute-cadence directory-sync check (runs
  `directory::sync_computers` once `ldap_config.sync_interval_minutes`
  has actually elapsed, not on every wake); a 60-second correlation-rule
  sweep and a 30-second syslog-allowlist refresh (both below).
- **Correlation rules** — threshold detection layered on the same
  `[Label]`-prefixed rows `parser.rs`'s rule table already produces, not
  a second, independently-risky pattern language: `parser::classify`
  (the matching loop pulled out of `parse_line` unchanged) and
  `parser::known_labels` (dedup'd labels, backs the admin UI's label
  picker) are the only surface a `correlation_rules` row can reference.
  The 60s sweep runs one `GROUP BY {host|user} HAVING COUNT(*) >=
  threshold` query per enabled rule
  (`db::correlation_rule_hits` — the `host`/`user` column choice is a
  fixed Rust `match`, not string-interpolated user input, despite the
  query being built as a `String`) over a `created_at > NOW() -
  INTERVAL window MINUTE` slice, and dedupes firing per rule via an
  in-loop `HashMap<rule_id, HashSet<group_value>>` — the same shape as
  the retention loop's `capacity_alert_sent` bool, generalized from one
  flag to one set per rule. A hit doesn't write a `logs` row (would
  break the checkpoint hash-chain's row-count assumptions); it only
  calls `notify::trigger_alert`, the same "system alert only, no
  separate history table" pattern already used for staleness/capacity/
  checkpoint-failure.
- **Telemetry rules** — the same threshold-detection shape as Correlation
  rules above, but over `telemetry_events` (the Linux eBPF sensor's
  structured data, see "Endpoint telemetry" below) instead of
  `[Label]`-prefixed `logs` rows. A deliberate second table
  (`telemetry_rules`) and query function (`db::telemetry_rule_hits`)
  rather than generalizing `correlation_rules`: that table's one
  `match_label` column is a single fixed-vocabulary string, but a
  telemetry rule needs "which event kind" (`process_exec` |
  `network_connect`) plus an optional filter on a *different* field
  depending on that kind (an `exe` substring for `process_exec`, a
  `dst_port` for `network_connect`) — overloading `match_label` to carry
  two unrelated meanings would be worse than a second, honestly-typed
  table. `group_by` is always `host` here (v1): `telemetry_events` has no
  login username the way `logs.user` does, just a numeric `uid`, so
  there's no clean equivalent to Correlation rules' "per user" option
  yet. Runs in the *same* 60s loop/task as the correlation-rule sweep
  (one fewer background task, nothing gained from a separate timer) with
  its own `HashMap<rule_id, HashSet<group_value>>` dedup — kept separate
  from the correlation sweep's map since `telemetry_rules.id` and
  `correlation_rules.id` are unrelated integer spaces from different
  tables and could otherwise collide. Closes the gap the "Endpoint
  telemetry" section below used to call out explicitly: before this,
  `telemetry_events` had zero detection reading it at all.
- **Syslog receiver** (`src/syslog.rs`) — a UDP and/or TCP listener on
  514, bound once at startup if enabled (`syslog_config`, read like
  `DATABASE_URL`: an infra-level socket bind, not a live setting — see
  the module's own comment for why). Security model: raw syslog has no
  per-message auth industry-wide, so this is a fail-closed source-IP/
  CIDR allowlist (`ip_allowed`/`ip_in_cidr`, hand-rolled IPv4/IPv6
  matching against `std::net::IpAddr`, no new crate) refreshed from the
  DB every 30s by a separate task into a shared `Arc<RwLock<Vec<String>>>`
  — this is the one piece of syslog config that *is* live, unlike the
  bind itself. `parse_syslog_message` strips a `<PRI>` prefix, tries an
  RFC5424 header regex then RFC3164, and routes whatever's left through
  the exact same `parser::classify`/`extract_user`/`extract_event_time`
  the shipper path uses — a syslog-sourced event is classified
  identically to a shipper-sourced one, not by a second rule set.
  Ingestion (dedup hash, `db::insert_log`, `notify::trigger_alert`) is a
  deliberate near-duplicate of `create_log`'s sequence rather than a
  shared helper — the surrounding context (an HTTP handler needing a
  status code vs. a raw listener task) differs enough that forcing one
  shared function would just be a branch inside it.
- **Archival storage** (`src/archive.rs`) — lets the retention loop
  upload rows to S3-compatible object storage (`rusty-s3`, Sans-IO
  request signing executed via the `reqwest` client already a
  dependency — chosen over `aws-sdk-s3` specifically to avoid that
  crate's large dependency tree) or SFTP (`russh` + `russh-sftp`, pure
  Rust/tokio-native, chosen over `ssh2` specifically to avoid a new
  libssh2 C dependency in the Dockerfile) before deleting them.
  `archive_and_delete_older_than`/`archive_and_delete_beyond_row_cap`
  mirror `db::delete_logs_older_than`/`enforce_max_log_rows`'s exact
  WHERE-clause shape via `db::select_logs_older_than`/
  `select_logs_beyond_row_cap` (so what gets archived is exactly what's
  about to be deleted), upload a JSON Lines file, and only call the real
  delete on upload success — on failure they return `Ok(0)` (no rows
  deleted) *and* raise a `[SYSTEM]` alert themselves, so a bad
  credential degrades to "retention paused, admin notified," never
  silent data loss. SFTP host keys are not verified against a
  known-hosts store (`SftpClient::check_server_key` always returns
  `true`) — no host-key-pinning UI exists yet, so this is a documented,
  not silent, trust-the-hostname tradeoff, the same one already made for
  `ldap://` vs `ldaps://`. Secrets reuse `crypto::MasterKey` (now three
  consumers: LDAP bind password, S3 secret key, SFTP password/private
  key).

## Shipper (`src/bin/shipper/main.rs`)

Single binary, no config file — everything comes from two environment
variables (`SHIPPER_API_URL`, `SECLOG_ENROLLMENT_TOKEN`) and state it
persists next to itself:

- `.seclog_agent_key` — the API key, written once after a successful
  `/agents/self-register` call. On every subsequent start, its presence
  means "already enrolled" — the enrollment token (single-use) is only
  consulted on a truly first run.
- `.shipper_state_<sanitized-path>_<hash>` — one file per watched path,
  storing the last byte offset shipped from that file. The hash suffix
  exists because the sanitized-path prefix alone isn't collision-proof
  (see the comment on `state_file_for`).

Startup sequence in `main()`:

1. Load or obtain (`self-register`) the API key.
2. Blocking-loop `GET /agents/config` until it succeeds, to learn the
   server-assigned hostname (attached to every event this run ships,
   rather than trusting a locally-detected one).
3. On Windows/macOS only, spawn the platform-specific watcher
   (`watch_windows_security_log` / `watch_macos_unified_log`) — these
   read from `wevtutil` / `log stream` respectively, not a flat file,
   since neither OS exposes security events as one.
4. Enter the reconciliation loop: poll `/agents/config` every 30s, diff
   the returned `paths` against the currently-running set
   (`active: HashMap<String, JoinHandle<()>>`), `tokio::spawn` a
   `watch_file` task for anything new, `.abort()` the task for anything
   removed. Changing watched paths in the dashboard takes effect on the
   next poll — no shipper restart needed.

`watch_file` polls its path once a second: reopen-on-error, detect
rotation/truncation (`size < position` ⇒ reset to 0), and read exactly
the newly-appended bytes using `read_until(b'\n', ...)` with manual byte
accounting — not `BufRead::lines()`, which strips line endings before you
can count them and would incorrectly treat a not-yet-`\n`-terminated
line (very possible when polling a file mid-write) as a complete one.
An incomplete trailing chunk is left unconsumed and retried next poll.

`ship_line` runs each line through `parser::parse_line`, POSTs the
result to `/logs`, and retries transport failures *and* non-2xx
responses up to three times before giving up on that line (the read
position only advances on confirmed success — see
[CHANGELOG](CHANGELOG.md)).

`looks_like_own_output` exists to break a specific feedback loop: under
systemd, the shipper's own stdout goes to the journal, which on several
distros gets forwarded back into `/var/log/messages`/`/var/log/secure`.
If those are also watched paths, the shipper would re-ingest its own
"Shipped: ..." output, ship *that*, and so on — each generation slightly
longer, filling a disk overnight. Every journal line for a process is
tagged `<name>[<pid>]:`, so any line matching `shipper[\d+]:` is skipped
before it ever reaches the classifier.

## Detection pipeline (`src/parser.rs`)

`parse_line` runs each raw line through an ordered table of regex rules
(`rules()`) — first match wins — assigning a `Severity`
(Low/Medium/High/Critical) and a human-readable label, which gets
prefixed onto the stored message (`[<label>] <original line>`). Rule
ordering is load-bearing: more specific patterns must precede broader
ones that would otherwise shadow them (see the ordering comment at the
top of `rules()`). A username is opportunistically extracted via a
second, smaller pattern table (`extract_user`), falling back to
`"system"`.

Windows events flowing through the generic text path (rare — mostly
whatever `classify_event_id` in the shipper doesn't already handle
directly) and macOS unified-log output use the same table; only the
Windows Security-log watcher builds its `NewLogEntry` directly from
`wevtutil` output instead of going through `parse_line`.

`parse_line` also calls `extract_event_time` (CJIS AU-8), which tries,
in order, auditd's embedded epoch timestamp, a leading ISO8601/RFC3339
timestamp (capture-group-based, not a strict RFC3339 parser -- it
accepts a space OR `T` as the date/time separator and a timezone offset
with or without a colon, which is what's needed to also cover macOS's
`log stream --style syslog` format and wevtutil's `Date:` field, not
just "proper" RFC3339), then classic BSD syslog format
(`"Mon DD HH:MM:SS"`, which carries no year — inferred as the current
one, stepped back if that would place the event in the future, so a
shipper catching up on a backlog spanning a New Year's boundary still
resolves correctly). `None` when nothing matches; the row falls back to
`created_at` (ingestion time) as the best available signal. Unit-tested
in `parser.rs`'s own `#[cfg(test)]` module -- the one bit of test
coverage in this codebase so far, covering both the BSD year-inference
edge case and the offset arithmetic (a `+05:30` stamp shifting the
computed UTC instant correctly), added because both are exactly the
kind of logic that's easy to get subtly wrong. Reused directly (not
just via `parse_line`) by `watch_windows_security_log` in
`shipper.rs`, which builds its `NewLogEntry` from `wevtutil` text
without going through the classification rules but still wants the
`Date:` field's timestamp. The server separately sanity-bounds and
compares any `event_time` it receives against its own clock at insert
time, logging or alerting on large skew (see AU-5 above).

`hash_line` (SHA-256 of the fully-classified message + host) backs the
`logs.line_hash` unique constraint — `db::insert_log` uses `INSERT
IGNORE`, so a shipper retry after a dropped response never creates a
duplicate row.

## Endpoint telemetry (Linux eBPF: `seclog-ebpf`, `seclog-ebpf-common`, `src/bin/shipper/ebpf_linux.rs`)

Everything above this section is log-line tailing: reactive text parsing of
files/commands that already exist. This is different in kind, not degree —
a kernel-level sensor with no text log in the loop at all, giving direct
visibility into process-exec and outbound-network-connect activity a text
log might never capture. It's a separate workspace (`seclog-ebpf-common`,
`seclog-ebpf` as members alongside the root `seclog` package) and an
off-by-default Cargo feature (`telemetry`) — building it needs the
`bpfel-unknown-none` target, a nightly toolchain (`-Z build-std=core`), and
`bpf-linker` (itself needing LLVM; the project's own prebuilt
`x86_64-unknown-linux-gnu`-musl release binary avoids needing LLVM dev
packages on the build host — see `.github/workflows/release.yml`), none of
which the server or a plain log-shipping shipper should ever need. A
normal `cargo build`/`cargo build --release` (what `Dockerfile` and a
default shipper build both do) never touches these crates at all;
`cargo build --bin shipper --features telemetry` does.

- **`seclog-ebpf-common`** — a `#![no_std]`, dependency-free crate holding
  one `#[repr(C)]` `TelemetryEvent` struct, compiled unmodified by both the
  kernel-side eBPF programs and the userspace poller, so the ring-buffer
  bytes one side writes and the other reads are guaranteed to agree with no
  separate wire format for this hop. One flat struct for both event kinds
  (kind-specific fields left zeroed when not applicable), same shape as
  `NewLogEntry`/`LdapConfigRequest` elsewhere in this codebase.
- **`seclog-ebpf`** — four tracepoint programs sharing one `RingBuf` map:
  - `process_exec` hooks `syscalls:sys_enter_execve` (not
    `sched:sched_process_exec`) specifically so `filename`/`argv` come from
    stable, fixed-offset tracepoint fields instead of needing a generated
    `task_struct`/`mm_struct` CO-RE binding just to walk
    `current->mm->arg_start/arg_end` — one fewer moving part, at the cost
    of a bounded (`MAX_ARGS = 8`) argv capture. Parent pid is deliberately
    **not** captured in-kernel for the same reason (would need that same
    `task_struct` binding); v1 has no ppid field anywhere in the pipeline.
  - `network_connect` hooks `sock:inet_sock_set_state`, filtering
    `oldstate == SYN_SENT && newstate == ESTABLISHED` — new *outbound* TCP
    connections only (the accept-side transition is `SYN_RECV ->
    ESTABLISHED` instead). UDP and inbound connections are out of scope.
  - `file_write` hooks `syscalls:sys_enter_openat`, filtered in-kernel to
    write-intent opens (`O_WRONLY|O_RDWR|O_CREAT|O_TRUNC`) against a
    small hardcoded list (`WATCHED_FILES`) of commonly security-relevant
    absolute paths (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, etc.) —
    file-integrity monitoring, v1. Deliberately **not** an
    admin-configurable watchlist synced from the server: that needs a
    second BPF map, a userspace→kernel sync path on every config poll,
    and exact byte-for-byte path-encoding agreement between the two
    sides — real surface that deserves its own pass, not something to
    fold into "add file events." Matching is exact-string only (the
    literal `openat()` path argument, not a canonicalized/resolved one)
    — opening a watched file via a relative path, a different absolute
    alias, or a symlink won't match. Covers `open()` too (glibc's
    `open()` compiles down to the `openat` syscall on every mainstream
    64-bit target) but not `openat2()` (a distinct syscall, only reached
    via that specific libc call).
  - `module_load` hooks `module:module_load`, which fires once a module
    has *finished* loading (not at `init_module`/`finit_module` syscall
    *entry*, unlike every other program here — neither syscall carries a
    module name at entry: `init_module(2)` takes a raw ELF image,
    `finit_module(2)` only a file descriptor, so the name isn't known
    until the kernel has parsed it). Its module-name field is a
    `__string()`/`__data_loc` field rather than a plain fixed-offset one
    — still part of the tracepoint's own stable, append-only record
    format, just needing one extra decode step: the raw `u32` is
    `(offset << 16 | length)` relative to the record's own start,
    verified against the exact kernel macros that decode it
    (`include/trace/stages/stage3_trace_output.h`'s
    `__get_dynamic_array`/`__get_str`), not guessed.
  - `file_write` and `module_load` both reuse `TelemetryEvent`'s
    `exe`/`exe_len` fields for their one string payload (the watched
    path, or the module name) rather than growing the struct with
    kind-specific fields nothing else needs — same "flat struct,
    unused-for-this-kind fields left alone" spirit the struct's own doc
    comment already describes for `process_exec`.
  - `TelemetryEvent` (~850 bytes) is far too large for the ~512-byte BPF
    stack frame limit — building one as a stack local fails the verifier
    immediately (`Looks like the BPF stack limit is exceeded`, hit and
    fixed while building this). Both programs build the event in a
    single-slot `PerCpuArray` scratch map instead (`DATA_HEAP`), which
    means every field read back out (`exe_len`, `args_len` especially)
    must be explicitly reset on every call path, since a per-CPU map slot
    persists stale values from whichever call last used it — there's no
    fresh zeroed stack frame to fall back on.
  - CO-RE (Compile Once – Run Everywhere) is what makes one compiled
    program portable across kernel versions: relocations resolve against
    `/sys/kernel/btf/vmlinux` at *load* time on the target host, not build
    time. No BTF (kernels older than roughly 5.8, or BTF-stripped builds)
    means `ebpf_linux::run` logs a warning and returns without loading
    anything — telemetry is additive, so a host that can't run the sensor
    must fall through to normal operation, not take the shipper down.
- **`src/bin/shipper/ebpf_linux.rs`** — loads the bytecode (embedded via
  `include_bytes_aligned!` from `OUT_DIR`, produced by `build.rs` calling
  `aya_build::build_ebpf` — the same cargo-in-cargo pattern the upstream
  `aya-template` uses, since Cargo itself can't `-Z build-std` a regular
  dependency), attaches both tracepoints, and polls the ring buffer via a
  tokio `AsyncFd`. Converts `bpf_ktime_get_boot_ns` timestamps
  (`CLOCK_BOOTTIME`, not wall-clock) to UTC by diffing against
  `clock_gettime(CLOCK_BOOTTIME)` read at conversion time. Batches events
  (2s timer or 100 events, whichever first) into `POST /telemetry/batch` —
  unlike the file-tailing watchers, there's no persisted read-position to
  hold back on failure, so a batch that exhausts its 3 retries is dropped,
  not requeued; telemetry here is best-effort additive intelligence, not
  an audit-grade record the way `logs` is.
  `main.rs`'s config-reconciliation loop starts/stops this exactly like a
  per-path file watcher (`tokio::spawn`/`.abort()`), just one
  `Option<JoinHandle>` instead of a `HashMap` since there's only one sensor
  per host — driven by `AgentConfigResponse.telemetry_enabled`, a per-agent
  opt-in (`agents.telemetry_enabled`, off by default) toggled from the
  Agents page (`POST /agents/{id}/telemetry`). Attaches and polls all
  four tracepoints above through this same path.

Server side: `telemetry_events` (`db::init_telemetry_schema`) is a
separate table from `logs`, not a repurposed one — rows are structured
(pid/uid/exe/argv, or a connection 5-tuple) rather than one free-text
message, with `argv` stored as a JSON string column (same "arbitrary
structured value as a JSON string" shape as
`notification_channels.config`). `POST /telemetry/batch`
(`AgentAuth`-gated like `POST /logs`) bulk-inserts via `sqlx::QueryBuilder`
multi-row `INSERT IGNORE` rather than one query per event — a real batch
can be dozens to hundreds of rows, and this is deliberately the hot path
for a feature about not falling behind real-time. `event_hash` (content
hash, same role as `logs.line_hash`) gives the same retry-safety
`insert_log` already has. `GET /telemetry` is `AuditAccess`-gated with the
same pagination shape and `limit.clamp(1, 500)` cap as `list_logs`, for
the same reason (see the 600k-row DOM-crash comment on `list_logs`).
Threshold detection over this table now exists too — see "Telemetry
rules" above — but it's opt-in per rule and off by default (no seeded
defaults, unlike Correlation rules' three); the Telemetry page itself
stays a raw event stream regardless, for pivoting into the underlying
events once a rule alerts.
`telemetry_events` shares `logs`' age-based retention window
(`db::delete_telemetry_older_than`, same `log_retention_days` Settings
value, called from the same 15-minute retention loop) so turning the
sensor on doesn't grow an unbounded table — but deliberately has no
row-cap backstop or archival integration yet (see that function's own
comment for why bolting it onto `max_log_rows`/the existing archive
config isn't the right move): telemetry volume is a different order of
magnitude from `logs`, and a real row-cap/archive story for it is a
follow-on decision, not one to improvise inside this feature.

### Auditd telemetry fallback (hosts without BTF)

For a kernel the eBPF sensor can't run on at all (older than roughly
5.8, or a BTF-stripped build — the same check `ebpf_linux::run` already
does against `/sys/kernel/btf/vmlinux`), there's no structured
`telemetry_events` equivalent. What exists instead reuses 100% existing
architecture, deliberately: four new `parser::rules()` entries
(`src/parser.rs`) matching `type=SYSCALL` lines from the Linux audit
subsystem tagged with one of four specific recommended `auditctl` `-k`
keys (`seclog_exec`, `seclog_connect`, `seclog_open`, `seclog_module`) —
see the "Auditd telemetry fallback" comment right above those rules for
the exact recommended rule set. Matching on an admin-chosen key string
rather than a numeric syscall ID sidesteps syscall numbers being
architecture-dependent (execve is 59 on x86_64, 221 on arm64); it works
identically whether the key came from a `-S execve`-style syscall rule
or a `-w /path -p wa`-style file watch, since auditd attaches the key
the same way either way.

This is a real but deliberately lower-fidelity substitute, not a second
implementation of the sensor: each matching line becomes one ordinary
classified `logs` row via the *existing* text-tailing path (the operator
adds `/var/log/audit/audit.log` as a watched path on the Agents page,
exactly like any other log file) — no argv/exe/dst_port extraction, no
`telemetry_events` row, and critically, **not** visible to Telemetry
Rules (which only ever read `telemetry_events`). Correlation Rules (which
read `[Label]`-prefixed `logs` rows) can threshold on these four new
labels exactly like any other detection — `known_labels()`/`classify()`
both derive from the same `rules()` table, so no separate wiring was
needed for them to show up in the Correlation Rules label picker. The
shipper's telemetry task prints the exact recommended `auditctl` rules
to stderr the moment it detects it can't load the real sensor (see
`ebpf_linux::run`), rather than requiring the operator to already know
to look here.

## Data flow, end to end

```
watched file / journal / event log
        │  (shipper: tail, classify via parser::parse_line)
        ▼
POST /logs  { severity, user, message, host }   [X-Agent-Key]
        │  (server: AgentAuth, NewLogEntry::is_valid, hash_line)
        ▼
INSERT IGNORE INTO logs               ──▶ tokio::spawn notify::trigger_alert
        │                                        │
        │                                        ▼
        │                         enabled channels (severity ≥ threshold)
        ▼
GET /logs, /logs/summary   [session cookie]
        │  (server: AuthUser)
        ▼
dashboard (static/pages/dashboard.html + app.js)
```

## Frontend (`static/`)

No build step, no framework — plain HTML fragments and vanilla JS,
served directly by axum's `ServeDir` fallback.

- **`index.html`** — login/signup/MFA screen.
- **`app.html`** — the authenticated shell: a topbar (`nav.js`) plus a
  `#content` div that `router.js` swaps fragments into.
- **`router.js`** — a tiny hash-free client router: each route maps a
  path to an HTML fragment under `pages/` and an `init*()` function
  (`app.js`) to run once that fragment is in the DOM. Uses
  `history.pushState`/`popstate`, not a routing library.
- **`auth.js`** — `authFetch()` wraps `fetch` with `credentials:
  'include'` and a blanket "401 ⇒ redirect to login" handler. The
  session cookie is httpOnly, so the client never handles a token
  directly.
- **`app.js`** — everything else: dashboard rendering (with per-row
  review controls), the Agents page (enrollment, path management), the
  Syslog page (receiver enable/allowlist), the Audit Log page (activity
  table, chain verification, checkpoint status — `AuditAccess`-gated,
  not admin-only, unlike the rest), and Settings — preferences (display
  timezone, `AuditAccess`-gated like the Audit Log page, not admin-only:
  it's a personal display setting, not administration) plus four
  admin-only tabs: general (now also archival storage), security,
  alerts (now also correlation rules), and directory (LDAP config,
  discovered-host table, per-host enrollment token generation,
  deployment packages — folded in from a standalone page into a
  Settings tab, since it's exclusively admin configuration like every
  other Settings tab, not its own navigation-level concern). All built
  with `document.createElement` rather than `innerHTML` for anything
  containing server- or directory-supplied text.

## Persistence

MariaDB, schema created and migrated at server startup (`db::init_*`),
not via a separate migration tool — every `init_*_schema` function is
idempotent (`CREATE TABLE IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`)
so it's safe to run on every boot, including against an existing
database from an older version. See `db::init_schema` for an example of
an actual data migration (the old `level` column with `Info/Warn/Error`
values, remapped to `severity` with `Low/Medium/High`).

## Deployment

- **Server**: `Dockerfile` (multi-stage: `rust:bookworm` builder →
  `debian:bookworm-slim` runtime), orchestrated by `docker-compose.yml`
  (app + MariaDB + optional Caddy profile for automatic TLS). `install.sh`
  bootstraps `.env` and prompts for the TLS setup.
  `.github/workflows/docker-publish.yml` builds and pushes the image to
  GHCR on pushes to `main`/`dev` and on version tags.
- **Shipper**: cross-compiled for Linux/macOS/Windows and attached to a
  GitHub Release by `.github/workflows/release.yml` on a `v*` tag push.
  `/install/linux.sh` and `/install/windows.ps1` (served by the running
  server, see `main.rs`) download the right binary, verify it's a real
  executable (not an error page), and install it as a systemd
  service / scheduled task respectively.
