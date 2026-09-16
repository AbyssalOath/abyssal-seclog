// Linux eBPF process-exec, network-connect, file-write (FIM), and
// kernel-module-load telemetry. Compiled only for
// `--target ... ` Linux builds with `--features telemetry` -- see the
// Cargo.toml comment on the `telemetry` feature for why this needs its own
// toolchain and isn't on by default. `main.rs` spawns `run()` as one task
// per the reconciliation loop's `telemetry_enabled` flag from
// `/agents/config`, the same shape already used for per-path file watchers,
// just one handle instead of a HashMap of them -- see the call site.
//
// Delivery here is best-effort, unlike the file-tailing path: there's no
// persisted read-position to hold back on failure (ring buffer events are
// gone once drained), so a batch that fails all retries is dropped rather
// than requeued. Telemetry is additive intelligence, not an audit-grade
// record the way `logs` is.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use aya::maps::RingBuf;
use aya::programs::TracePoint;
use chrono::{DateTime, Utc};
use seclog_ebpf_common::{
    TelemetryEvent, AF_INET, AF_INET6, KIND_FILE_WRITE, KIND_MODULE_LOAD, KIND_PROCESS_EXEC,
};
use serde::Serialize;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

const FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const MAX_BATCH: usize = 100;
const MAX_RETRIES: u32 = 3;

#[derive(Serialize)]
struct NewTelemetryEvent {
    kind: &'static str,
    host: String,
    pid: u32,
    uid: u32,
    // Always None on Linux -- uid above already carries real identity;
    // this exists for Windows' Sysmon-sourced events, which have no uid
    // concept at all. See models::NewTelemetryEvent's doc comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    argv: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    event_time: DateTime<Utc>,
}

// Runs forever (until the caller aborts the task). Never panics on a
// missing/unsupported kernel -- telemetry is additive, so a host that can't
// run it must fall through to a no-op rather than take the whole shipper
// process down with it (the file-tailing watchers must keep working
// regardless).
pub async fn run(base_url: String, api_key: String, host: String) {
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        eprintln!(
            "[Telemetry] /sys/kernel/btf/vmlinux not found -- this kernel has no BTF, which the \
             eBPF sensor's CO-RE relocation needs. Telemetry disabled on this host (kernels before \
             ~5.8, or BTF-stripped builds). Everything else keeps running normally.\n\
             [Telemetry] Fallback available: if auditd is running here, add these rules (see \
             ARCHITECTURE.md's \"Auditd telemetry fallback\") and add /var/log/audit/audit.log as \
             a watched path on the Agents page -- lower-fidelity than the sensor (goes through the \
             regular log pipeline as classified [Label] rows, not structured telemetry_events), but \
             real signal with zero extra toolchain:\n\
             [Telemetry]   -a always,exit -F arch=b64 -S execve -k seclog_exec\n\
             [Telemetry]   -a always,exit -F arch=b64 -S connect -k seclog_connect\n\
             [Telemetry]   -w /etc/passwd -p wa -k seclog_open   (repeat -w per sensitive path)\n\
             [Telemetry]   -a always,exit -F arch=b64 -S init_module,finit_module -k seclog_module"
        );
        return;
    }

    // Needed for older kernels that don't use memcg-based accounting for
    // locked eBPF map memory -- same as every aya template/example does.
    let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        eprintln!("[Telemetry] Warning: failed to raise the memlock rlimit; ring buffer setup may fail");
    }

    let mut ebpf = match aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/seclog-ebpf"))) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[Telemetry] Failed to load eBPF program: {e} -- telemetry disabled this run");
            return;
        }
    };

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        eprintln!("[Telemetry] Note: eBPF-side logging not initialized: {e} (non-fatal, no log statements to lose)");
    }

    if let Err(e) = attach_programs(&mut ebpf) {
        eprintln!("[Telemetry] Failed to attach eBPF programs: {e} -- telemetry disabled this run");
        return;
    }

    let ring_map = match ebpf.take_map("EVENTS") {
        Some(m) => m,
        None => {
            eprintln!("[Telemetry] EVENTS ring buffer not found in the loaded program -- telemetry disabled this run");
            return;
        }
    };
    let ring_buf = match RingBuf::try_from(ring_map) {
        Ok(rb) => rb,
        Err(e) => {
            eprintln!("[Telemetry] Failed to open EVENTS ring buffer: {e} -- telemetry disabled this run");
            return;
        }
    };
    let mut poll = match AsyncFd::with_interest(ring_buf, Interest::READABLE) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[Telemetry] Failed to poll EVENTS ring buffer: {e} -- telemetry disabled this run");
            return;
        }
    };

    // `ebpf` itself is never touched again after this point but must stay
    // alive for the rest of this function -- dropping it detaches the
    // tracepoints. It's captured by the enclosing scope, not moved
    // anywhere, so that happens naturally when this task is aborted.
    println!("[Telemetry] eBPF sensor attached (process-exec, network-connect, file-write, module-load)");

    let client = crate::new_http_client();
    let batch_url = format!("{base_url}/telemetry/batch");
    let mut batch: Vec<NewTelemetryEvent> = Vec::new();
    let mut flush_timer = tokio::time::interval(FLUSH_INTERVAL);

    loop {
        tokio::select! {
            _ = flush_timer.tick() => {
                flush_batch(&client, &batch_url, &api_key, &mut batch).await;
            }
            guard_result = poll.readable_mut() => {
                let mut guard = match guard_result {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!("[Telemetry] Ring buffer poll error: {e}");
                        continue;
                    }
                };
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if let Some(event) = unsafe { TelemetryEvent::from_bytes(&item) } {
                        batch.push(to_wire_event(&event, &host));
                    }
                }
                guard.clear_ready();
                if batch.len() >= MAX_BATCH {
                    flush_batch(&client, &batch_url, &api_key, &mut batch).await;
                }
            }
        }
    }
}

fn attach_programs(ebpf: &mut aya::Ebpf) -> Result<(), Box<dyn std::error::Error>> {
    let exec_program: &mut TracePoint = ebpf
        .program_mut("process_exec")
        .ok_or("process_exec program not present in seclog-ebpf object")?
        .try_into()?;
    exec_program.load()?;
    exec_program.attach("syscalls", "sys_enter_execve")?;

    let net_program: &mut TracePoint = ebpf
        .program_mut("network_connect")
        .ok_or("network_connect program not present in seclog-ebpf object")?
        .try_into()?;
    net_program.load()?;
    net_program.attach("sock", "inet_sock_set_state")?;

    let file_program: &mut TracePoint = ebpf
        .program_mut("file_write")
        .ok_or("file_write program not present in seclog-ebpf object")?
        .try_into()?;
    file_program.load()?;
    file_program.attach("syscalls", "sys_enter_openat")?;

    let module_program: &mut TracePoint = ebpf
        .program_mut("module_load")
        .ok_or("module_load program not present in seclog-ebpf object")?
        .try_into()?;
    module_program.load()?;
    module_program.attach("module", "module_load")?;

    Ok(())
}

fn to_wire_event(event: &TelemetryEvent, host: &str) -> NewTelemetryEvent {
    let event_time = boottime_to_utc(event.timestamp_ns);

    // file_write and module_load both reuse exe/exe_len for their one
    // string payload (the watched path, or the module name) -- see
    // seclog-ebpf-common's TelemetryEvent doc comment. Neither has argv
    // or network fields, same shape as process_exec's own exe-only case.
    let base = NewTelemetryEvent {
        kind: "",
        host: host.to_string(),
        pid: event.pid,
        uid: event.uid,
        user: None,
        exe: None,
        argv: None,
        src_ip: None,
        src_port: None,
        dst_ip: None,
        dst_port: None,
        protocol: None,
        event_time,
    };

    match event.kind {
        KIND_PROCESS_EXEC => {
            let argv = split_args(event.args_bytes());
            NewTelemetryEvent {
                kind: "process_exec",
                exe: non_empty(event.exe_str()),
                argv: if argv.is_empty() { None } else { Some(argv) },
                ..base
            }
        }
        KIND_FILE_WRITE => NewTelemetryEvent {
            kind: "file_write",
            exe: non_empty(event.exe_str()),
            ..base
        },
        KIND_MODULE_LOAD => NewTelemetryEvent {
            kind: "module_load",
            exe: non_empty(event.exe_str()),
            ..base
        },
        _ => NewTelemetryEvent {
            kind: "network_connect",
            src_ip: ip_string(event.family, &event.saddr),
            src_port: Some(event.sport),
            dst_ip: ip_string(event.family, &event.daddr),
            dst_port: Some(event.dport),
            protocol: Some(protocol_name(event.protocol)),
            ..base
        },
    }
}

// bpf_ktime_get_boot_ns (kernel side) is nanoseconds since boot
// (CLOCK_BOOTTIME), not wall-clock -- convert by comparing against
// CLOCK_BOOTTIME right now, the same technique used anywhere eBPF
// timestamps need to become wall-clock time. Falls back to "now" (an
// approximation, not a crash) if clock_gettime itself fails.
fn boottime_to_utc(event_boottime_ns: u64) -> DateTime<Utc> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0 {
        return Utc::now();
    }
    let now_boottime_ns = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
    let delta_ns = now_boottime_ns.saturating_sub(event_boottime_ns);
    Utc::now() - chrono::Duration::nanoseconds(delta_ns as i64)
}

fn ip_string(family: u16, addr: &[u8; 16]) -> Option<String> {
    if family == AF_INET {
        Some(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string())
    } else if family == AF_INET6 {
        Some(Ipv6Addr::from(*addr).to_string())
    } else {
        None
    }
}

fn protocol_name(protocol: u8) -> String {
    match protocol {
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        other => other.to_string(),
    }
}

// Mirrors the exact technique the kernel side uses to lay these out: each
// argv slot is NUL-terminated (and zero-padded to its fixed slot size), so
// splitting the whole buffer on NUL bytes and dropping empty pieces (the
// padding) recovers the original argument boundaries.
fn split_args(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() { None } else { Some(s.to_string()) }
}

async fn flush_batch(client: &reqwest::Client, url: &str, api_key: &str, batch: &mut Vec<NewTelemetryEvent>) {
    if batch.is_empty() {
        return;
    }
    let payload = std::mem::take(batch);
    let count = payload.len();

    for attempt in 1..=MAX_RETRIES {
        match client.post(url).header("X-Agent-Key", api_key).json(&payload).send().await {
            Ok(response) if response.status().is_success() => {
                println!("[Telemetry] Shipped batch of {count} events ({})", response.status());
                return;
            }
            Ok(response) => {
                eprintln!("[Telemetry] Attempt {attempt}/{MAX_RETRIES} failed to ship batch: server returned {}", response.status());
            }
            Err(e) => {
                eprintln!("[Telemetry] Attempt {attempt}/{MAX_RETRIES} failed to ship batch: {e}");
            }
        }
        if attempt < MAX_RETRIES {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    eprintln!("[Telemetry] Dropping batch of {count} events after {MAX_RETRIES} failed attempts");
}
