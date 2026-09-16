// Windows native-ETW telemetry -- the fallback used when Sysmon isn't
// installed (see sysmon_windows::is_available and main.rs's
// run_telemetry_sensor dispatch). Sysmon is deliberately tried *first*
// (see sysmon_windows.rs's own module doc comment: well-documented XML
// over a CLI tool vs. this file's direct Win32 ETW consumer FFI via the
// `ferrisetw` crate) -- this exists for fleets that can't or won't
// deploy Sysmon.
//
// VERIFICATION NOTE, read before trusting this file: every provider
// GUID / EventID / field name below is taken from the actual published
// ETW manifests for these two providers, not guessed or half-remembered
// -- see
// https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-17134/Microsoft-Windows-Kernel-Process.xml
// and .../Microsoft-Windows-Kernel-Network.xml -- cross-referenced
// against ferrisetw's own working examples (examples/user_trace.rs,
// examples/multiple_providers.rs, whose Provider::by_guid(...) call is
// a doc-tested snippet, not just an example) for the actual Rust call
// shapes. That said: this is the one part of the telemetry pipeline
// that could not be build-checked AT ALL in the environment this was
// written in -- no Windows box, and unlike sysmon_windows.rs (which is
// platform-independent logic underneath a thin wevtutil shell-out, and
// so could be compiled and clippy'd natively on Linux under a temporary
// module alias), `ferrisetw` and the `windows` crate it wraps only
// compile for an actual Windows target at all -- there's no
// platform-independent core to isolate and check. Three different
// attempts at real Windows cross-compilation in this environment (a
// local mingw toolchain, and two different Docker-based cross-rs
// container setups) each hit an unrelated infrastructure issue (missing
// mingw-w64-gcc with no root to install it; a rustup
// toolchain/target-resolution mismatch inside the container; a
// HOME/euid mismatch under Docker) rather than anything about this
// code. Build and test this specifically before relying on it -- with
// `cargo build --bin shipper --target x86_64-pc-windows-msvc` (or -gnu)
// on a real Windows machine or CI runner.
//
// Coverage vs. Sysmon, two real gaps, both by necessity, not oversight:
// - No `argv` for process_exec: Microsoft-Windows-Kernel-Process's
//   ProcessStart event (every version in the manifest) carries
//   ImageName but never a command line -- Sysmon gets that via its own
//   in-kernel enrichment, which a plain ETW consumer has no equivalent
//   for. `exe` is still populated; `argv` is always None here.
// - No file_write at all: the FileIo kernel provider's Create/Write
//   events are two of the more notoriously awkward ETW event classes to
//   consume correctly (a Create event and the actual filename are
//   separate records that need correlating by FileKey/FileObject) --
//   real, well-documented complexity even for people who DO have a
//   Windows box to iterate against. Given no way to verify a
//   correlation implementation here at all, this is deliberately left
//   unimplemented rather than shipped unverified. A later, Windows-side
//   pass is the right way to close this gap, not a guess made here.
//
// network_connect is IPv4 only, for a similar reason: the IPv6 variant
// of the "connection attempted" event (EventID 28) encodes addresses as
// raw 16-byte binary, while the IPv4 event (12) uses a plain UInt32 --
// ferrisetw's convenience `IpAddr` parsing is only confirmed (via its
// own working example, for a sibling TCP event using the same field
// types) against that UInt32 form.

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::*;
use ferrisetw::EventRecord;
use serde::Serialize;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

const FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const MAX_BATCH: usize = 100;
const MAX_RETRIES: u32 = 3;

// Microsoft-Windows-Kernel-Process and Microsoft-Windows-Kernel-Network,
// per the published manifests linked above.
const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_NETWORK_GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";

const EVENT_ID_PROCESS_START: u16 = 1;
const EVENT_ID_IMAGE_LOAD: u16 = 5;
const EVENT_ID_TCP_CONNECT_ATTEMPTED_V4: u16 = 12;

// The System process's PID -- an ImageLoad event attributed to it is a
// kernel driver load, not an ordinary user-mode module load into some
// process's own address space. Matches the same PID==4 heuristic
// seclog-ebpf's own module_load (Linux) uses for the same distinction;
// see that file's comment for why PID 4 specifically is a safe,
// well-known signal here.
const SYSTEM_PID: u32 = 4;

// Mirrors ebpf_linux.rs / sysmon_windows.rs's own NewTelemetryEvent (all
// three are the identical shape the server's models::NewTelemetryEvent
// expects) -- a separate definition, not shared code, since all three
// are mutually-exclusive-target compilation units that never build
// together in the same binary.
#[derive(Serialize)]
struct NewTelemetryEvent {
    kind: &'static str,
    host: String,
    pid: i64,
    // Always 0 here (or -1 for module_load -- see below): no POSIX uid
    // concept on Windows, and this provider carries no per-event user
    // identity the way Sysmon's own `User` field does. See
    // models::NewTelemetryEvent's doc comment for the uid-vs-user split.
    uid: i64,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    event_time: Option<DateTime<Utc>>,
}

pub async fn run(base_url: String, api_key: String, host: String) {
    println!(
        "[Telemetry] Starting native ETW consumer (Microsoft-Windows-Kernel-Process, \
         Microsoft-Windows-Kernel-Network) -- no Sysmon detected"
    );

    // Callbacks run on a background OS thread ferrisetw spawns internally
    // (start_and_process() returns immediately -- see the trace's own
    // doc comment below), not on this task's tokio worker, so they hand
    // events off through a channel rather than calling anything async
    // directly. tokio's UnboundedSender::send is a plain synchronous,
    // non-blocking method -- safe to call from any thread, no
    // spawn_blocking bridging needed on either side.
    let (tx, mut rx) = unbounded_channel::<NewTelemetryEvent>();

    let process_provider = Provider::by_guid(KERNEL_PROCESS_GUID)
        .add_filter(EventFilter::ByEventIds(vec![
            EVENT_ID_PROCESS_START,
            EVENT_ID_IMAGE_LOAD,
        ]))
        .add_callback(process_callback(host.clone(), tx.clone()))
        .build();

    let network_provider = Provider::by_guid(KERNEL_NETWORK_GUID)
        .add_filter(EventFilter::ByEventIds(vec![EVENT_ID_TCP_CONNECT_ATTEMPTED_V4]))
        .add_callback(network_callback(host.clone(), tx.clone()))
        .build();
    drop(tx); // the two clones above are what actually keep the channel alive

    // start_and_process() spawns its own background thread and returns
    // immediately with a handle -- it does NOT block this task. Holding
    // that handle (`_trace`) alive for the rest of this function is what
    // keeps the trace running: dropping it (here, at the end of this
    // function, or when the surrounding tokio task is aborted by the
    // reconciliation loop turning telemetry off) stops the trace
    // automatically, per ferrisetw's own documented Drop behavior --
    // the exact same "hold the sensor handle as a local, let task abort
    // = drop = stop" shape process_exec's Linux/eBPF path gets for free
    // from its own RAII types.
    let _trace = match UserTrace::new()
        .enable(process_provider)
        .enable(network_provider)
        .start_and_process()
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "[Telemetry] Failed to start the ETW trace: {e:?} -- telemetry disabled this \
                 run (are you Administrator?)"
            );
            return;
        }
    };

    println!(
        "[Telemetry] Native ETW sensor attached (process-exec, network-connect [IPv4 only], \
         module-load; no file-write coverage -- see this module's doc comment for why)"
    );

    let client = crate::new_http_client();
    let batch_url = format!("{base_url}/telemetry/batch");
    let mut batch: Vec<NewTelemetryEvent> = Vec::new();
    let mut flush_timer = tokio::time::interval(FLUSH_INTERVAL);

    loop {
        tokio::select! {
            _ = flush_timer.tick() => {
                flush_batch(&client, &batch_url, &api_key, &mut batch).await;
            }
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        batch.push(event);
                        if batch.len() >= MAX_BATCH {
                            flush_batch(&client, &batch_url, &api_key, &mut batch).await;
                        }
                    }
                    None => {
                        // Both senders live inside the providers' own
                        // callbacks, which the trace holds for its
                        // whole lifetime -- this only happens if the
                        // trace itself has already torn down.
                        eprintln!("[Telemetry] ETW event channel closed -- sensor thread exited, stopping");
                        return;
                    }
                }
            }
        }
    }
}

// sched:sched_process_exec's Linux equivalent, event-wise: fires once a
// process has started (ImageName already resolved), or once a kernel
// driver has loaded. One provider, two event IDs, because
// Microsoft-Windows-Kernel-Process happens to emit both -- see
// EVENT_ID_IMAGE_LOAD's handling below for why only PID==4 loads count
// as our module_load kind.
fn process_callback(
    host: String,
    tx: UnboundedSender<NewTelemetryEvent>,
) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |record: &EventRecord, schema_locator: &SchemaLocator| {
        let event_id = record.event_id();
        if event_id != EVENT_ID_PROCESS_START && event_id != EVENT_ID_IMAGE_LOAD {
            return;
        }
        let schema = match schema_locator.event_schema(record) {
            Ok(s) => s,
            Err(_) => return,
        };
        let parser = Parser::create(record, &schema);
        let event_time = etw_time_to_utc(record);

        if event_id == EVENT_ID_PROCESS_START {
            let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
            let exe: Option<String> = parser.try_parse("ImageName").ok();
            let _ = tx.send(NewTelemetryEvent {
                kind: "process_exec",
                host: host.clone(),
                pid: pid as i64,
                uid: 0,
                user: None,
                exe,
                argv: None, // not available from this provider -- see module doc comment
                src_ip: None,
                src_port: None,
                dst_ip: None,
                dst_port: None,
                protocol: None,
                event_time,
            });
            return;
        }

        // EVENT_ID_IMAGE_LOAD -- ordinary user-process DLL loads are
        // Sysmon's ImageLoad (event 7), which this project deliberately
        // doesn't cover on either platform; only a load attributed to
        // the System process is one of our four telemetry kinds.
        let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
        if pid != SYSTEM_PID {
            return;
        }
        let exe: Option<String> = parser.try_parse("ImageName").ok();
        let _ = tx.send(NewTelemetryEvent {
            kind: "module_load",
            host: host.clone(),
            // -1, not 0: 0 would be System Idle Process, an actual (if
            // unusual) real Windows PID, so it isn't a safe "not
            // applicable" sentinel the way it is elsewhere -- matches
            // sysmon_windows.rs's own DriverLoad handling exactly.
            pid: -1,
            uid: 0,
            user: None,
            exe,
            argv: None,
            src_ip: None,
            src_port: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            event_time,
        });
    }
}

fn network_callback(
    host: String,
    tx: UnboundedSender<NewTelemetryEvent>,
) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |record: &EventRecord, schema_locator: &SchemaLocator| {
        if record.event_id() != EVENT_ID_TCP_CONNECT_ATTEMPTED_V4 {
            return;
        }
        let schema = match schema_locator.event_schema(record) {
            Ok(s) => s,
            Err(_) => return,
        };
        let parser = Parser::create(record, &schema);
        let event_time = etw_time_to_utc(record);

        // Field names are exactly as published in the manifest -- note
        // "PID" here, not "ProcessID" (that's the Process provider's
        // own naming; this is a different provider with its own schema).
        let pid: u32 = parser.try_parse("PID").unwrap_or(0);
        let src_ip: Option<IpAddr> = parser.try_parse("saddr").ok();
        let dst_ip: Option<IpAddr> = parser.try_parse("daddr").ok();
        let src_port: Option<u16> = parser.try_parse("sport").ok();
        let dst_port: Option<u16> = parser.try_parse("dport").ok();

        let _ = tx.send(NewTelemetryEvent {
            kind: "network_connect",
            host: host.clone(),
            pid: pid as i64,
            uid: 0,
            user: None,
            exe: None,
            argv: None,
            src_ip: src_ip.map(|ip| ip.to_string()),
            src_port,
            dst_ip: dst_ip.map(|ip| ip.to_string()),
            dst_port,
            protocol: Some("tcp".to_string()),
            event_time,
        });
    }
}

fn etw_time_to_utc(record: &EventRecord) -> Option<DateTime<Utc>> {
    let ts = record.timestamp(); // time::OffsetDateTime
    let total_ns = ts.unix_timestamp_nanos();
    let secs = total_ns.div_euclid(1_000_000_000) as i64;
    let nsecs = total_ns.rem_euclid(1_000_000_000) as u32;
    DateTime::from_timestamp(secs, nsecs)
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
                eprintln!(
                    "[Telemetry] Attempt {attempt}/{MAX_RETRIES} failed to ship batch: server returned {}",
                    response.status()
                );
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
