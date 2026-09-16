// Windows telemetry: polls the Microsoft-Windows-Sysmon/Operational event
// channel via wevtutil -- the same tool watch_windows_security_log
// (main.rs) already uses for the Security channel. No new toolchain, no
// eBPF, nothing beyond what a normal Windows shipper build already has --
// that's the whole point of doing Windows this way before native ETW
// (ferrisetw), which is a separate, later phase. Needs Sysmon
// (https://learn.microsoft.com/sysinternals/downloads/sysmon) installed
// and configured to log at least event IDs 1, 3, 6, and 11 -- the four
// this module maps, matching the same four kinds seclog-ebpf's Linux
// sensor covers (process_exec, network_connect, module_load, file_write
// respectively) so both platforms report through the identical
// telemetry_events schema (see models::NewTelemetryEvent) with no
// server-side platform-specific code at all. Every other Sysmon event ID
// (7/ImageLoad, 8/CreateRemoteThread, 12/13 RegistryEvent, etc.) is
// ignored for this phase.
//
// Deliberately does NOT re-filter events the way seclog-ebpf's
// file_write does (a hardcoded watched-path list): Sysmon already has
// its own mature, widely-used config system for exactly this (see
// SwiftOnSecurity's popular baseline config, or an operator's own) --
// re-implementing that filtering here would be redundant with, and could
// silently diverge from, whatever the operator already configured Sysmon
// to log. What Sysmon reports (per its own config), this ships.
//
// Polling, not a live subscription: wevtutil is a point-in-time query
// tool, so this genuinely re-queries on an interval rather than pushing
// events as they happen (that needs real ETW consumption, the "native
// ETW" roadmap item). Every poll re-fetches the last POLL_COUNT events
// and re-ships them -- deliberately not tracking a last-seen RecordID to
// query only what's new, matching watch_windows_security_log's own
// existing "re-fetch + rely on server-side event_hash dedup (INSERT
// IGNORE)" shape exactly, rather than introducing a second, untested
// incremental-query mechanism. At this poll count/interval the resulting
// redundant traffic is small; if Sysmon volume on a given fleet makes
// that worth avoiding, an EventRecordID-based `/q:` XPath filter is the
// next optimization, not a redesign.

use std::collections::HashMap;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Serialize;

const POLL_INTERVAL: Duration = Duration::from_secs(10);
const MAX_RETRIES: u32 = 3;

// Mirrors ebpf_linux.rs's NewTelemetryEvent (same server-side
// models::NewTelemetryEvent on the receiving end) -- a separate
// definition, not shared code, since the two are platform-exclusive
// compilation targets that never both build in the same binary.
#[derive(Serialize)]
struct NewTelemetryEvent {
    kind: &'static str,
    host: String,
    pid: i64,
    // Always 0 (or -1 -- see DriverLoad below) on Windows: there's no
    // POSIX uid concept here at all. `user` carries the real identity
    // (a resolved DOMAIN\name straight from Sysmon's own `User` field).
    // See models::NewTelemetryEvent's doc comment for the full split.
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
    println!("[Telemetry] Starting Sysmon poll (Microsoft-Windows-Sysmon/Operational)");
    let client = crate::new_http_client();
    let batch_url = format!("{base_url}/telemetry/batch");

    loop {
        match poll_events() {
            Ok(xml) => {
                let events: Vec<NewTelemetryEvent> = parse_events(&xml)
                    .iter()
                    .filter_map(|ev| to_wire_event(ev, &host))
                    .collect();
                if !events.is_empty() {
                    ship_batch(&client, &batch_url, &api_key, events).await;
                }
            }
            Err(e) => {
                eprintln!(
                    "[Telemetry] wevtutil query against Microsoft-Windows-Sysmon/Operational \
                     failed: {e} -- is Sysmon installed and running, and are you Administrator?"
                );
            }
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// `wevtutil gl` ("get log") just reads a channel's registered
// configuration -- it succeeds the moment Sysmon's manifest has been
// installed (i.e. Sysmon has been installed at all), regardless of
// whether it's actively logging anything right now, and fails cleanly
// if the channel was never registered. Cheap enough to call once at
// telemetry startup (see main.rs's run_telemetry_sensor) to decide
// between this module and etw_windows.rs, rather than needing a second
// piece of server-side config for the operator to think about.
pub fn is_available() -> bool {
    Command::new("wevtutil")
        .args(["gl", "Microsoft-Windows-Sysmon/Operational"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

// /rd:true = most recent first, /c:50 = last 50 events, /f:xml =
// structured output -- unlike watch_windows_security_log's /f:text (that
// code ships the whole raw block as a log message and never needs to
// pull out individual fields), telemetry needs specific named fields
// (Image, CommandLine, DestinationIp, ...) extracted unambiguously.
// wevtutil's <Data Name="X">value</Data> elements give that for free;
// text mode would mean guessing which of possibly several "User:"-style
// lines in a rendered block is the real one (Sysmon's own field vs. the
// envelope's account-that-wrote-the-log-entry, which is always just
// "SYSTEM" since Sysmon's service runs as SYSTEM).
fn poll_events() -> Result<String, String> {
    let output = Command::new("wevtutil")
        .args(["qe", "Microsoft-Windows-Sysmon/Operational", "/rd:true", "/c:50", "/f:xml"])
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

struct SysmonEvent {
    event_id: u32,
    time: Option<DateTime<Utc>>,
    fields: HashMap<String, String>,
}

// wevtutil's `/f:xml` output for multiple matched events is a sequence of
// back-to-back `<Event xmlns="...">...</Event>` fragments, NOT one
// well-formed document with a single root -- a well-known wevtutil quirk
// (every tool that consumes this output has to work around it one way or
// another). Rather than trying to parse the whole blob as one XML
// document (which would fail), this splits on `</Event>` and treats each
// resulting chunk independently via plain regex field extraction. That
// also means this works unchanged whether or not some wevtutil version
// ever does wrap the output in an outer root -- an extra closing tag
// just becomes one more empty/no-`<Event`-in-it chunk, filtered out
// below.
fn parse_events(xml: &str) -> Vec<SysmonEvent> {
    static EVENT_ID_RE: OnceLock<Regex> = OnceLock::new();
    let event_id_re = EVENT_ID_RE.get_or_init(|| Regex::new(r"<EventID[^>]*>(\d+)</EventID>").unwrap());
    static TIME_RE: OnceLock<Regex> = OnceLock::new();
    let time_re = TIME_RE.get_or_init(|| Regex::new(r#"<TimeCreated SystemTime="([^"]+)""#).unwrap());
    static DATA_RE: OnceLock<Regex> = OnceLock::new();
    let data_re = DATA_RE.get_or_init(|| Regex::new(r#"<Data Name="([^"]+)">([^<]*)</Data>"#).unwrap());

    let mut events = Vec::new();
    for chunk in xml.split("</Event>") {
        if !chunk.contains("<Event") {
            continue; // trailing fragment after the last real event (or a stray closing tag)
        }

        let Some(id_caps) = event_id_re.captures(chunk) else { continue };
        let Ok(event_id) = id_caps[1].parse::<u32>() else { continue };

        // We only care about four event IDs -- skip field extraction
        // entirely for anything else rather than building a HashMap for
        // events we're about to throw away.
        if !matches!(event_id, 1 | 3 | 6 | 11) {
            continue;
        }

        let time = time_re
            .captures(chunk)
            .and_then(|c| DateTime::parse_from_rfc3339(&c[1]).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let mut fields = HashMap::new();
        for caps in data_re.captures_iter(chunk) {
            fields.insert(caps[1].to_string(), unescape_xml(&caps[2]));
        }

        events.push(SysmonEvent { event_id, time, fields });
    }
    events
}

// &amp; last, deliberately -- unescaping it first could turn a literal,
// already-correct "&amp;lt;" (a real ampersand followed by the text
// "lt;") into "&lt;", which would then get wrongly unescaped again into
// "<" by this same pass. Doing &amp; last means an already-literal
// ampersand from an earlier step is never re-interpreted.
fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn to_wire_event(ev: &SysmonEvent, host: &str) -> Option<NewTelemetryEvent> {
    let pid: i64 = ev.fields.get("ProcessId").and_then(|s| s.parse().ok()).unwrap_or(0);
    let user = ev.fields.get("User").filter(|s| !s.is_empty()).cloned();

    let base = NewTelemetryEvent {
        kind: "",
        host: host.to_string(),
        pid,
        uid: 0,
        user,
        exe: None,
        argv: None,
        src_ip: None,
        src_port: None,
        dst_ip: None,
        dst_port: None,
        protocol: None,
        event_time: ev.time,
    };

    match ev.event_id {
        // ProcessCreate. CommandLine is Windows' own full raw command
        // line as one string, not a pre-split argv array the way
        // execve's argv is -- shipped as a single-element argv rather
        // than tokenized ourselves: Windows command-line parsing has its
        // own quoting rules (CommandLineToArgvW's), distinct from a
        // shell's, and getting that wrong would be worse than not
        // splitting at all.
        1 => Some(NewTelemetryEvent {
            kind: "process_exec",
            exe: ev.fields.get("Image").cloned(),
            argv: ev
                .fields
                .get("CommandLine")
                .filter(|s| !s.is_empty())
                .map(|cmd| vec![cmd.clone()]),
            ..base
        }),
        // NetworkConnect.
        3 => Some(NewTelemetryEvent {
            kind: "network_connect",
            src_ip: ev.fields.get("SourceIp").cloned(),
            src_port: ev.fields.get("SourcePort").and_then(|s| s.parse().ok()),
            dst_ip: ev.fields.get("DestinationIp").cloned(),
            dst_port: ev.fields.get("DestinationPort").and_then(|s| s.parse().ok()),
            protocol: ev.fields.get("Protocol").cloned(),
            ..base
        }),
        // FileCreate -- reuses exe/exe_len (via the `exe` wire field) for
        // the created/overwritten file's path, same field reuse as
        // seclog-ebpf's file_write and module_load kinds on Linux.
        11 => Some(NewTelemetryEvent {
            kind: "file_write",
            exe: ev.fields.get("TargetFilename").cloned(),
            ..base
        }),
        // DriverLoad -- no ProcessId/User at all for this event kind (a
        // kernel-level driver load, not tied to a specific process), so
        // pid uses -1 here rather than the 0 every other kind falls back
        // to: 0 is System Idle Process, an actual (if unusual) real
        // Windows PID, so it's not a safe "not applicable" sentinel the
        // way it would be on Linux; -1 unambiguously never collides with
        // a real PID.
        6 => Some(NewTelemetryEvent {
            kind: "module_load",
            pid: -1,
            user: None,
            exe: ev.fields.get("ImageLoaded").cloned(),
            ..base
        }),
        _ => None,
    }
}

async fn ship_batch(client: &reqwest::Client, url: &str, api_key: &str, batch: Vec<NewTelemetryEvent>) {
    let count = batch.len();
    for attempt in 1..=MAX_RETRIES {
        match client.post(url).header("X-Agent-Key", api_key).json(&batch).send().await {
            Ok(resp) if resp.status().is_success() => {
                println!("[Telemetry] Shipped batch of {count} events ({})", resp.status());
                return;
            }
            Ok(resp) => {
                eprintln!(
                    "[Telemetry] Attempt {attempt}/{MAX_RETRIES} failed to ship batch: server returned {}",
                    resp.status()
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
