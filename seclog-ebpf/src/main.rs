#![no_std]
#![no_main]

// Four tracepoint programs sharing one ring buffer (`EVENTS`), emitting the
// shared `seclog_ebpf_common::TelemetryEvent` struct the shipper's
// `ebpf_linux.rs` polls and re-serializes to JSON for `POST
// /telemetry/batch`. See seclog-ebpf-common/src/lib.rs for the wire layout
// and why it's one flat struct rather than two.
//
// process_exec and network_connect were chosen specifically to avoid
// needing any kernel-struct (task_struct/mm_struct) bindings: every field
// either comes straight from the tracepoint's own stable ABI (documented
// in Documentation/trace/events.rst -- these fields are append-only for
// BPF compatibility, never reordered/removed) or from a plain aya_ebpf
// helper. module_load bends that rule slightly: its one string field
// (`mod->name`) is a `__string()`/`__data_loc` field, not a plain
// fixed-offset one -- still part of the tracepoint's own stable record
// format (also append-only), just needing one extra decode step (see
// try_module_load below) instead of a direct `ctx.read_at`. None of the
// four need a generated bindings.rs / re-verifying per target kernel.

use aya_ebpf::{
    EbpfContext,
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_boot_ns,
    bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
};
use seclog_ebpf_common::{
    TelemetryEvent, ARGS_LEN, EXE_PATH_LEN, TASK_COMM_LEN, AF_INET, AF_INET6,
    KIND_FILE_WRITE, KIND_MODULE_LOAD, KIND_NETWORK_CONNECT, KIND_PROCESS_EXEC,
};

// 1 MiB -- sized to absorb a burst (e.g. a build or a package-manager run
// spawning hundreds of processes in a few seconds) without dropping events
// before the shipper's poll loop drains it. RingBuf sizes must be a power
// of two; aya_ebpf rounds up if not, but stating one directly here avoids
// relying on that.
const RING_BUF_BYTES: u32 = 1 << 20;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_BYTES, 0);

// TelemetryEvent (~850 bytes) is far too large for the ~512-byte BPF stack
// frame limit -- building one as a stack local blew the verifier's stack
// check immediately. Per-CPU scratch map instead: one slot is enough since
// a single CPU can't be running two BPF programs at once (no true
// reentrancy risk here), same technique every non-trivial aya program
// with a wide event struct uses.
#[map]
static DATA_HEAP: PerCpuArray<TelemetryEvent> = PerCpuArray::with_max_entries(1, 0);

fn event_scratch() -> Option<&'static mut TelemetryEvent> {
    unsafe { DATA_HEAP.get_ptr_mut(0).map(|p| &mut *p) }
}

fn write_event(event: &TelemetryEvent) {
    if let Some(mut entry) = EVENTS.reserve::<TelemetryEvent>(0) {
        entry.write(*event);
        entry.submit(0);
    }
    // No `Some`: the ring buffer is full (consumer isn't keeping up). Drop
    // the event rather than block -- there's no backpressure mechanism
    // available inside a tracepoint handler, and blocking here would stall
    // whatever syscall triggered it.
}

// --- process_exec: syscalls:sys_enter_execve ---
//
// Deliberately hooked here rather than sched:sched_process_exec: this
// tracepoint's `filename`/`argv`/`envp` fields are typed userspace pointers
// at fixed, stable offsets (see Documentation/trace/events.rst on syscall
// tracepoints), whereas sched_process_exec only carries a __data_loc
// filename and no argv at all -- getting argv from *that* tracepoint means
// walking current->mm->arg_start/arg_end via a generated task_struct
// binding instead. This is simpler and has one fewer moving part.
//
// Field offsets (stable across kernel versions -- syscall tracepoint ABI
// is tied to the syscall prototype itself):
//   8: __syscall_nr (u32, padded to 8)
//   16: filename (const char *)
//   24: argv (const char *const *)
//   32: envp (const char *const *) -- unused here

const FILENAME_OFFSET: usize = 16;
const ARGV_OFFSET: usize = 24;

// Fixed, compile-time loop bound -- required for the verifier to prove
// termination. Each arg gets an equal fixed slice of the shared ARGS_LEN
// buffer, so a long single argument gets truncated rather than starving
// the args after it; see seclog_ebpf_common::ARGS_LEN.
const MAX_ARGS: usize = 8;
const PER_ARG_LEN: usize = ARGS_LEN / MAX_ARGS;

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn process_exec(ctx: TracePointContext) -> u32 {
    match unsafe { try_process_exec(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_process_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    // event lives in the DATA_HEAP per-CPU map, not on the stack -- it
    // persists between calls on the same CPU, so every field this function
    // reads back out (exe_len, args_len in particular) must be explicitly
    // (re)set on every path, never left to "whatever zeroed() would have
    // given a fresh stack local."
    let event = match event_scratch() {
        Some(e) => e,
        None => return Ok(0),
    };
    event.kind = KIND_PROCESS_EXEC;
    event.timestamp_ns = unsafe { bpf_ktime_get_boot_ns() };

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid & 0xFFFF_FFFF) as u32;

    event.comm = [0; TASK_COMM_LEN];
    if let Ok(comm) = bpf_get_current_comm() {
        let len = comm.iter().position(|&b| b == 0).unwrap_or(comm.len()).min(event.comm.len());
        event.comm[..len].copy_from_slice(&comm[..len]);
    }

    event.exe_len = 0;
    let filename_ptr: *const u8 = unsafe { ctx.read_at(FILENAME_OFFSET)? };
    if !filename_ptr.is_null() {
        if let Ok(bytes) = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.exe) } {
            event.exe_len = bytes.len() as u16;
        }
    }

    let argv_ptr: *const *const u8 = unsafe { ctx.read_at(ARGV_OFFSET)? };
    let mut furthest_written = 0usize;
    if !argv_ptr.is_null() {
        for i in 0..MAX_ARGS {
            let arg_ptr = match unsafe { bpf_probe_read_user::<*const u8>(argv_ptr.add(i)) } {
                Ok(p) if !p.is_null() => p,
                _ => break,
            };
            let mut arg_buf = [0u8; PER_ARG_LEN];
            let read_len = match unsafe { bpf_probe_read_user_str_bytes(arg_ptr, &mut arg_buf) } {
                Ok(bytes) => bytes.len(),
                Err(_) => break,
            };
            let dst_start = i * PER_ARG_LEN;
            event.args[dst_start..dst_start + PER_ARG_LEN].copy_from_slice(&arg_buf);
            furthest_written = dst_start + read_len;
        }
    }
    event.args_len = furthest_written as u16;

    write_event(event);
    Ok(0)
}

// --- network_connect: sock:inet_sock_set_state ---
//
// Field offsets are the documented stable ABI for this tracepoint (it was
// specifically added, and is kept append-only, for BPF consumers -- see
// net/ipv4/... trace/events/sock.h). Filtering oldstate==SYN_SENT &&
// newstate==ESTABLISHED selects outbound connections completing their
// handshake (a client-initiated connect()); the inbound/accept-side
// transition is SYN_RECV -> ESTABLISHED instead, and is out of scope for
// this phase (see the phase-2 plan: "new outbound TCP connections" only).

const OLDSTATE_OFFSET: usize = 16;
const NEWSTATE_OFFSET: usize = 20;
const SPORT_OFFSET: usize = 24;
const DPORT_OFFSET: usize = 26;
const FAMILY_OFFSET: usize = 28;
const PROTOCOL_OFFSET: usize = 30;
const SADDR_V4_OFFSET: usize = 32;
const DADDR_V4_OFFSET: usize = 36;
const SADDR_V6_OFFSET: usize = 40;
const DADDR_V6_OFFSET: usize = 56;

const TCP_ESTABLISHED: i32 = 1;
const TCP_SYN_SENT: i32 = 2;

#[tracepoint(category = "sock", name = "inet_sock_set_state")]
pub fn network_connect(ctx: TracePointContext) -> u32 {
    match unsafe { try_network_connect(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_network_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    let oldstate: i32 = unsafe { ctx.read_at(OLDSTATE_OFFSET)? };
    let newstate: i32 = unsafe { ctx.read_at(NEWSTATE_OFFSET)? };
    if oldstate != TCP_SYN_SENT || newstate != TCP_ESTABLISHED {
        return Ok(0);
    }

    let event = match event_scratch() {
        Some(e) => e,
        None => return Ok(0),
    };
    event.kind = KIND_NETWORK_CONNECT;
    event.timestamp_ns = unsafe { bpf_ktime_get_boot_ns() };

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid & 0xFFFF_FFFF) as u32;

    // sport/dport are stored in network (big-endian) byte order in the
    // kernel's own inet_sock, same as inet_sport/inet_dport everywhere
    // else in the stack -- from_be corrects that regardless of this
    // host's own endianness.
    let sport: u16 = unsafe { ctx.read_at(SPORT_OFFSET)? };
    let dport: u16 = unsafe { ctx.read_at(DPORT_OFFSET)? };
    event.sport = u16::from_be(sport);
    event.dport = u16::from_be(dport);
    event.family = unsafe { ctx.read_at(FAMILY_OFFSET)? };
    event.protocol = unsafe { ctx.read_at(PROTOCOL_OFFSET)? };

    // Both branches fill the full 16-byte field (zeroing the tail for v4)
    // rather than leaving 12 stale bytes from a previous v6 event sitting
    // in this same heap slot -- ip_string() on the receiving end only ever
    // reads the first 4 bytes for AF_INET, but zeroing here costs nothing
    // and removes the question.
    if event.family == AF_INET {
        let saddr: [u8; 4] = unsafe { ctx.read_at(SADDR_V4_OFFSET)? };
        let daddr: [u8; 4] = unsafe { ctx.read_at(DADDR_V4_OFFSET)? };
        event.saddr = [0; 16];
        event.daddr = [0; 16];
        event.saddr[..4].copy_from_slice(&saddr);
        event.daddr[..4].copy_from_slice(&daddr);
    } else if event.family == AF_INET6 {
        event.saddr = unsafe { ctx.read_at(SADDR_V6_OFFSET)? };
        event.daddr = unsafe { ctx.read_at(DADDR_V6_OFFSET)? };
    } else {
        return Ok(0);
    }

    write_event(event);
    Ok(0)
}

// --- file_write: syscalls:sys_enter_openat, filtered to a fixed watchlist ---
//
// File-integrity monitoring, v1: a small, hardcoded list of commonly
// security-relevant absolute paths (credential/auth-config files) rather
// than an admin-configurable watchlist synced from the server. An
// eBPF-side dynamic watchlist (a BPF map populated from the shipper's
// config poll) is the natural next increment, but it adds real surface
// (a second map, a userspace->kernel sync path, exact byte-for-byte
// encoding agreement between the two sides) that deserves its own pass
// rather than being folded into "add file events" -- see
// ARCHITECTURE.md's Endpoint telemetry section.
//
// Matching is exact-string only: the literal path argument passed to
// openat(), not a canonicalized/resolved one. Opening one of these paths
// via a relative path, a different absolute alias, or a symlink pointing
// at it will NOT match -- a documented v1 limitation, same spirit as
// process_exec's MAX_ARGS truncation above.
//
// Hooking sys_enter_openat (not sys_enter_open) covers glibc's open() too
// -- open()/openat() both compile down to the openat syscall on every
// mainstream 64-bit target; the bare legacy `open` syscall is effectively
// unused by anything glibc-linked. openat2() (a distinct, newer syscall
// only reached via the explicit openat2() libc call, not a normal
// open()/openat() call) is not covered.

const OPENAT_FILENAME_OFFSET: usize = 24;
const OPENAT_FLAGS_OFFSET: usize = 32;

// Generic (arch-independent) fcntl.h values -- true on every Linux target
// aya/this project supports, not just x86_64.
const O_WRONLY: i32 = 0o1;
const O_RDWR: i32 = 0o2;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;

const WATCHED_FILES: &[&[u8]] = &[
    b"/etc/passwd",
    b"/etc/shadow",
    b"/etc/sudoers",
    b"/etc/ssh/sshd_config",
    b"/etc/crontab",
    b"/root/.ssh/authorized_keys",
];

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn file_write(ctx: TracePointContext) -> u32 {
    match unsafe { try_file_write(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_file_write(ctx: &TracePointContext) -> Result<u32, i64> {
    let flags: i32 = unsafe { ctx.read_at(OPENAT_FLAGS_OFFSET)? };
    if flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC) == 0 {
        return Ok(0); // read-only open -- not what FIM cares about
    }

    let filename_ptr: *const u8 = unsafe { ctx.read_at(OPENAT_FILENAME_OFFSET)? };
    if filename_ptr.is_null() {
        return Ok(0);
    }
    // Fresh stack local, not the shared per-CPU DATA_HEAP -- this is only
    // used for the watchlist comparison below, and a freshly allocated
    // array is zero-initialized on every call (unlike a persistent
    // per-CPU map slot, which can carry stale bytes from a previous,
    // longer path -- see DATA_HEAP's own comment above). 64 bytes covers
    // every entry in WATCHED_FILES with room to spare, well under the
    // eBPF stack limit.
    let mut path_buf = [0u8; 64];
    let path = match unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut path_buf) } {
        Ok(p) => p,
        Err(_) => return Ok(0),
    };
    if !WATCHED_FILES.iter().any(|&watched| watched == path) {
        return Ok(0);
    }

    let event = match event_scratch() {
        Some(e) => e,
        None => return Ok(0),
    };
    event.kind = KIND_FILE_WRITE;
    event.timestamp_ns = unsafe { bpf_ktime_get_boot_ns() };

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid & 0xFFFF_FFFF) as u32;

    // Reuse exe/exe_len for the watched path itself -- see
    // seclog-ebpf-common's TelemetryEvent doc comment for why.
    event.exe = [0; EXE_PATH_LEN];
    let len = path.len().min(EXE_PATH_LEN);
    event.exe[..len].copy_from_slice(&path[..len]);
    event.exe_len = len as u16;

    write_event(event);
    Ok(0)
}

// --- module_load: module:module_load ---
//
// Fires once a kernel module has finished loading (init_module/
// finit_module succeeded) -- not at syscall entry, unlike every other
// program in this file, because at *entry* neither syscall carries a
// module name: init_module(2) takes a raw ELF image buffer, and
// finit_module(2) takes only a file descriptor, so the name isn't known
// until the kernel has parsed the module. This tracepoint fires from
// deep inside that parsing, by which point `mod->name` is populated.
//
// Its one field of interest (mod->name) is a `__string()` field, which
// compiles to a `__data_loc` u32 in the actual record: the low 16 bits
// are a byte offset from the start of the tracepoint's own record (the
// same base TracePointContext::read_at uses), the high 16 bits are the
// string's length -- verified against the exact macros the kernel itself
// uses to decode this (include/trace/stages/stage3_trace_output.h:
// __get_dynamic_array/__get_str), not guessed. The length half isn't
// needed here since mod->name is itself always a NUL-terminated
// fixed-size buffer (MODULE_NAME_LEN, ~56-60 bytes depending on
// architecture word size) inside struct module, and
// bpf_probe_read_kernel_str_bytes already stops at the NUL.
//
// Record layout (include/trace/events/module.h's module_load
// TRACE_EVENT): 8-byte common header, then `unsigned int taints` at
// offset 8, then `u32 __data_loc_name` at offset 12 (no padding between
// two 4-byte-aligned u32 fields starting at an already-4-aligned offset).
const MODULE_NAME_DATALOC_OFFSET: usize = 12;

#[tracepoint(category = "module", name = "module_load")]
pub fn module_load(ctx: TracePointContext) -> u32 {
    match unsafe { try_module_load(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_module_load(ctx: &TracePointContext) -> Result<u32, i64> {
    let event = match event_scratch() {
        Some(e) => e,
        None => return Ok(0),
    };
    event.kind = KIND_MODULE_LOAD;
    event.timestamp_ns = unsafe { bpf_ktime_get_boot_ns() };

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid & 0xFFFF_FFFF) as u32;

    event.exe = [0; EXE_PATH_LEN];
    event.exe_len = 0;

    let data_loc: u32 = unsafe { ctx.read_at(MODULE_NAME_DATALOC_OFFSET)? };
    let name_offset = (data_loc & 0xffff) as usize;
    // Safety: `name_offset` comes from the kernel's own tracepoint
    // record, read via the same base pointer/mechanism as every other
    // field in this file -- not user-controlled input.
    let name_ptr = unsafe { (ctx.as_ptr() as *const u8).add(name_offset) };
    if let Ok(name) = unsafe { bpf_probe_read_kernel_str_bytes(name_ptr, &mut event.exe) } {
        event.exe_len = name.len() as u16;
    }

    write_event(event);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Required so the kernel permits calling the (GPL-restricted) helpers used
// above -- see the template's identical declaration.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
