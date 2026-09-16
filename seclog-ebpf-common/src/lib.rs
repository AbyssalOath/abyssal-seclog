#![no_std]

// Shared between seclog-ebpf (the kernel-side programs, no_std) and the
// shipper's userspace ring-buffer poller (ebpf_linux.rs, std). Both sides
// compile this exact same source, so the #[repr(C)] layout the kernel side
// writes into the ring buffer and the layout userspace reads back out are
// guaranteed to agree -- no separate wire-format/serialization step needed
// for this hop (JSON only starts at the shipper -> server HTTP boundary,
// see NewTelemetryEvent in models.rs on the server side).
//
// One flat struct for both event kinds (kind-specific fields left zeroed
// when not applicable) rather than two separate ring buffers or a Rust
// enum -- Rust enums with data aren't FFI/repr(C)-safe in a way that's
// convenient to write from eBPF bytecode, and this matches the same "flat
// struct, unused fields left at a default" shape already used for
// NewLogEntry/LdapConfigRequest on the server side.

pub const TASK_COMM_LEN: usize = 16; // matches the kernel's TASK_COMM_LEN
pub const EXE_PATH_LEN: usize = 256;
pub const ARGS_LEN: usize = 512; // argv joined with NUL separators, truncated to fit

pub const KIND_PROCESS_EXEC: u8 = 1;
pub const KIND_NETWORK_CONNECT: u8 = 2;
pub const KIND_FILE_WRITE: u8 = 3;
pub const KIND_MODULE_LOAD: u8 = 4;

// AF_INET / AF_INET6, for `family` below -- not reusing libc's constants
// here since this crate has to stay no_std/dependency-free for the kernel
// side to compile.
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TelemetryEvent {
    pub kind: u8,
    _pad: [u8; 7],
    // Nanoseconds since boot (bpf_ktime_get_boot_ns on the kernel side) --
    // userspace converts to wall-clock time relative to its own boot time,
    // the same "best available signal, not an exact one" spirit as
    // parser::extract_event_time on the log-tailing side.
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,

    // --- KIND_PROCESS_EXEC fields ---
    // `exe`/`exe_len` are also reused, unmodified, by two other kinds
    // that just need "one string payload" and nothing else FIM/module
    // events don't need argv, a comm, or the network fields below, and
    // giving each kind its own dedicated string field would just grow
    // this struct for no benefit -- same "flat struct, kind-specific
    // fields left zeroed when not applicable" spirit as the rest of this
    // type:
    //   - KIND_FILE_WRITE: the file path that was opened for writing.
    //   - KIND_MODULE_LOAD: the loaded kernel module's name.
    pub comm: [u8; TASK_COMM_LEN],
    pub exe: [u8; EXE_PATH_LEN],
    pub exe_len: u16,
    pub args: [u8; ARGS_LEN],
    pub args_len: u16,

    // --- KIND_NETWORK_CONNECT fields ---
    pub family: u16, // AF_INET or AF_INET6
    pub protocol: u8,
    pub saddr: [u8; 16], // v4 address in the first 4 bytes, else full v6
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
}

impl TelemetryEvent {
    pub const fn zeroed() -> Self {
        Self {
            kind: 0,
            _pad: [0; 7],
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            comm: [0; TASK_COMM_LEN],
            exe: [0; EXE_PATH_LEN],
            exe_len: 0,
            args: [0; ARGS_LEN],
            args_len: 0,
            family: 0,
            protocol: 0,
            saddr: [0; 16],
            daddr: [0; 16],
            sport: 0,
            dport: 0,
        }
    }

    /// # Safety
    /// `bytes` must be at least `size_of::<TelemetryEvent>()` long and
    /// contain a validly-initialized `TelemetryEvent` (true for anything
    /// read back out of the ring buffer this struct was written into --
    /// the kernel side never emits a partially-initialized entry, see
    /// `write_and_submit` in seclog-ebpf's main.rs).
    pub unsafe fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Self) })
    }

    pub fn comm_str(&self) -> &str {
        str_from_fixed(&self.comm)
    }

    pub fn exe_str(&self) -> &str {
        core::str::from_utf8(&self.exe[..(self.exe_len as usize).min(EXE_PATH_LEN)]).unwrap_or("")
    }

    /// Raw NUL-separated argv bytes -- splitting on NUL is left to the
    /// caller (std's `split(|&b| b == 0)` in userspace; no_std has no
    /// equivalent std::ffi::CStr array-splitting worth pulling in here).
    pub fn args_bytes(&self) -> &[u8] {
        &self.args[..(self.args_len as usize).min(ARGS_LEN)]
    }
}

fn str_from_fixed(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..len]).unwrap_or("")
}
