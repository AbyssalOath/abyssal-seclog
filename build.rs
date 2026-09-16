// Only does anything when built with `--features telemetry` -- otherwise
// `cargo build` (the server, or a plain shipper) must not require the eBPF
// toolchain (bpfel-unknown-none target, nightly, bpf-linker) at all. Cargo
// compiles build scripts with the same --cfg feature=... set as the package
// itself, so `#[cfg(feature = "telemetry")]` here works the same way it
// would in src/.
fn main() {
    #[cfg(feature = "telemetry")]
    build_ebpf::run().expect("failed to build seclog-ebpf");
}

#[cfg(feature = "telemetry")]
mod build_ebpf {
    use anyhow::{Context as _, anyhow};
    use aya_build::Toolchain;

    // Mirrors the upstream aya-template's build.rs exactly (see
    // https://github.com/aya-rs/aya-template) -- aya_build::build_ebpf
    // cargo-in-cargos a `cargo +nightly build -Z build-std=core --target
    // bpfel-unknown-none` for the seclog-ebpf package and leaves the
    // resulting object file where seclog-ebpf-common's
    // `include_bytes_aligned!(concat!(env!("OUT_DIR"), "/seclog-ebpf"))`
    // (in ebpf_linux.rs) expects to find it.
    pub fn run() -> anyhow::Result<()> {
        let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
            .no_deps()
            .exec()
            .context("MetadataCommand::exec")?;
        let ebpf_package = packages
            .into_iter()
            .find(|cargo_metadata::Package { name, .. }| name.as_str() == "seclog-ebpf")
            .ok_or_else(|| anyhow!("seclog-ebpf package not found"))?;
        let cargo_metadata::Package { name, manifest_path, .. } = ebpf_package;
        let ebpf_package = aya_build::Package {
            name: name.as_str(),
            root_dir: manifest_path
                .parent()
                .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
                .as_str(),
            ..Default::default()
        };
        aya_build::build_ebpf([ebpf_package], Toolchain::default())
    }
}
