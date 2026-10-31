use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let metadata = cargo_metadata::MetadataCommand::new().no_deps().exec()?;
    let ebpf_package = metadata
        .packages
        .into_iter()
        .find(|package| package.name == "sentinelforge-process-ebpf")
        .ok_or_else(|| anyhow::anyhow!("process eBPF package not found"))?;
    let root_dir = ebpf_package
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("eBPF package has no parent directory"))?;

    aya_build::build_ebpf(
        [aya_build::Package {
            name: "sentinelforge-process-ebpf",
            root_dir: root_dir.as_str(),
            ..Default::default()
        }],
        Toolchain::default(),
    )
}
