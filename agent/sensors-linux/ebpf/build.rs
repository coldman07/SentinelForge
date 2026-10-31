fn main() {
    let linker = which::which("bpf-linker").expect("bpf-linker must be installed");
    println!("cargo:rerun-if-changed={}", linker.display());
}
