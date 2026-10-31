# Rust endpoint agent

The first Rust slice is the platform-neutral process-start event model in
`core/`. Its fields follow the versioned Protobuf contract in
`../proto/events/v1/event.proto`.

The Linux Aya sensor is under `sensors-linux/`. It correlates
`sys_enter_execve` and `sys_exit_execve` to report successful process starts,
converts them into the shared event model, observes successful `openat` calls
as file events, and reports successful synchronous IPv4/IPv6 `connect` calls.

The initial Windows sensor is under `sensors-windows/`. It consumes process
start events from the `Microsoft-Windows-Kernel-Process` ETW provider and emits
the shared JSON process event to stdout. It captures process ID, image path,
command line when available, and parent process ID. The command line falls
back to the image path when ETW does not provide it. Starting the ETW session
requires an elevated Windows terminal; file, network and authentication
telemetry are not included in this first slice.

Run the current core checks from this directory with:

```sh
cargo test
```

Build the Linux-only eBPF sensor from a Linux host with the Aya nightly toolchain
and `bpf-linker`; see `sensors-linux/README.md` for prerequisites and scope.

Build and run the Windows ETW process sensor from an elevated Windows terminal:

```powershell
cargo build -p sentinelforge-windows-sensor
cargo run -p sentinelforge-windows-sensor
```
