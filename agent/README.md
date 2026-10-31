# Rust endpoint agent

The first Rust slice is the platform-neutral process-start event model in
`core/`. Its fields follow the versioned Protobuf contract in
`../proto/events/v1/event.proto`.

The Linux Aya sensor is under `sensors-linux/`. It correlates
`sys_enter_execve` and `sys_exit_execve` to report successful process starts,
converts them into the shared event model, observes successful `openat` calls
as file events, and reports successful synchronous IPv4/IPv6 `connect` calls.

Run the current core checks from this directory with:

```sh
cargo test
```

Build the Linux-only eBPF sensor from a Linux host with the Aya nightly toolchain
and `bpf-linker`; see `sensors-linux/README.md` for prerequisites and scope.
