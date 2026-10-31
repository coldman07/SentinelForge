# Linux endpoint sensors

The process sensor attaches Aya eBPF programs to `syscalls/sys_enter_execve`
and `syscalls/sys_exit_execve`. It emits an event only when exec succeeds. The
loader converts it to the shared process event envelope, resolves host and user
metadata from standard Linux files, and prints gateway-shaped JSON. The current
sensor does not collect the full argv command line yet, so
`process.command_line` contains the executable path. The loader drops events
from its own process to avoid feeding its logging and metadata lookups back
into the event stream.

The file sensor correlates `sys_enter_openat` and `sys_exit_openat`. It emits
only successful opens, resolves the opened path through `/proc/<pid>/fd/<fd>`
when available, and records the Linux open flags in the file event. Actions
`open_create_intent` and `open_write_intent` describe requested flags; they do
not claim a file was created or written. A successful `O_TRUNC` open is
reported as `truncate`.

The loader also attaches to `openat2` when the kernel exposes its tracepoints.
It reads the `open_how.flags` field and sends successful opens through the same
file event pipeline. Older kernels continue with `openat` sensing only.
Successful `unlinkat` calls are reported as `delete`; `AT_REMOVEDIR` is reported
as `delete_directory`. Successful `renameat` and `renameat2` calls produce
paired `rename_from` and `rename_to` events with a shared `correlation_id`;
`renameat2` is optional on kernels without its tracepoint. Writes through an
already-open descriptor are reported for the `write` syscall, including the
successful byte count. Opened descriptor paths are cached until `close`; writes
to pipe, socket, and anonymous-inode descriptors are omitted. Descriptors that
were already open when the sensor started are resolved from `/proc` while they
remain open. `pwrite64` and `writev` are separate additions.

The network sensor correlates `sys_enter_connect` and `sys_exit_connect` and
reports successful IPv4 and IPv6 destinations. The transport protocol and
local endpoint are currently unknown. Nonblocking connects that return
`EINPROGRESS`, accepted connections, DNS activity, and UDP sends are not
reported by this slice.

The initial implementation supports the x86_64 tracepoint layout. Before
running, verify that the filename pointer is at offset 16 in
`/sys/kernel/tracing/events/syscalls/sys_enter_execve/format` and the return
value is at offset 16 in
`/sys/kernel/tracing/events/syscalls/sys_exit_execve/format`, the path pointer
is at offset 24 in
`/sys/kernel/tracing/events/syscalls/sys_enter_openat/format`, and the return
value is at offset 16 in
`/sys/kernel/tracing/events/syscalls/sys_exit_openat/format` (or the equivalent
debugfs tracing path), for `openat2` verify the pathname pointer at offset 24,
the `open_how` pointer at offset 32, and the size at offset 40 in
`/sys/kernel/tracing/events/syscalls/sys_enter_openat2/format`. Also verify the
`openat2` return value at offset 16 in
`/sys/kernel/tracing/events/syscalls/sys_exit_openat2/format`. For `unlinkat`,
verify the pathname pointer at offset 24 in
`/sys/kernel/tracing/events/syscalls/sys_enter_unlinkat/format` and return value
at offset 16 in
`/sys/kernel/tracing/events/syscalls/sys_exit_unlinkat/format`. For `renameat`,
verify old pathname at offset 24 and new pathname at offset 40 in
`/sys/kernel/tracing/events/syscalls/sys_enter_renameat/format`, plus return
value at offset 16 in
`/sys/kernel/tracing/events/syscalls/sys_exit_renameat/format`. For `renameat2`,
the same pathname offsets apply and flags are at offset 48; verify its return
value at offset 16 in `/sys/kernel/tracing/events/syscalls/sys_exit_renameat2/format`.
For `write`, verify the file descriptor at offset 16 in
`/sys/kernel/tracing/events/syscalls/sys_enter_write/format` and return value at
offset 16 in `/sys/kernel/tracing/events/syscalls/sys_exit_write/format`.
For network sensing, verify the sockaddr pointer is at offset 24 in
`/sys/kernel/tracing/events/syscalls/sys_enter_connect/format`, and the return
value is at offset 16 in
`/sys/kernel/tracing/events/syscalls/sys_exit_connect/format`. The sensor only
observes events; it does not block or alter process, file, or network
operations.

## Build and run

Use a Linux host with a nightly Rust toolchain, `rust-src`, and `bpf-linker`.
Then run:

```sh
cargo run --release
```

Loading the program requires the kernel capabilities and permissions for eBPF
and tracepoint access. The loader emits JSON to stdout; sending it to the
gateway is a later step.
