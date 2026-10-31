# Rust endpoint agent

The first Rust slice is the platform-neutral process-start event model in
`core/`. Its fields follow the versioned Protobuf contract in
`../proto/events/v1/event.proto`.

The Linux Aya sensor is under `sensors-linux/`. It correlates
`sys_enter_execve` and `sys_exit_execve` to report successful process starts,
converts them into the shared event model, observes successful `openat` calls
as file events, and reports successful synchronous IPv4/IPv6 `connect` calls.

The initial Windows sensor is under `sensors-windows/`. It consumes process
start events from `Microsoft-Windows-Kernel-Process` and file create/delete
events from the kernel File I/O ETW provider, then POSTs shared JSON events to
the gateway. Process events include PID, image path, command line when
available, and parent PID. File events include the path as reported by ETW,
which may use a Windows device path rather than a drive letter. The ETW
sessions require an elevated Windows terminal. The sensor also reports
outbound TCP connects, accepted TCP connections, and UDP sends/receives with
local and remote addresses/ports for IPv4 and IPv6. File writes include the
ETW-reported byte count and are linked to paths through a bounded file-object
cache. The sensor also subscribes to Security log events 4624 and 4625 for
successful and failed logons; its service account must have permission to read
that channel. Configure `SF_GATEWAY_URL` to point at the gateway; it defaults
to `http://127.0.0.1:8080/v1/events`.
ETW callbacks enqueue events into a bounded in-memory queue and a worker thread
performs HTTP delivery. Events are logged to stderr and dropped if the queue is
full or the gateway request fails; a persistent offline queue and retry policy
remain future work.

Run the current core checks from this directory with:

```sh
cargo test
```

Build the Linux-only eBPF sensor from a Linux host with the Aya nightly toolchain
and `bpf-linker`; see `sensors-linux/README.md` for prerequisites and scope.

For foreground lab use, build and run the Windows sensor from an elevated
Windows terminal:

```powershell
$env:SF_GATEWAY_URL = "http://<gateway-host>:8080/v1/events"
cargo build -p sentinelforge-windows-sensor
cargo run -p sentinelforge-windows-sensor -- --console
```

The executable also supports the Windows Service Control Manager. Build it in
release mode, then from an elevated PowerShell terminal register the executable
with the SCM:

```powershell
cargo build --release -p sentinelforge-windows-sensor
$sensorExe = (Resolve-Path .\target\release\sentinelforge-windows-sensor.exe).Path
$servicePath = '"' + $sensorExe + '" --service'
sc.exe create SentinelForgeWindowsSensor binPath= $servicePath start= auto
sc.exe start SentinelForgeWindowsSensor
```

Stop or remove it with `sc.exe stop SentinelForgeWindowsSensor` and
`sc.exe delete SentinelForgeWindowsSensor`. The default service account is
LocalSystem, which can read the Security log and start the kernel ETW sessions.
Set `SF_GATEWAY_URL` in the system environment before starting the service when
the gateway is not on the same host.

This gateway route is an unauthenticated development transport. Use it only on
an isolated, trusted lab network until agent authentication and mTLS are added.
