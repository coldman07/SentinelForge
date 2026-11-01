use std::{
    collections::HashMap,
    convert::TryFrom,
    mem::size_of,
    ptr, thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use aya::{Ebpf, maps::RingBuf, programs::TracePoint};
use sentinelforge_agent_core::{
    FileEvent, Host, NetworkConnect, ProcessReference, ProcessStart, User, format_ip_address,
    format_timestamp, uuid_v4_from_random,
};
use sentinelforge_process_common::{FileOperationEvent, NetworkConnectEvent, ProcessExecEvent};

fn main() -> anyhow::Result<()> {
    let agent_pid = std::process::id();
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sentinelforge-process-ebpf"
    )))
    .context("load process eBPF program")?;

    let enter_program: &mut TracePoint = ebpf
        .program_mut("process_exec_enter")
        .context("find process_exec_enter program")?
        .try_into()
        .context("convert process_exec_enter program")?;
    enter_program
        .load()
        .context("load process entry tracepoint")?;
    enter_program
        .attach("syscalls", "sys_enter_execve")
        .context("attach sys_enter_execve tracepoint")?;

    let exit_program: &mut TracePoint = ebpf
        .program_mut("process_exec_exit")
        .context("find process_exec_exit program")?
        .try_into()
        .context("convert process_exec_exit program")?;
    exit_program
        .load()
        .context("load process exit tracepoint")?;
    exit_program
        .attach("syscalls", "sys_exit_execve")
        .context("attach sys_exit_execve tracepoint")?;

    let file_enter: &mut TracePoint = ebpf
        .program_mut("file_open_enter")
        .context("find file_open_enter program")?
        .try_into()
        .context("convert file_open_enter program")?;
    file_enter
        .load()
        .context("load file open entry tracepoint")?;
    file_enter
        .attach("syscalls", "sys_enter_openat")
        .context("attach sys_enter_openat tracepoint")?;

    let file_exit: &mut TracePoint = ebpf
        .program_mut("file_open_exit")
        .context("find file_open_exit program")?
        .try_into()
        .context("convert file_open_exit program")?;
    file_exit.load().context("load file open exit tracepoint")?;
    file_exit
        .attach("syscalls", "sys_exit_openat")
        .context("attach sys_exit_openat tracepoint")?;

    let openat2_available = attach_openat2(&mut ebpf)?;

    let unlinkat_exit: &mut TracePoint = ebpf
        .program_mut("file_unlinkat_exit")
        .context("find file_unlinkat_exit program")?
        .try_into()
        .context("convert file_unlinkat_exit program")?;
    unlinkat_exit
        .load()
        .context("load unlinkat exit tracepoint")?;
    unlinkat_exit
        .attach("syscalls", "sys_exit_unlinkat")
        .context("attach sys_exit_unlinkat tracepoint")?;

    let unlinkat_enter: &mut TracePoint = ebpf
        .program_mut("file_unlinkat_enter")
        .context("find file_unlinkat_enter program")?
        .try_into()
        .context("convert file_unlinkat_enter program")?;
    unlinkat_enter
        .load()
        .context("load unlinkat entry tracepoint")?;
    unlinkat_enter
        .attach("syscalls", "sys_enter_unlinkat")
        .context("attach sys_enter_unlinkat tracepoint")?;

    let write_exit: &mut TracePoint = ebpf
        .program_mut("file_write_exit")
        .context("find file_write_exit program")?
        .try_into()
        .context("convert file_write_exit program")?;
    write_exit.load().context("load write exit tracepoint")?;
    write_exit
        .attach("syscalls", "sys_exit_write")
        .context("attach sys_exit_write tracepoint")?;

    let write_enter: &mut TracePoint = ebpf
        .program_mut("file_write_enter")
        .context("find file_write_enter program")?
        .try_into()
        .context("convert file_write_enter program")?;
    write_enter.load().context("load write entry tracepoint")?;
    write_enter
        .attach("syscalls", "sys_enter_write")
        .context("attach sys_enter_write tracepoint")?;

    let close_exit: &mut TracePoint = ebpf
        .program_mut("file_close_exit")
        .context("find file_close_exit program")?
        .try_into()
        .context("convert file_close_exit program")?;
    close_exit.load().context("load close exit tracepoint")?;
    close_exit
        .attach("syscalls", "sys_exit_close")
        .context("attach sys_exit_close tracepoint")?;

    let close_enter: &mut TracePoint = ebpf
        .program_mut("file_close_enter")
        .context("find file_close_enter program")?
        .try_into()
        .context("convert file_close_enter program")?;
    close_enter.load().context("load close entry tracepoint")?;
    close_enter
        .attach("syscalls", "sys_enter_close")
        .context("attach sys_enter_close tracepoint")?;

    let renameat_exit: &mut TracePoint = ebpf
        .program_mut("file_renameat_exit")
        .context("find file_renameat_exit program")?
        .try_into()
        .context("convert file_renameat_exit program")?;
    renameat_exit
        .load()
        .context("load renameat exit tracepoint")?;
    renameat_exit
        .attach("syscalls", "sys_exit_renameat")
        .context("attach sys_exit_renameat tracepoint")?;

    let renameat_enter: &mut TracePoint = ebpf
        .program_mut("file_renameat_enter")
        .context("find file_renameat_enter program")?
        .try_into()
        .context("convert file_renameat_enter program")?;
    renameat_enter
        .load()
        .context("load renameat entry tracepoint")?;
    renameat_enter
        .attach("syscalls", "sys_enter_renameat")
        .context("attach sys_enter_renameat tracepoint")?;
    let renameat2_available = attach_renameat2(&mut ebpf)?;

    let connect_enter: &mut TracePoint = ebpf
        .program_mut("network_connect_enter")
        .context("find network_connect_enter program")?
        .try_into()
        .context("convert network_connect_enter program")?;
    connect_enter
        .load()
        .context("load connect entry tracepoint")?;
    connect_enter
        .attach("syscalls", "sys_enter_connect")
        .context("attach sys_enter_connect tracepoint")?;

    let connect_exit: &mut TracePoint = ebpf
        .program_mut("network_connect_exit")
        .context("find network_connect_exit program")?
        .try_into()
        .context("convert network_connect_exit program")?;
    connect_exit
        .load()
        .context("load connect exit tracepoint")?;
    connect_exit
        .attach("syscalls", "sys_exit_connect")
        .context("attach sys_exit_connect tracepoint")?;

    let map = ebpf
        .take_map("PROCESS_EVENTS")
        .context("find PROCESS_EVENTS ring buffer")?;
    let mut events = RingBuf::try_from(map).context("open PROCESS_EVENTS ring buffer")?;
    let file_map = ebpf
        .take_map("FILE_EVENTS")
        .context("find FILE_EVENTS ring buffer")?;
    let mut file_events = RingBuf::try_from(file_map).context("open FILE_EVENTS ring buffer")?;
    let network_map = ebpf
        .take_map("NETWORK_EVENTS")
        .context("find NETWORK_EVENTS ring buffer")?;
    let mut network_events =
        RingBuf::try_from(network_map).context("open NETWORK_EVENTS ring buffer")?;
    let host = host_identity()?;
    let mut user_cache = HashMap::new();
    let mut descriptor_paths: HashMap<(u32, i32), String> = HashMap::new();
    eprintln!(
        "Watching successful execve, openat, unlinkat, renameat,{}{} and connect calls (agent PID {agent_pid}); press Ctrl-C to stop.",
        if openat2_available { " openat2" } else { "" },
        if renameat2_available {
            " renameat2"
        } else {
            ""
        }
    );

    loop {
        while let Some(item) = events.next() {
            if item.len() != size_of::<ProcessExecEvent>() {
                eprintln!(
                    "discarding process observation with unexpected size {}",
                    item.len()
                );
                continue;
            }
            // The producer and consumer use the same repr(C) type from common.
            let event = unsafe { ptr::read_unaligned(item.as_ptr().cast::<ProcessExecEvent>()) };
            if event.pid == agent_pid {
                continue;
            }
            let filename = nul_terminated(&event.filename);
            let (seconds, nanoseconds) = wall_clock()?;
            let timestamp =
                format_timestamp(seconds, nanoseconds).context("format event timestamp")?;
            let process_event = ProcessStart::from_exec_observation(
                event_id()?,
                timestamp,
                host.clone(),
                event.pid,
                user_for_uid(event.uid, &mut user_cache),
                filename,
            );
            process_event.validate().context("validate process event")?;
            println!("{}", process_event.to_json()?);
        }
        while let Some(item) = file_events.next() {
            if item.len() != size_of::<FileOperationEvent>() {
                eprintln!(
                    "discarding file observation with unexpected size {}",
                    item.len()
                );
                continue;
            }
            let observation =
                unsafe { ptr::read_unaligned(item.as_ptr().cast::<FileOperationEvent>()) };
            let requested_path = nul_terminated(&observation.filename);
            if observation.pid == agent_pid {
                continue;
            }
            let descriptor = (observation.pid, observation.fd);
            if observation.syscall == 9 {
                descriptor_paths.remove(&descriptor);
                continue;
            }
            let path = if observation.syscall == 8 {
                let path = current_fd_path(observation.pid, observation.fd)
                    .or_else(|| descriptor_paths.get(&descriptor).cloned());
                let Some(path) = path.filter(|value| is_file_like_path(value)) else {
                    continue;
                };
                path
            } else {
                resolved_open_path(
                    observation.pid,
                    observation.fd,
                    observation.dirfd,
                    requested_path,
                )
            };
            if matches!(observation.syscall, 1 | 2) && observation.fd >= 0 {
                descriptor_paths.insert(descriptor, path.clone());
            }
            let (seconds, nanoseconds) = wall_clock()?;
            let timestamp =
                format_timestamp(seconds, nanoseconds).context("format file event timestamp")?;
            let mut file_event = FileEvent::from_observation(
                event_id()?,
                timestamp,
                host.clone(),
                user_for_uid(observation.uid, &mut user_cache),
                &path,
                observation.syscall,
                observation.flags,
                observation.bytes_written,
                if (4..=7).contains(&observation.syscall) {
                    Some(format!("{:016x}", observation.correlation_id))
                } else {
                    None
                },
            );
            file_event.file.process = process_reference(observation.pid);
            file_event.validate().context("validate file event")?;
            println!("{}", file_event.to_json()?);
        }
        while let Some(item) = network_events.next() {
            if item.len() != size_of::<NetworkConnectEvent>() {
                eprintln!(
                    "discarding network observation with unexpected size {}",
                    item.len()
                );
                continue;
            }
            let observation =
                unsafe { ptr::read_unaligned(item.as_ptr().cast::<NetworkConnectEvent>()) };
            if observation.pid == agent_pid {
                continue;
            }
            let Some((remote_address, remote_port)) = remote_endpoint(&observation) else {
                eprintln!("discarding connect event with unsupported address family");
                continue;
            };
            let (seconds, nanoseconds) = wall_clock()?;
            let timestamp =
                format_timestamp(seconds, nanoseconds).context("format network event timestamp")?;
            let mut network_event = NetworkConnect::from_connect_observation(
                event_id()?,
                timestamp,
                host.clone(),
                user_for_uid(observation.uid, &mut user_cache),
                &remote_address,
                remote_port,
            );
            network_event.network.process = process_reference(observation.pid);
            network_event.validate().context("validate network event")?;
            println!("{}", network_event.to_json()?);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn attach_openat2(ebpf: &mut Ebpf) -> anyhow::Result<bool> {
    let exit_program: &mut TracePoint = ebpf
        .program_mut("file_openat2_exit")
        .context("find file_openat2_exit program")?
        .try_into()
        .context("convert file_openat2_exit program")?;
    if let Err(error) = exit_program.load() {
        eprintln!("openat2 tracepoint unavailable; continuing without it: {error}");
        return Ok(false);
    }
    if let Err(error) = exit_program.attach("syscalls", "sys_exit_openat2") {
        eprintln!("openat2 exit tracepoint unavailable; continuing without it: {error}");
        return Ok(false);
    }

    let enter_program: &mut TracePoint = ebpf
        .program_mut("file_openat2_enter")
        .context("find file_openat2_enter program")?
        .try_into()
        .context("convert file_openat2_enter program")?;
    if let Err(error) = enter_program.load() {
        eprintln!("openat2 entry tracepoint unavailable; continuing without it: {error}");
        return Ok(false);
    }
    if let Err(error) = enter_program.attach("syscalls", "sys_enter_openat2") {
        eprintln!("openat2 entry tracepoint unavailable; continuing without it: {error}");
        return Ok(false);
    }
    Ok(true)
}

fn attach_renameat2(ebpf: &mut Ebpf) -> anyhow::Result<bool> {
    let exit_program: &mut TracePoint = ebpf
        .program_mut("file_renameat2_exit")
        .context("find file_renameat2_exit program")?
        .try_into()
        .context("convert file_renameat2_exit program")?;
    if let Err(error) = exit_program.load() {
        eprintln!("renameat2 tracepoint unavailable; continuing without it: {error}");
        return Ok(false);
    }
    if let Err(error) = exit_program.attach("syscalls", "sys_exit_renameat2") {
        eprintln!("renameat2 exit tracepoint unavailable; continuing without it: {error}");
        return Ok(false);
    }

    let enter_program: &mut TracePoint = ebpf
        .program_mut("file_renameat2_enter")
        .context("find file_renameat2_enter program")?
        .try_into()
        .context("convert file_renameat2_enter program")?;
    if let Err(error) = enter_program.load() {
        eprintln!("renameat2 entry tracepoint unavailable; continuing without it: {error}");
        return Ok(false);
    }
    if let Err(error) = enter_program.attach("syscalls", "sys_enter_renameat2") {
        eprintln!("renameat2 entry tracepoint unavailable; continuing without it: {error}");
        return Ok(false);
    }
    Ok(true)
}

fn nul_terminated(bytes: &[u8]) -> &str {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).unwrap_or("<non-utf8>")
}

fn host_identity() -> anyhow::Result<Host> {
    let host_id = read_trimmed("/etc/machine-id")
        .or_else(|| read_trimmed("/etc/hostname"))
        .filter(|value| !value.is_empty())
        .context("read host identity from /etc/machine-id or /etc/hostname")?;
    let os_version =
        read_trimmed("/proc/sys/kernel/osrelease").context("read Linux kernel release")?;
    Ok(Host {
        host_id,
        os: "linux".into(),
        os_version,
        agent_version: env!("CARGO_PKG_VERSION").into(),
    })
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
}

fn resolved_open_path(pid: u32, fd: i32, dirfd: i32, requested_path: &str) -> String {
    if let Ok(path) = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")) {
        return path.to_string_lossy().into_owned();
    }

    let requested = std::path::Path::new(requested_path);
    if requested.is_absolute() {
        return requested_path.to_owned();
    }

    let base = if dirfd == -100 {
        format!("/proc/{pid}/cwd")
    } else {
        format!("/proc/{pid}/fd/{dirfd}")
    };
    std::fs::read_link(base)
        .map(|directory| directory.join(requested).to_string_lossy().into_owned())
        .unwrap_or_else(|_| requested_path.to_owned())
}

fn current_fd_path(pid: u32, fd: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn is_file_like_path(path: &str) -> bool {
    !path.starts_with("socket:[") && !path.starts_with("pipe:[") && !path.starts_with("anon_inode:")
}

fn remote_endpoint(event: &NetworkConnectEvent) -> Option<(String, u16)> {
    let port = u16::from_be_bytes(event.port_be);
    let address = format_ip_address(event.family, event.address)?;
    Some((address, port))
}

fn process_reference(pid: u32) -> Option<ProcessReference> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let path = path.to_string_lossy().into_owned();
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())?
        .to_owned();
    Some(ProcessReference {
        pid: u64::from(pid),
        name,
        path,
    })
}

fn user_for_uid(uid: u32, cache: &mut HashMap<u32, Option<User>>) -> Option<User> {
    if let Some(user) = cache.get(&uid) {
        return user.clone();
    }
    let user = resolve_user(uid);
    cache.insert(uid, user.clone());
    user
}

fn resolve_user(uid: u32) -> Option<User> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let entry_uid = fields.next()?.parse::<u32>().ok()?;
        if entry_uid != uid {
            return None;
        }
        Some(User {
            name: name.into(),
            sid: String::new(),
            privilege: if uid == 0 { "root" } else { "standard" }.into(),
        })
    })
}

fn wall_clock() -> anyhow::Result<(u64, u32)> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    Ok((elapsed.as_secs(), elapsed.subsec_nanos()))
}

fn event_id() -> anyhow::Result<String> {
    let mut bytes = [0_u8; 16];
    let mut filled = 0;
    while filled < bytes.len() {
        let result = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error()).context("read event ID randomness");
        }
        if result == 0 {
            anyhow::bail!("getrandom returned no bytes");
        }
        filled += result as usize;
    }
    Ok(uuid_v4_from_random(bytes))
}
