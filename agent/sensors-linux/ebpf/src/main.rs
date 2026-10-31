#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::BPF_F_NO_PREALLOC,
    helpers::bpf_get_current_pid_tgid,
    helpers::bpf_ktime_get_ns,
    helpers::bpf_probe_read_user_buf,
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use sentinelforge_process_common::{
    FileOperationEvent, NetworkConnectEvent, ProcessExecEvent, exec_succeeded,
};

#[map]
static PROCESS_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static PENDING_EXEC: HashMap<u32, ProcessExecEvent> =
    HashMap::with_max_entries(16_384, BPF_F_NO_PREALLOC);

#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static PENDING_FILE_OPERATION: HashMap<u64, FileOperationEvent> =
    HashMap::with_max_entries(16_384, BPF_F_NO_PREALLOC);

#[map]
static PENDING_RENAME_FROM: HashMap<u64, FileOperationEvent> =
    HashMap::with_max_entries(16_384, BPF_F_NO_PREALLOC);

#[map]
static PENDING_RENAME_TO: HashMap<u64, FileOperationEvent> =
    HashMap::with_max_entries(16_384, BPF_F_NO_PREALLOC);

#[map]
static NETWORK_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static PENDING_CONNECT: HashMap<u64, NetworkConnectEvent> =
    HashMap::with_max_entries(16_384, BPF_F_NO_PREALLOC);

#[tracepoint]
pub fn process_exec_enter(ctx: TracePointContext) -> u32 {
    match try_process_exec_enter(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_process_exec_enter(ctx: TracePointContext) -> Result<(), i32> {
    // sys_enter_execve's filename pointer is at offset 16 on x86_64. Confirm
    // against the host's tracepoint format file before enabling this sensor.
    const FILENAME_POINTER_OFFSET: usize = 16;
    let filename: *const u8 = unsafe { ctx.read_at(FILENAME_POINTER_OFFSET)? };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let mut event = ProcessExecEvent {
        pid: tgid,
        uid: ctx.uid(),
        filename: [0; 256],
    };
    unsafe {
        bpf_probe_read_user_str_bytes(filename, &mut event.filename)
            .map_err(|error| error as i32)?;
    }
    PENDING_EXEC.insert(&tgid, &event, 0)
}

#[tracepoint]
pub fn process_exec_exit(ctx: TracePointContext) -> u32 {
    match try_process_exec_exit(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_process_exec_exit(ctx: TracePointContext) -> Result<(), i32> {
    // sys_exit_execve stores the syscall return value at offset 16 on x86_64.
    const RETURN_VALUE_OFFSET: usize = 16;
    let return_value: i64 = unsafe { ctx.read_at(RETURN_VALUE_OFFSET)? };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if !exec_succeeded(return_value) {
        let _ = PENDING_EXEC.remove(&tgid);
        return Ok(());
    }

    // BPF_F_NO_PREALLOC is set on PENDING_EXEC, so lookup and removal are
    // atomic with respect to concurrent updates as required by Aya's API.
    let event = unsafe { *PENDING_EXEC.get(&tgid).ok_or(-2)? };
    let _ = PENDING_EXEC.remove(&tgid);
    PROCESS_EVENTS.output::<ProcessExecEvent>(&event, 0)
}

#[tracepoint]
pub fn file_open_enter(ctx: TracePointContext) -> u32 {
    match try_file_open_enter(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_file_open_enter(ctx: TracePointContext) -> Result<(), i32> {
    // x86_64 sys_enter_openat context: dfd at 16, filename at 24, flags at 32.
    const DIRFD_OFFSET: usize = 16;
    const FILENAME_POINTER_OFFSET: usize = 24;
    const FLAGS_OFFSET: usize = 32;
    let dirfd: i32 = unsafe { ctx.read_at(DIRFD_OFFSET)? };
    let filename: *const u8 = unsafe { ctx.read_at(FILENAME_POINTER_OFFSET)? };
    let flags: u64 = unsafe { ctx.read_at(FLAGS_OFFSET)? };
    let task_id = bpf_get_current_pid_tgid();
    let mut event = FileOperationEvent {
        pid: (task_id >> 32) as u32,
        uid: ctx.uid(),
        fd: -1,
        dirfd,
        flags: flags as u32,
        syscall: 1,
        _padding: [0; 3],
        correlation_id: 0,
        bytes_written: 0,
        filename: [0; 256],
    };
    unsafe {
        bpf_probe_read_user_str_bytes(filename, &mut event.filename)
            .map_err(|error| error as i32)?;
    }
    PENDING_FILE_OPERATION.insert(&task_id, &event, 0)
}

#[tracepoint]
pub fn file_open_exit(ctx: TracePointContext) -> u32 {
    match try_file_operation_exit(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_file_operation_exit(ctx: TracePointContext) -> Result<(), i32> {
    // Syscall exit tracepoints store the return value at offset 16 on x86_64.
    const RETURN_VALUE_OFFSET: usize = 16;
    let return_value: i64 = unsafe { ctx.read_at(RETURN_VALUE_OFFSET)? };
    let task_id = bpf_get_current_pid_tgid();
    if return_value < 0 {
        let event = unsafe { *PENDING_FILE_OPERATION.get(&task_id).ok_or(-2)? };
        let _ = PENDING_FILE_OPERATION.remove(&task_id);
        if event.syscall == 9 {
            return FILE_EVENTS.output::<FileOperationEvent>(&event, 0);
        }
        return Ok(());
    }

    // BPF_F_NO_PREALLOC permits safe lookup while concurrent tasks update keys.
    let mut event = unsafe { *PENDING_FILE_OPERATION.get(&task_id).ok_or(-2)? };
    let _ = PENDING_FILE_OPERATION.remove(&task_id);
    match event.syscall {
        1 | 2 => event.fd = return_value as i32,
        3 => {}
        8 if return_value > 0 => event.bytes_written = return_value as u64,
        8 => return Ok(()),
        9 => {}
        _ => return Err(-22),
    }
    FILE_EVENTS.output::<FileOperationEvent>(&event, 0)
}

#[tracepoint]
pub fn file_openat2_enter(ctx: TracePointContext) -> u32 {
    match try_file_openat2_enter(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_file_openat2_enter(ctx: TracePointContext) -> Result<(), i32> {
    // x86_64 sys_enter_openat2: dirfd at 16, filename at 24, open_how at 32,
    // and the open_how byte size at 40. The flags member is its first u64.
    const DIRFD_OFFSET: usize = 16;
    const FILENAME_POINTER_OFFSET: usize = 24;
    const HOW_POINTER_OFFSET: usize = 32;
    const HOW_SIZE_OFFSET: usize = 40;
    let dirfd: i32 = unsafe { ctx.read_at(DIRFD_OFFSET)? };
    let filename: *const u8 = unsafe { ctx.read_at(FILENAME_POINTER_OFFSET)? };
    let how_ptr: *const u8 = unsafe { ctx.read_at(HOW_POINTER_OFFSET)? };
    let how_size: u64 = unsafe { ctx.read_at(HOW_SIZE_OFFSET)? };
    if how_size < 8 {
        return Err(-22);
    }
    let mut flags_bytes = [0_u8; 8];
    unsafe {
        bpf_probe_read_user_buf(how_ptr, &mut flags_bytes).map_err(|error| error as i32)?;
    }
    let flags = u64::from_ne_bytes(flags_bytes);
    let task_id = bpf_get_current_pid_tgid();
    let mut event = FileOperationEvent {
        pid: (task_id >> 32) as u32,
        uid: ctx.uid(),
        fd: -1,
        dirfd,
        flags: flags as u32,
        syscall: 2,
        _padding: [0; 3],
        correlation_id: 0,
        bytes_written: 0,
        filename: [0; 256],
    };
    unsafe {
        bpf_probe_read_user_str_bytes(filename, &mut event.filename)
            .map_err(|error| error as i32)?;
    }
    PENDING_FILE_OPERATION.insert(&task_id, &event, 0)
}

#[tracepoint]
pub fn file_openat2_exit(ctx: TracePointContext) -> u32 {
    match try_file_operation_exit(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

#[tracepoint]
pub fn file_unlinkat_enter(ctx: TracePointContext) -> u32 {
    match try_file_unlinkat_enter(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_file_unlinkat_enter(ctx: TracePointContext) -> Result<(), i32> {
    // x86_64 sys_enter_unlinkat context: dirfd at 16, pathname at 24, flags at 32.
    const DIRFD_OFFSET: usize = 16;
    const FILENAME_POINTER_OFFSET: usize = 24;
    const FLAGS_OFFSET: usize = 32;
    let dirfd: i32 = unsafe { ctx.read_at(DIRFD_OFFSET)? };
    let filename: *const u8 = unsafe { ctx.read_at(FILENAME_POINTER_OFFSET)? };
    let flags: u64 = unsafe { ctx.read_at(FLAGS_OFFSET)? };
    let task_id = bpf_get_current_pid_tgid();
    let mut event = FileOperationEvent {
        pid: (task_id >> 32) as u32,
        uid: ctx.uid(),
        fd: -1,
        dirfd,
        flags: flags as u32,
        syscall: 3,
        _padding: [0; 3],
        correlation_id: 0,
        bytes_written: 0,
        filename: [0; 256],
    };
    unsafe {
        bpf_probe_read_user_str_bytes(filename, &mut event.filename)
            .map_err(|error| error as i32)?;
    }
    PENDING_FILE_OPERATION.insert(&task_id, &event, 0)
}

#[tracepoint]
pub fn file_unlinkat_exit(ctx: TracePointContext) -> u32 {
    match try_file_operation_exit(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

#[tracepoint]
pub fn file_write_enter(ctx: TracePointContext) -> u32 {
    match try_file_write_enter(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_file_write_enter(ctx: TracePointContext) -> Result<(), i32> {
    // x86_64 sys_enter_write stores the file descriptor at offset 16.
    const FD_OFFSET: usize = 16;
    let fd: i32 = unsafe { ctx.read_at(FD_OFFSET)? };
    let task_id = bpf_get_current_pid_tgid();
    let event = FileOperationEvent {
        pid: (task_id >> 32) as u32,
        uid: ctx.uid(),
        fd,
        dirfd: -100,
        flags: 0,
        syscall: 8,
        _padding: [0; 3],
        correlation_id: 0,
        bytes_written: 0,
        filename: [0; 256],
    };
    PENDING_FILE_OPERATION.insert(&task_id, &event, 0)
}

#[tracepoint]
pub fn file_write_exit(ctx: TracePointContext) -> u32 {
    match try_file_operation_exit(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

#[tracepoint]
pub fn file_close_enter(ctx: TracePointContext) -> u32 {
    match try_file_close_enter(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_file_close_enter(ctx: TracePointContext) -> Result<(), i32> {
    // x86_64 sys_enter_close stores the file descriptor at offset 16.
    const FD_OFFSET: usize = 16;
    let fd: i32 = unsafe { ctx.read_at(FD_OFFSET)? };
    let task_id = bpf_get_current_pid_tgid();
    let event = FileOperationEvent {
        pid: (task_id >> 32) as u32,
        uid: ctx.uid(),
        fd,
        dirfd: -100,
        flags: 0,
        syscall: 9,
        _padding: [0; 3],
        correlation_id: 0,
        bytes_written: 0,
        filename: [0; 256],
    };
    PENDING_FILE_OPERATION.insert(&task_id, &event, 0)
}

#[tracepoint]
pub fn file_close_exit(ctx: TracePointContext) -> u32 {
    match try_file_operation_exit(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

#[tracepoint]
pub fn file_renameat_enter(ctx: TracePointContext) -> u32 {
    match try_file_rename_enter(ctx, 0, 4) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

#[tracepoint]
pub fn file_renameat2_enter(ctx: TracePointContext) -> u32 {
    match try_file_renameat2_enter(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_file_renameat2_enter(ctx: TracePointContext) -> Result<(), i32> {
    const FLAGS_OFFSET: usize = 48;
    let flags: u64 = unsafe { ctx.read_at(FLAGS_OFFSET)? };
    try_file_rename_enter(ctx, flags as u32, 6)
}

fn try_file_rename_enter(
    ctx: TracePointContext,
    flags: u32,
    syscall_marker: u8,
) -> Result<(), i32> {
    // x86_64 renameat/renameat2 context: old dirfd/path at 16/24 and new
    // dirfd/path at 32/40. renameat2's flags argument is at offset 48.
    const OLD_DIRFD_OFFSET: usize = 16;
    const OLD_PATH_POINTER_OFFSET: usize = 24;
    const NEW_DIRFD_OFFSET: usize = 32;
    const NEW_PATH_POINTER_OFFSET: usize = 40;
    let old_dirfd: i32 = unsafe { ctx.read_at(OLD_DIRFD_OFFSET)? };
    let old_path: *const u8 = unsafe { ctx.read_at(OLD_PATH_POINTER_OFFSET)? };
    let new_dirfd: i32 = unsafe { ctx.read_at(NEW_DIRFD_OFFSET)? };
    let new_path: *const u8 = unsafe { ctx.read_at(NEW_PATH_POINTER_OFFSET)? };
    let task_id = bpf_get_current_pid_tgid();
    let correlation_id = task_id ^ unsafe { bpf_ktime_get_ns() };
    let mut event = FileOperationEvent {
        pid: (task_id >> 32) as u32,
        uid: ctx.uid(),
        fd: -1,
        dirfd: old_dirfd,
        flags,
        syscall: syscall_marker,
        _padding: [0; 3],
        correlation_id,
        bytes_written: 0,
        filename: [0; 256],
    };
    if let Err(error) = unsafe { bpf_probe_read_user_str_bytes(old_path, &mut event.filename) } {
        return Err(error as i32);
    }
    PENDING_RENAME_FROM.insert(&task_id, &event, 0)?;

    event.dirfd = new_dirfd;
    event.syscall = syscall_marker + 1;
    event.filename = [0; 256];
    if let Err(error) = unsafe { bpf_probe_read_user_str_bytes(new_path, &mut event.filename) } {
        let _ = PENDING_RENAME_FROM.remove(&task_id);
        return Err(error as i32);
    }
    if let Err(error) = PENDING_RENAME_TO.insert(&task_id, &event, 0) {
        let _ = PENDING_RENAME_FROM.remove(&task_id);
        return Err(error);
    }
    Ok(())
}

#[tracepoint]
pub fn file_renameat_exit(ctx: TracePointContext) -> u32 {
    match try_file_rename_exit(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

#[tracepoint]
pub fn file_renameat2_exit(ctx: TracePointContext) -> u32 {
    match try_file_rename_exit(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_file_rename_exit(ctx: TracePointContext) -> Result<(), i32> {
    const RETURN_VALUE_OFFSET: usize = 16;
    let return_value: i64 = unsafe { ctx.read_at(RETURN_VALUE_OFFSET)? };
    let task_id = bpf_get_current_pid_tgid();
    if return_value != 0 {
        let _ = PENDING_RENAME_FROM.remove(&task_id);
        let _ = PENDING_RENAME_TO.remove(&task_id);
        return Ok(());
    }

    let from_result = {
        let from = unsafe { PENDING_RENAME_FROM.get(&task_id).ok_or(-2)? };
        FILE_EVENTS.output::<FileOperationEvent>(from, 0)
    };
    let to_result = {
        let to = unsafe { PENDING_RENAME_TO.get(&task_id).ok_or(-2)? };
        FILE_EVENTS.output::<FileOperationEvent>(to, 0)
    };
    let _ = PENDING_RENAME_FROM.remove(&task_id);
    let _ = PENDING_RENAME_TO.remove(&task_id);
    from_result?;
    to_result?;
    Ok(())
}

#[tracepoint]
pub fn network_connect_enter(ctx: TracePointContext) -> u32 {
    match try_network_connect_enter(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_network_connect_enter(ctx: TracePointContext) -> Result<(), i32> {
    // x86_64 sys_enter_connect context: fd at 16, sockaddr at 24, addrlen at 32.
    const FD_OFFSET: usize = 16;
    const ADDRESS_POINTER_OFFSET: usize = 24;
    const ADDRESS_LENGTH_OFFSET: usize = 32;
    let fd: i32 = unsafe { ctx.read_at(FD_OFFSET)? };
    let address_ptr: *const u8 = unsafe { ctx.read_at(ADDRESS_POINTER_OFFSET)? };
    let address_len: u32 = unsafe { ctx.read_at(ADDRESS_LENGTH_OFFSET)? };

    let mut family_bytes = [0_u8; 2];
    unsafe {
        bpf_probe_read_user_buf(address_ptr, &mut family_bytes).map_err(|error| error as i32)?;
    }
    let family = u16::from_ne_bytes(family_bytes);

    let mut raw_address = [0_u8; 28];
    match family {
        2 if address_len >= 16 => unsafe {
            bpf_probe_read_user_buf(address_ptr, &mut raw_address[..16])
                .map_err(|error| error as i32)?;
        },
        10 if address_len >= 28 => unsafe {
            bpf_probe_read_user_buf(address_ptr, &mut raw_address).map_err(|error| error as i32)?;
        },
        _ => return Err(-22),
    }

    let address = if family == 2 {
        [
            raw_address[4],
            raw_address[5],
            raw_address[6],
            raw_address[7],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
    } else {
        [
            raw_address[8],
            raw_address[9],
            raw_address[10],
            raw_address[11],
            raw_address[12],
            raw_address[13],
            raw_address[14],
            raw_address[15],
            raw_address[16],
            raw_address[17],
            raw_address[18],
            raw_address[19],
            raw_address[20],
            raw_address[21],
            raw_address[22],
            raw_address[23],
        ]
    };

    let task_id = bpf_get_current_pid_tgid();
    let event = NetworkConnectEvent {
        pid: (task_id >> 32) as u32,
        uid: ctx.uid(),
        fd,
        family,
        port_be: [raw_address[2], raw_address[3]],
        address,
    };
    PENDING_CONNECT.insert(&task_id, &event, 0)
}

#[tracepoint]
pub fn network_connect_exit(ctx: TracePointContext) -> u32 {
    match try_network_connect_exit(ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

fn try_network_connect_exit(ctx: TracePointContext) -> Result<(), i32> {
    // sys_exit_connect context stores the return value at offset 16 on x86_64.
    const RETURN_VALUE_OFFSET: usize = 16;
    let return_value: i64 = unsafe { ctx.read_at(RETURN_VALUE_OFFSET)? };
    let task_id = bpf_get_current_pid_tgid();
    if return_value != 0 {
        let _ = PENDING_CONNECT.remove(&task_id);
        return Ok(());
    }

    let event = unsafe { *PENDING_CONNECT.get(&task_id).ok_or(-2)? };
    let _ = PENDING_CONNECT.remove(&task_id);
    NETWORK_EVENTS.output::<NetworkConnectEvent>(&event, 0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
