#![no_std]

/// Fixed-size observation passed from the eBPF program to the Rust loader.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub filename: [u8; 256],
}

/// Successful file operation collected from Linux syscall tracepoints.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileOperationEvent {
    pub pid: u32,
    pub uid: u32,
    pub fd: i32,
    pub dirfd: i32,
    pub flags: u32,
    pub syscall: u8,
    pub _padding: [u8; 3],
    pub correlation_id: u64,
    pub bytes_written: u64,
    pub filename: [u8; 256],
}

/// Successful `connect` result collected from the Linux syscall tracepoints.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkConnectEvent {
    pub pid: u32,
    pub uid: u32,
    pub fd: i32,
    pub family: u16,
    pub port_be: [u8; 2],
    pub address: [u8; 16],
}

pub const fn exec_succeeded(return_value: i64) -> bool {
    return_value == 0
}

#[cfg(test)]
mod tests {
    use super::{FileOperationEvent, NetworkConnectEvent, ProcessExecEvent, exec_succeeded};

    #[test]
    fn event_layout_is_stable_for_the_ring_buffer() {
        assert_eq!(core::mem::size_of::<ProcessExecEvent>(), 264);
        assert_eq!(core::mem::align_of::<ProcessExecEvent>(), 4);
    }

    #[test]
    fn only_zero_exec_return_is_successful() {
        assert!(exec_succeeded(0));
        assert!(!exec_succeeded(-2));
        assert!(!exec_succeeded(-13));
    }

    #[test]
    fn file_event_layout_is_stable_for_the_ring_buffer() {
        assert_eq!(core::mem::size_of::<FileOperationEvent>(), 296);
        assert_eq!(core::mem::align_of::<FileOperationEvent>(), 8);
    }

    #[test]
    fn network_event_layout_is_stable_for_the_ring_buffer() {
        assert_eq!(core::mem::size_of::<NetworkConnectEvent>(), 32);
        assert_eq!(core::mem::align_of::<NetworkConnectEvent>(), 4);
    }
}
