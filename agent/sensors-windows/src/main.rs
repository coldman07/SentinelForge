#[cfg(windows)]
mod windows_sensor;

#[cfg(windows)]
mod windows_auth;

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !std::env::args().any(|argument| argument == "--service") {
        return windows_sensor::run();
    }
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(windows)]
const SERVICE_NAME: &str = "SentinelForgeWindowsSensor";

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(error) = run_service() {
        eprintln!("SentinelForge Windows service failed: {error}");
    }
}

#[cfg(windows)]
fn run_service() -> windows_service::Result<()> {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use windows_service::{
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };

    let running = Arc::new(AtomicBool::new(true));
    let stop_signal = running.clone();
    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_signal.store(false, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;

    let ready_status_handle = &status_handle;
    let ready_signal = running.clone();
    let sensor_result = windows_sensor::run_with_ready_callback(running, || {
        if let Err(error) = ready_status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }) {
            eprintln!("could not report Windows service as running: {error}");
            ready_signal.store(false, Ordering::SeqCst);
        }
    });
    let (exit_code, result) = match sensor_result {
        Ok(()) => (ServiceExitCode::Win32(0), Ok(())),
        Err(error) => {
            eprintln!("SentinelForge Windows sensor exited with an error: {error}");
            (ServiceExitCode::Win32(1), Err(()))
        }
    };
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    if result.is_err() {
        eprintln!("SentinelForge Windows service stopped with an error");
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the SentinelForge Windows sensor can only run on Windows");
}
