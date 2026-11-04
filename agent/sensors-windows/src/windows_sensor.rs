use ferrisetw::{
    EventRecord,
    parser::Parser,
    provider::{
        Provider,
        kernel_providers::{FILE_IO_PROVIDER, KernelProvider, TCP_IP_PROVIDER},
    },
    schema_locator::SchemaLocator,
    trace::{KernelTrace, UserTrace},
};
use reqwest::{Certificate, Identity, blocking::Client};
use sentinelforge_agent_core::{
    FileDetails, FileEvent, Host, NetworkConnect, NetworkDetails, ProcessReference, ProcessStart,
    RawSource, SCHEMA_VERSION, format_timestamp, uuid_v4_from_random,
};
use std::path::PathBuf;
use std::{
    collections::HashMap,
    env,
    error::Error,
    io,
    net::IpAddr,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const KERNEL_PROCESS_PROVIDER: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const PROCESS_START_EVENT_ID: u16 = 1;
const PROCESS_KEYWORD: u64 = 0x10;
const FILE_CREATE_EVENT_ID: u16 = 32;
const FILE_DELETE_EVENT_ID: u16 = 35;
const FILE_CLOSE_EVENT_ID: u16 = 66;
const FILE_WRITE_EVENT_ID: u16 = 68;
const FILE_OBJECT_PATH_CAPACITY: usize = 65_536;
const PROCESS_PATH_CAPACITY: usize = 65_536;
const TCP_CONNECT_IPV4_EVENT_ID: u16 = 12;
const TCP_CONNECT_IPV6_EVENT_ID: u16 = 28;
const TCP_ACCEPT_IPV4_EVENT_ID: u16 = 15;
const TCP_ACCEPT_IPV6_EVENT_ID: u16 = 31;
const UDP_SEND_IPV4_EVENT_ID: u16 = 10;
const UDP_RECEIVE_IPV4_EVENT_ID: u16 = 11;
const UDP_SEND_IPV6_EVENT_ID: u16 = 26;
const UDP_RECEIVE_IPV6_EVENT_ID: u16 = 27;
const SOURCE: &str = "ETW";
const PROVIDER_NAME: &str = "Microsoft-Windows-Kernel-Process";
const FILE_PROVIDER_NAME: &str = "Windows-Kernel-FileIo";
const NETWORK_PROVIDER_NAME: &str = "Windows-Kernel-TcpIp";
const UDP_PROVIDER_NAME: &str = "Windows-Kernel-UdpIp";
const EVENT_QUEUE_CAPACITY: usize = 4096;

static HOST: std::sync::OnceLock<Host> = std::sync::OnceLock::new();

struct GatewayClient {
    client: Client,
    endpoint: String,
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let signal_state = running.clone();
    ctrlc::set_handler(move || signal_state.store(false, Ordering::SeqCst))?;
    run_with_shutdown(running)
}

pub fn run_with_shutdown(running: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
    run_with_ready_callback(running, || {})
}

pub fn run_with_ready_callback<F>(
    running: Arc<AtomicBool>,
    on_ready: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnOnce(),
{
    HOST.set(host_identity())
        .map_err(|_| "Windows sensor host identity was initialized more than once")?;
    let gateway = GatewayClient {
        client: gateway_client()?,
        endpoint: env::var("SF_GATEWAY_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080/v1/events".into()),
    };
    let (event_sender, event_receiver) = mpsc::sync_channel(EVENT_QUEUE_CAPACITY);
    let publisher = thread::Builder::new()
        .name("sentinelforge-gateway-publisher".into())
        .spawn(move || publish_events(event_receiver, gateway))?;

    let file_event_sender = event_sender.clone();
    let file_paths = Arc::new(Mutex::new(HashMap::<u32, String>::new()));
    let callback_file_paths = file_paths.clone();
    let process_paths = Arc::new(Mutex::new(HashMap::<u32, String>::new()));
    let file_process_paths = process_paths.clone();
    let file_provider = Provider::kernel(&FILE_IO_PROVIDER)
        .add_callback(move |record, schema_locator| {
            file_callback(
                record,
                schema_locator,
                &file_event_sender,
                &callback_file_paths,
                &file_process_paths,
            )
        })
        .build();
    let network_event_sender = event_sender.clone();
    let network_process_paths = process_paths.clone();
    let network_provider = Provider::kernel(&TCP_IP_PROVIDER)
        .add_callback(move |record, schema_locator| {
            network_callback(
                record,
                schema_locator,
                &network_event_sender,
                &network_process_paths,
                "tcp",
            )
        })
        .build();
    let udp_ip_provider =
        KernelProvider::new("bf3a50c5-a9c9-4988-a005-2df0b7c80f80".into(), 0x0001_0000);
    let udp_event_sender = event_sender.clone();
    let udp_process_paths = process_paths.clone();
    let udp_provider = Provider::kernel(&udp_ip_provider)
        .add_callback(move |record, schema_locator| {
            network_callback(
                record,
                schema_locator,
                &udp_event_sender,
                &udp_process_paths,
                "udp",
            )
        })
        .build();
    let mut file_trace = match KernelTrace::new()
        .named(String::from("SentinelForgeWindowsKernel"))
        .enable(file_provider)
        .enable(network_provider)
        .enable(udp_provider)
        .start_and_process()
    {
        Ok(trace) => Some(trace),
        Err(error) => {
            eprintln!(
                "could not start Windows file/network ETW trace; continuing with process telemetry: {error:?}"
            );
            None
        }
    };

    // Kernel process starts need the Process keyword and an elevated trace session.
    let process_event_sender = event_sender.clone();
    let process_event_paths = process_paths.clone();
    let provider = Provider::by_guid(KERNEL_PROCESS_PROVIDER)
        .any(PROCESS_KEYWORD)
        .add_callback(move |record, schema_locator| {
            process_callback(
                record,
                schema_locator,
                &process_event_sender,
                &process_event_paths,
            )
        })
        .build();
    let trace = UserTrace::new()
        .named(String::from("SentinelForgeWindowsProcess"))
        .enable(provider)
        .start_and_process()
        .map_err(|error| format!("start Windows process ETW trace: {error:?}"))?;

    eprintln!("SentinelForge Windows ETW process sensor is running");
    let authentication_listener = crate::windows_auth::start_listener(
        event_sender.clone(),
        HOST.get().expect("host identity was initialized").clone(),
        running.clone(),
    );
    on_ready();
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(250));
    }
    trace
        .stop()
        .map_err(|error| format!("stop Windows process ETW trace: {error:?}"))?;
    if let Some(trace) = file_trace.take() {
        trace
            .stop()
            .map_err(|error| format!("stop Windows file ETW trace: {error:?}"))?;
    }
    authentication_listener
        .join()
        .map_err(|_| io::Error::other("Windows authentication listener panicked"))?;
    drop(event_sender);
    publisher
        .join()
        .map_err(|_| io::Error::other("gateway event publisher thread panicked"))?;
    Ok(())
}

fn gateway_client() -> Result<Client, Box<dyn Error>> {
    let required =
        env::var("SF_MTLS_REQUIRED").is_ok_and(|value| value.eq_ignore_ascii_case("true"));
    let endpoint =
        env::var("SF_GATEWAY_URL").unwrap_or_else(|_| "http://127.0.0.1:8080/v1/events".into());
    let ca_file = env::var_os("SF_GATEWAY_CA_FILE").map(PathBuf::from);
    let cert_file = env::var_os("SF_GATEWAY_CERT_FILE").map(PathBuf::from);
    let key_file = env::var_os("SF_GATEWAY_KEY_FILE").map(PathBuf::from);
    if required && (ca_file.is_none() || cert_file.is_none() || key_file.is_none()) {
        return Err("SF_MTLS_REQUIRED needs SF_GATEWAY_CA_FILE, SF_GATEWAY_CERT_FILE, and SF_GATEWAY_KEY_FILE".into());
    }
    if required && !endpoint.starts_with("https://") {
        return Err("SF_MTLS_REQUIRED requires an https:// SF_GATEWAY_URL".into());
    }
    let mut builder = Client::builder().timeout(Duration::from_secs(5));
    if let Some(path) = ca_file {
        builder = builder.add_root_certificate(Certificate::from_pem(&std::fs::read(path)?)?);
    }
    match (cert_file, key_file) {
        (Some(cert), Some(key)) => {
            let mut identity = std::fs::read(cert)?;
            identity.extend_from_slice(b"\n");
            identity.extend_from_slice(&std::fs::read(key)?);
            builder = builder.identity(Identity::from_pem(&identity)?);
        }
        (None, None) => {}
        _ => return Err("both SF_GATEWAY_CERT_FILE and SF_GATEWAY_KEY_FILE are required".into()),
    }
    Ok(builder.build()?)
}

fn process_callback(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    event_sender: &SyncSender<String>,
    process_paths: &Arc<Mutex<HashMap<u32, String>>>,
) {
    if record.event_id() != PROCESS_START_EVENT_ID {
        return;
    }
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let Ok(pid) = parser
        .try_parse::<u32>("ProcessID")
        .or_else(|_| parser.try_parse::<u32>("ProcessId"))
    else {
        return;
    };
    let Ok(path) = parser
        .try_parse::<String>("ImageName")
        .or_else(|_| parser.try_parse::<String>("ImageFileName"))
    else {
        return;
    };
    if let Ok(mut paths) = process_paths.lock() {
        if !paths.contains_key(&pid) && paths.len() >= PROCESS_PATH_CAPACITY {
            if let Some(oldest_pid) = paths.keys().next().copied() {
                paths.remove(&oldest_pid);
            }
        }
        paths.insert(pid, path.clone());
    }

    let command_line = parser
        .try_parse::<String>("CommandLine")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| path.clone());
    let parent = parser
        .try_parse::<u32>("ParentProcessID")
        .or_else(|_| parser.try_parse::<u32>("ParentId"))
        .ok()
        .filter(|parent_pid| *parent_pid != 0)
        .map(|pid| ProcessReference {
            pid: u64::from(pid),
            name: String::new(),
            path: String::new(),
        });

    let Some(timestamp) = wall_clock_timestamp() else {
        return;
    };
    let mut random_bytes = [0_u8; 16];
    if getrandom::fill(&mut random_bytes).is_err() {
        return;
    }
    let Some(host) = HOST.get() else { return };
    let event = ProcessStart::from_observation(
        uuid_v4_from_random(random_bytes),
        timestamp,
        host.clone(),
        pid,
        None,
        &path,
        &command_line,
        parent,
        SOURCE,
        PROVIDER_NAME,
    );
    match event.to_json() {
        Ok(json) => match event_sender.try_send(json) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => eprintln!(
                "Windows telemetry queue is full; dropping process event {}",
                event.event_id
            ),
            Err(TrySendError::Disconnected(_)) => eprintln!(
                "gateway publisher stopped; dropping process event {}",
                event.event_id
            ),
        },
        Err(error) => eprintln!("could not serialize ETW process event: {error}"),
    }
}

fn file_callback(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    event_sender: &SyncSender<String>,
    file_paths: &Arc<Mutex<HashMap<u32, String>>>,
    process_paths: &Arc<Mutex<HashMap<u32, String>>>,
) {
    let event_id = record.event_id();
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    if event_id == FILE_CLOSE_EVENT_ID {
        if let Ok(object) = parser.try_parse::<u32>("FileObject")
            && let Ok(mut paths) = file_paths.lock()
        {
            paths.remove(&object);
        }
        return;
    }
    let (action, path, bytes_written) = match event_id {
        FILE_CREATE_EVENT_ID | FILE_DELETE_EVENT_ID => {
            let action = if event_id == FILE_CREATE_EVENT_ID {
                "create"
            } else {
                "delete"
            };
            let Ok(path) = parser.try_parse::<String>("FileName") else {
                return;
            };
            if event_id == FILE_CREATE_EVENT_ID
                && let Ok(object) = parser.try_parse::<u32>("FileObject")
                && let Ok(mut paths) = file_paths.lock()
            {
                if paths.len() >= FILE_OBJECT_PATH_CAPACITY {
                    if let Some(oldest_object) = paths.keys().next().copied() {
                        paths.remove(&oldest_object);
                    }
                }
                paths.insert(object, path.clone());
            }
            (action, path, None)
        }
        FILE_WRITE_EVENT_ID => {
            let (Ok(object), Ok(size)) = (
                parser.try_parse::<u32>("FileObject"),
                parser.try_parse::<u32>("IoSize"),
            ) else {
                return;
            };
            let Ok(paths) = file_paths.lock() else { return };
            let Some(path) = paths.get(&object).cloned() else {
                return;
            };
            ("write", path, (size > 0).then_some(u64::from(size)))
        }
        _ => return,
    };
    if path.trim().is_empty() {
        return;
    }
    let Some(timestamp) = wall_clock_timestamp() else {
        return;
    };
    let mut random_bytes = [0_u8; 16];
    if getrandom::fill(&mut random_bytes).is_err() {
        return;
    }
    let Some(host) = HOST.get() else { return };
    let event = FileEvent {
        event_id: uuid_v4_from_random(random_bytes),
        correlation_id: None,
        timestamp,
        host: host.clone(),
        category: "file",
        action: action.into(),
        user: None,
        file: FileDetails {
            path,
            file_type: String::new(),
            hash: None,
            size_bytes: None,
            flags: 0,
            bytes_written,
            process: process_reference(record.process_id(), process_paths),
        },
        raw: RawSource {
            source: "ETW".into(),
            provider: FILE_PROVIDER_NAME.into(),
        },
        schema_version: SCHEMA_VERSION.into(),
    };
    match event.to_json() {
        Ok(json) => match event_sender.try_send(json) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => eprintln!(
                "Windows telemetry queue is full; dropping file {action} event {}",
                event.event_id
            ),
            Err(TrySendError::Disconnected(_)) => eprintln!(
                "gateway publisher stopped; dropping file {action} event {}",
                event.event_id
            ),
        },
        Err(error) => eprintln!("could not serialize ETW file event: {error}"),
    }
}

fn network_callback(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    event_sender: &SyncSender<String>,
    process_paths: &Arc<Mutex<HashMap<u32, String>>>,
    protocol: &str,
) {
    let (action, direction, provider) = match (protocol, record.event_id()) {
        ("tcp", TCP_CONNECT_IPV4_EVENT_ID | TCP_CONNECT_IPV6_EVENT_ID) => {
            ("connect", "outbound", NETWORK_PROVIDER_NAME)
        }
        ("tcp", TCP_ACCEPT_IPV4_EVENT_ID | TCP_ACCEPT_IPV6_EVENT_ID) => {
            ("accept", "inbound", NETWORK_PROVIDER_NAME)
        }
        ("udp", UDP_SEND_IPV4_EVENT_ID | UDP_SEND_IPV6_EVENT_ID) => {
            ("send", "outbound", UDP_PROVIDER_NAME)
        }
        ("udp", UDP_RECEIVE_IPV4_EVENT_ID | UDP_RECEIVE_IPV6_EVENT_ID) => {
            ("receive", "inbound", UDP_PROVIDER_NAME)
        }
        _ => return,
    };
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let (Ok(local_address), Ok(remote_address), Ok(local_port), Ok(remote_port)) = (
        parser.try_parse::<IpAddr>("saddr"),
        parser.try_parse::<IpAddr>("daddr"),
        parser.try_parse::<u16>("sport"),
        parser.try_parse::<u16>("dport"),
    ) else {
        return;
    };
    let process_id = if protocol == "udp" {
        parser
            .try_parse::<u32>("context")
            .unwrap_or_else(|_| record.process_id())
    } else {
        parser
            .try_parse::<u32>("PID")
            .unwrap_or_else(|_| record.process_id())
    };
    let (local_address, remote_address, local_port, remote_port) = if direction == "inbound" {
        (remote_address, local_address, remote_port, local_port)
    } else {
        (local_address, remote_address, local_port, remote_port)
    };
    let Some(timestamp) = wall_clock_timestamp() else {
        return;
    };
    let mut random_bytes = [0_u8; 16];
    if getrandom::fill(&mut random_bytes).is_err() {
        return;
    }
    let Some(host) = HOST.get() else { return };
    let event = NetworkConnect {
        event_id: uuid_v4_from_random(random_bytes),
        timestamp,
        host: host.clone(),
        category: "network",
        action: action.into(),
        user: None,
        network: NetworkDetails {
            protocol: protocol.into(),
            direction: direction.into(),
            local_address: local_address.to_string(),
            local_port: u32::from(local_port),
            remote_address: remote_address.to_string(),
            remote_port: u32::from(remote_port),
            process: process_reference(process_id, process_paths),
        },
        raw: RawSource {
            source: "ETW".into(),
            provider: provider.into(),
        },
        schema_version: SCHEMA_VERSION.into(),
    };
    match event.to_json() {
        Ok(json) => match event_sender.try_send(json) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => eprintln!(
                "Windows telemetry queue is full; dropping TCP connection event {}",
                event.event_id
            ),
            Err(TrySendError::Disconnected(_)) => eprintln!(
                "gateway publisher stopped; dropping TCP connection event {}",
                event.event_id
            ),
        },
        Err(error) => eprintln!("could not serialize ETW network event: {error}"),
    }
}

fn process_reference(
    process_id: u32,
    process_paths: &Arc<Mutex<HashMap<u32, String>>>,
) -> Option<ProcessReference> {
    if process_id == 0 {
        return None;
    }
    let path = process_paths.lock().ok()?.get(&process_id)?.clone();
    let name = path
        .rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())?
        .to_owned();
    Some(ProcessReference {
        pid: u64::from(process_id),
        name,
        path,
    })
}

fn publish_events(receiver: Receiver<String>, gateway: GatewayClient) {
    for event in receiver {
        let event_id = serde_json::from_str::<serde_json::Value>(&event)
            .ok()
            .and_then(|value| {
                value
                    .get("event_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "unknown".into());
        if let Err(error) = gateway.publish(&event) {
            eprintln!("could not send telemetry event {event_id} to gateway: {error}");
        }
    }
}

impl GatewayClient {
    fn publish(&self, event: &str) -> Result<(), reqwest::Error> {
        self.client
            .post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(event.to_owned())
            .send()?
            .error_for_status()?;
        Ok(())
    }
}

fn wall_clock_timestamp() -> Option<String> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    format_timestamp(elapsed.as_secs(), elapsed.subsec_nanos())
}

fn host_identity() -> Host {
    let host_id = env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown-windows-host".into());
    let os_version = Command::new("cmd.exe")
        .args(["/C", "ver"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "unknown".into());
    Host {
        host_id,
        os: "windows".into(),
        os_version,
        agent_version: env!("CARGO_PKG_VERSION").into(),
    }
}
