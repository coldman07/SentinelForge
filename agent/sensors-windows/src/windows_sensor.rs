use ferrisetw::{
    EventRecord,
    parser::Parser,
    provider::{
        Provider,
        kernel_providers::{FILE_IO_PROVIDER, TCP_IP_PROVIDER},
    },
    schema_locator::SchemaLocator,
    trace::{KernelTrace, UserTrace},
};
use reqwest::blocking::Client;
use sentinelforge_agent_core::{
    FileDetails, FileEvent, Host, NetworkConnect, NetworkDetails, ProcessReference, ProcessStart,
    RawSource, SCHEMA_VERSION, format_timestamp, uuid_v4_from_random,
};
use std::{
    env,
    error::Error,
    io,
    net::IpAddr,
    process::Command,
    sync::{
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
const TCP_CONNECT_IPV4_EVENT_ID: u16 = 12;
const TCP_CONNECT_IPV6_EVENT_ID: u16 = 28;
const SOURCE: &str = "ETW";
const PROVIDER_NAME: &str = "Microsoft-Windows-Kernel-Process";
const FILE_PROVIDER_NAME: &str = "Windows-Kernel-FileIo";
const NETWORK_PROVIDER_NAME: &str = "Windows-Kernel-TcpIp";
const EVENT_QUEUE_CAPACITY: usize = 4096;

static HOST: std::sync::OnceLock<Host> = std::sync::OnceLock::new();

struct GatewayClient {
    client: Client,
    endpoint: String,
}

pub fn run() -> Result<(), Box<dyn Error>> {
    HOST.set(host_identity())
        .map_err(|_| "Windows sensor host identity was initialized more than once")?;
    let gateway = GatewayClient {
        client: Client::builder().timeout(Duration::from_secs(5)).build()?,
        endpoint: env::var("SF_GATEWAY_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080/v1/events".into()),
    };
    let (event_sender, event_receiver) = mpsc::sync_channel(EVENT_QUEUE_CAPACITY);
    let publisher = thread::Builder::new()
        .name("sentinelforge-gateway-publisher".into())
        .spawn(move || publish_events(event_receiver, gateway))?;

    let file_event_sender = event_sender.clone();
    let file_provider = Provider::kernel(&FILE_IO_PROVIDER)
        .add_callback(move |record, schema_locator| {
            file_callback(record, schema_locator, &file_event_sender)
        })
        .build();
    let network_event_sender = event_sender.clone();
    let network_provider = Provider::kernel(&TCP_IP_PROVIDER)
        .add_callback(move |record, schema_locator| {
            network_callback(record, schema_locator, &network_event_sender)
        })
        .build();
    let mut file_trace = match KernelTrace::new()
        .named(String::from("SentinelForgeWindowsKernel"))
        .enable(file_provider)
        .enable(network_provider)
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
    let provider = Provider::by_guid(KERNEL_PROCESS_PROVIDER)
        .any(PROCESS_KEYWORD)
        .add_callback(move |record, schema_locator| {
            process_callback(record, schema_locator, &process_event_sender)
        })
        .build();
    let trace = UserTrace::new()
        .named(String::from("SentinelForgeWindowsProcess"))
        .enable(provider)
        .start_and_process()
        .map_err(|error| format!("start Windows process ETW trace: {error:?}"))?;

    eprintln!("SentinelForge Windows ETW process sensor is running");
    let running = std::sync::Arc::new(AtomicBool::new(true));
    let signal_state = running.clone();
    ctrlc::set_handler(move || signal_state.store(false, Ordering::SeqCst))?;
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
    drop(event_sender);
    publisher
        .join()
        .map_err(|_| io::Error::other("gateway event publisher thread panicked"))?;
    Ok(())
}

fn process_callback(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    event_sender: &SyncSender<String>,
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
) {
    let action = match record.event_id() {
        FILE_CREATE_EVENT_ID => "create",
        FILE_DELETE_EVENT_ID => "delete",
        _ => return,
    };
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let Ok(path) = parser.try_parse::<String>("FileName") else {
        return;
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
            bytes_written: None,
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
) {
    let protocol = match record.event_id() {
        TCP_CONNECT_IPV4_EVENT_ID | TCP_CONNECT_IPV6_EVENT_ID => "tcp",
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
        action: "connect".into(),
        user: None,
        network: NetworkDetails {
            protocol: protocol.into(),
            direction: "outbound".into(),
            local_address: local_address.to_string(),
            local_port: u32::from(local_port),
            remote_address: remote_address.to_string(),
            remote_port: u32::from(remote_port),
        },
        raw: RawSource {
            source: "ETW".into(),
            provider: NETWORK_PROVIDER_NAME.into(),
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
            eprintln!("could not send process event {event_id} to gateway: {error}");
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
