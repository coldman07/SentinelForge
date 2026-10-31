use ferrisetw::{
    EventRecord, parser::Parser, provider::Provider, schema_locator::SchemaLocator,
    trace::UserTrace,
};
use sentinelforge_agent_core::{
    Host, ProcessReference, ProcessStart, format_timestamp, uuid_v4_from_random,
};
use std::{
    env,
    error::Error,
    process::Command,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const KERNEL_PROCESS_PROVIDER: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const PROCESS_START_EVENT_ID: u16 = 1;
const SOURCE: &str = "ETW";
const PROVIDER_NAME: &str = "Microsoft-Windows-Kernel-Process";

static HOST: OnceLock<Host> = OnceLock::new();

pub fn run() -> Result<(), Box<dyn Error>> {
    HOST.set(host_identity())
        .map_err(|_| "Windows sensor host identity was initialized more than once")?;

    let provider = Provider::by_guid(KERNEL_PROCESS_PROVIDER)
        .any(0x10)
        .add_callback(process_callback)
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
    Ok(())
}

fn process_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
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
        .filter(|command_line| !command_line.trim().is_empty())
        .unwrap_or_else(|| path.clone());
    let parent_pid = parser
        .try_parse::<u32>("ParentProcessID")
        .or_else(|_| parser.try_parse::<u32>("ParentId"))
        .ok()
        .filter(|parent_pid| *parent_pid != 0);
    let parent = parent_pid.map(|pid| ProcessReference {
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
        Ok(json) => println!("{json}"),
        Err(error) => eprintln!("could not serialize ETW process event: {error}"),
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
