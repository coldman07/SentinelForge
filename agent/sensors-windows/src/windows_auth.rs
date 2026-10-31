use sentinelforge_agent_core::{Host, SCHEMA_VERSION, format_timestamp, uuid_v4_from_random};
use std::{
    ffi::c_void,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use windows::{
    Win32::{
        Foundation::HANDLE,
        System::EventLog::{
            EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION, EvtClose, EvtRender, EvtRenderEventXml,
            EvtSubscribe, EvtSubscribeActionDeliver, EvtSubscribeToFutureEvents,
        },
    },
    core::PCWSTR,
};

const SECURITY_CHANNEL: &str = "Security";
const LOGON_QUERY: &str = "*[System[(EventID=4624 or EventID=4625)]]";
const SECURITY_PROVIDER: &str = "Microsoft-Windows-Security-Auditing";

struct AuthContext {
    event_sender: SyncSender<String>,
    host: Host,
}

pub fn start_listener(
    event_sender: SyncSender<String>,
    host: Host,
    running: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("sentinelforge-windows-authentication".into())
        .spawn(move || {
            if let Err(error) = listen(event_sender, host, running) {
                eprintln!("Windows Security event subscription unavailable: {error}");
            }
        })
        .expect("could not start Windows authentication listener")
}

fn listen(
    event_sender: SyncSender<String>,
    host: Host,
    running: Arc<AtomicBool>,
) -> windows::core::Result<()> {
    let context = AuthContext { event_sender, host };
    let channel = to_wide(SECURITY_CHANNEL);
    let query = to_wide(LOGON_QUERY);
    let subscription = unsafe {
        EvtSubscribe(
            EVT_HANDLE::default(),
            HANDLE::default(),
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            EVT_HANDLE::default(),
            Some((&context as *const AuthContext).cast::<c_void>()),
            Some(authentication_callback),
            EvtSubscribeToFutureEvents.0,
        )?
    };

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(250));
    }
    unsafe { EvtClose(subscription)? };
    Ok(())
}

unsafe extern "system" fn authentication_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    user_context: *const c_void,
    event: EVT_HANDLE,
) -> u32 {
    if action != EvtSubscribeActionDeliver {
        eprintln!(
            "Windows Security event subscription reported status {}",
            event.0
        );
        return 0;
    }
    let Some(context) = (unsafe { user_context.cast::<AuthContext>().as_ref() }) else {
        unsafe {
            let _ = EvtClose(event);
        }
        return 0;
    };
    match render_xml(event).and_then(|xml| event_json(&xml, &context.host)) {
        Some(json) => match context.event_sender.try_send(json) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                eprintln!("Windows telemetry queue is full; dropping authentication event")
            }
            Err(TrySendError::Disconnected(_)) => {
                eprintln!("gateway publisher stopped; dropping authentication event")
            }
        },
        None => eprintln!("could not render Windows authentication event"),
    }
    unsafe {
        let _ = EvtClose(event);
    }
    0
}

fn render_xml(event: EVT_HANDLE) -> Option<String> {
    let mut bytes_used = 0_u32;
    let mut property_count = 0_u32;
    unsafe {
        let _ = EvtRender(
            EVT_HANDLE::default(),
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut bytes_used,
            &mut property_count,
        );
    }
    if bytes_used == 0 {
        return None;
    }
    let mut buffer = vec![0_u16; (bytes_used as usize).div_ceil(2)];
    unsafe {
        EvtRender(
            EVT_HANDLE::default(),
            event,
            EvtRenderEventXml.0,
            bytes_used,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            &mut bytes_used,
            &mut property_count,
        )
        .ok()?;
        let end = buffer
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..end]))
    }
}

fn event_json(xml: &str, host: &Host) -> Option<String> {
    let event_id = xml_tag(xml, "EventID")?.parse::<u16>().ok()?;
    if event_id != 4624 && event_id != 4625 {
        return None;
    }
    let user_name = xml_field(xml, "TargetUserName").unwrap_or_default();
    let domain = xml_field(xml, "TargetDomainName").unwrap_or_default();
    let target = match (domain.is_empty(), user_name.is_empty()) {
        (false, false) => format!("{domain}\\{user_name}"),
        (true, false) => user_name,
        (false, true) => domain,
        (true, true) => "unknown".into(),
    };
    let source_address = xml_field(xml, "IpAddress")
        .filter(|address| address != "-")
        .unwrap_or_default();
    let method = xml_field(xml, "LogonType")
        .map(|value| logon_method(&value).to_owned())
        .unwrap_or_else(|| "unknown".into());
    let outcome = if event_id == 4624 {
        "success"
    } else {
        "failure"
    };
    let action = if event_id == 4624 {
        "logon"
    } else {
        "logon_failed"
    };
    let timestamp = xml_attribute(xml, "TimeCreated", "SystemTime").unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| format_timestamp(time.as_secs(), time.subsec_nanos()))
            .unwrap_or_default()
    });
    if timestamp.is_empty() {
        return None;
    }
    let mut random_bytes = [0_u8; 16];
    getrandom::fill(&mut random_bytes).ok()?;
    serde_json::to_string(&serde_json::json!({
        "event_id": uuid_v4_from_random(random_bytes),
        "timestamp": timestamp,
        "host": host,
        "category": "authentication",
        "action": action,
        "authentication": {
            "method": method,
            "outcome": outcome,
            "source_address": source_address,
            "target": target,
        },
        "raw": {"source": "ETW", "provider": SECURITY_PROVIDER},
        "schema_version": SCHEMA_VERSION,
    }))
    .ok()
}

fn xml_field(xml: &str, name: &str) -> Option<String> {
    let marker = format!("Name=\"{name}\">");
    let start = xml.find(&marker)? + marker.len();
    let end = xml[start..].find("</Data>")? + start;
    let value = xml[start..end]
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'");
    (value != "-").then_some(value)
}

fn xml_tag(xml: &str, name: &str) -> Option<String> {
    let opening = format!("<{name}>");
    let closing = format!("</{name}>");
    let start = xml.find(&opening)? + opening.len();
    let end = xml[start..].find(&closing)? + start;
    Some(xml[start..end].trim().to_owned())
}

fn xml_attribute(xml: &str, element: &str, attribute: &str) -> Option<String> {
    let opening = format!("<{element} ");
    let element_start = xml.find(&opening)?;
    let element_end = xml[element_start..].find('>')? + element_start;
    let attributes = &xml[element_start..element_end];
    let marker = format!("{attribute}=\"");
    let start = attributes.find(&marker)? + marker.len();
    let end = attributes[start..].find('"')? + start;
    Some(attributes[start..end].to_owned())
}

fn logon_method(logon_type: &str) -> &str {
    match logon_type {
        "2" => "interactive",
        "3" => "network",
        "4" => "batch",
        "5" => "service",
        "7" => "unlock",
        "8" => "network_cleartext",
        "9" => "new_credentials",
        "10" => "remote_interactive",
        "11" => "cached_interactive",
        _ => "other",
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
