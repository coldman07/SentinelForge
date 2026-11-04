use async_nats::jetstream::{
    consumer::{pull, AckPolicy},
    stream::{Config as StreamConfig, RetentionPolicy, StorageType},
    AckKind,
};
use futures_util::StreamExt;
use sentinelforge_detection::{DetectionMatch, SigmaEngine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    env,
    error::Error,
    fs, io,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

const EVENT_STREAM: &str = "SENTINELFORGE_EVENTS";
const EVENT_SUBJECT: &str = "sentinelforge.events.v1.>";
const DETECTION_CONSUMER: &str = "SENTINELFORGE_DETECTION";
const ALERT_STREAM: &str = "SENTINELFORGE_ALERTS";
const ALERT_STREAM_SUBJECT: &str = "sentinelforge.alerts.v1.>";
const ALERT_SUBJECT: &str = "sentinelforge.alerts.v1.match";

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Serialize)]
struct DetectionAlert {
    event_id: String,
    event: Value,
    matches: Vec<DetectionMatch>,
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    if let Some(mode) = env::args().nth(1) {
        match mode.as_str() {
            "--validate-rule" => return validate_rule_stdin(),
            "--replay-rule" => return replay_rule_stdin(),
            _ => {}
        }
    }
    let nats_url = env::var("SF_NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into());
    let rules_dir = env::var_os("SF_RULES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("rules/sigma"));
    let engine = load_rules(&rules_dir)?;

    let client = if env::var("SF_MTLS_REQUIRED").is_ok_and(|value| value == "true") {
        use std::{io, path::PathBuf};
        let ca = env::var_os("SF_NATS_CA_FILE")
            .map(PathBuf::from)
            .ok_or_else(|| {
                io::Error::other("SF_NATS_CA_FILE is required when SF_MTLS_REQUIRED=true")
            })?;
        let cert = env::var_os("SF_NATS_CERT_FILE")
            .map(PathBuf::from)
            .ok_or_else(|| {
                io::Error::other("SF_NATS_CERT_FILE is required when SF_MTLS_REQUIRED=true")
            })?;
        let key = env::var_os("SF_NATS_KEY_FILE")
            .map(PathBuf::from)
            .ok_or_else(|| {
                io::Error::other("SF_NATS_KEY_FILE is required when SF_MTLS_REQUIRED=true")
            })?;
        let tls_url = nats_url
            .strip_prefix("nats://")
            .map(|host| format!("tls://{host}"))
            .unwrap_or(nats_url);
        if !tls_url.starts_with("tls://") {
            return Err("mutual TLS requires a tls:// NATS URL".into());
        }
        async_nats::ConnectOptions::new()
            .require_tls(true)
            .add_root_certificates(ca)
            .add_client_certificate(cert, key)
            .connect(tls_url)
            .await?
    } else {
        async_nats::connect(&nats_url).await?
    };
    let jetstream = async_nats::jetstream::new(client);
    let event_stream = jetstream.get_stream(EVENT_STREAM).await?;
    let consumer = event_stream
        .get_or_create_consumer(
            DETECTION_CONSUMER,
            pull::Config {
                durable_name: Some(DETECTION_CONSUMER.into()),
                filter_subject: EVENT_SUBJECT.into(),
                ack_policy: AckPolicy::Explicit,
                ack_wait: Duration::from_secs(60),
                max_deliver: -1,
                max_ack_pending: 64,
                ..Default::default()
            },
        )
        .await?;
    jetstream
        .get_or_create_stream(StreamConfig {
            name: ALERT_STREAM.into(),
            subjects: vec![ALERT_STREAM_SUBJECT.into()],
            retention: RetentionPolicy::Limits,
            storage: StorageType::File,
            ..Default::default()
        })
        .await?;

    eprintln!(
        "detection worker loaded {} Sigma rules; consuming {}",
        engine.rule_count(),
        EVENT_STREAM
    );
    let mut messages = consumer.messages().await?;
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            result = &mut shutdown => {
                result?;
                break;
            }
            next = messages.next() => {
                let Some(message) = next else { break };
                let message = message?;
                match process_event(&jetstream, &engine, &message.payload).await {
                    Ok(true) => message.ack().await?,
                    Ok(false) => {
                        eprintln!("discarding malformed event from the detection stream");
                        message.ack_with(AckKind::Term).await?;
                    }
                    Err(error) => {
                        eprintln!("detection publish failed; event will be retried: {error}");
                        message.ack_with(AckKind::Nak(Some(Duration::from_secs(5)))).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_rule_stdin() -> Result<(), AnyError> {
    let mut source = String::new();
    io::stdin().read_to_string(&mut source)?;
    let rule = sentinelforge_detection::SigmaRule::from_yaml(&source)?;
    println!(
        "{}",
        json!({
            "valid": true,
            "title": rule.title,
            "rule_id": rule.id,
            "level": rule.level,
            "tags": rule.tags,
        })
    );
    Ok(())
}

#[derive(Deserialize)]
struct ReplayInput {
    rule_yaml: String,
    positive_events: Vec<Value>,
    negative_events: Vec<Value>,
}

fn replay_rule_stdin() -> Result<(), AnyError> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let input: ReplayInput = serde_json::from_str(&input)?;
    let rule = sentinelforge_detection::SigmaRule::from_yaml(&input.rule_yaml)?;
    let positive_matched = input
        .positive_events
        .iter()
        .filter(|event| rule.matches(event))
        .count();
    let negative_matched = input
        .negative_events
        .iter()
        .filter(|event| rule.matches(event))
        .count();
    let passed = !input.positive_events.is_empty()
        && !input.negative_events.is_empty()
        && positive_matched > 0
        && negative_matched == 0;
    println!(
        "{}",
        json!({
            "passed": passed,
            "positive_total": input.positive_events.len(),
            "positive_matched": positive_matched,
            "negative_total": input.negative_events.len(),
            "negative_matched": negative_matched,
        })
    );
    Ok(())
}

async fn process_event(
    jetstream: &async_nats::jetstream::Context,
    engine: &SigmaEngine,
    payload: &[u8],
) -> Result<bool, AnyError> {
    let event: Value = match serde_json::from_slice(payload) {
        Ok(event) => event,
        Err(error) => {
            eprintln!("invalid event JSON: {error}");
            return Ok(false);
        }
    };
    let Some(event_id) = event
        .get("event_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        eprintln!("event has no string event_id");
        return Ok(false);
    };

    let matches = engine.evaluate(&event);
    if matches.is_empty() {
        return Ok(true);
    }
    let alert = DetectionAlert {
        event_id: event_id.clone(),
        event,
        matches,
    };
    let mut headers = async_nats::HeaderMap::new();
    headers.insert("Nats-Msg-Id", event_id.as_str());
    let payload = serde_json::to_vec(&alert)?;
    jetstream
        .publish_with_headers(ALERT_SUBJECT, headers, payload.into())
        .await?
        .await?;
    Ok(true)
}

fn load_rules(directory: &Path) -> Result<SigmaEngine, AnyError> {
    let mut files = Vec::new();
    collect_rule_files(directory, &mut files)?;
    files.sort();
    if files.is_empty() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no .yml or .yaml Sigma rules found in {}",
                directory.display()
            ),
        )));
    }

    let mut engine = SigmaEngine::default();
    for path in files {
        let source = fs::read_to_string(&path)?;
        engine.add_rule_yaml(&source).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {error}", path.display()),
            )
        })?;
    }
    Ok(engine)
}

fn collect_rule_files(directory: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_rule_files(&path, files)?;
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    matches!(extension.to_ascii_lowercase().as_str(), "yml" | "yaml")
                })
        {
            files.push(path);
        }
    }
    Ok(())
}
