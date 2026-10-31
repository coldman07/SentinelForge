//! Small, deterministic Sigma evaluator for SentinelForge's normalized JSON events.
//!
//! This crate intentionally implements a documented subset of Sigma: selection
//! maps, scalar/list values, common string modifiers, and boolean conditions
//! over named selections, including `of` quantifiers. Unsupported modifiers
//! and condition syntax are rejected during parsing instead of silently
//! weakening a rule.

use regex::Regex;
use serde::Serialize;
use serde_yaml::{Mapping, Value as YamlValue};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("invalid Sigma YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Sigma rule must be a YAML mapping")]
    RootNotMapping,
    #[error("Sigma rule is missing a string `title`")]
    MissingTitle,
    #[error("Sigma rule is missing a `detection` mapping")]
    MissingDetection,
    #[error("Sigma detection is missing a string `condition`")]
    MissingCondition,
    #[error("invalid Sigma condition: {0}")]
    InvalidCondition(String),
    #[error("invalid selection `{selection}`: {reason}")]
    InvalidSelection { selection: String, reason: String },
    #[error("unsupported Sigma modifier `{0}`")]
    UnsupportedModifier(String),
    #[error("invalid Sigma rule metadata `{field}`: {reason}")]
    InvalidMetadata { field: String, reason: String },
    #[error("invalid Sigma logsource: {0}")]
    InvalidLogSource(String),
}

#[derive(Clone, Debug)]
pub struct SigmaRule {
    pub title: String,
    pub id: Option<String>,
    pub description: Option<String>,
    pub level: Option<String>,
    pub tags: Vec<String>,
    logsource: LogSource,
    selections: BTreeMap<String, Vec<FieldMatcher>>,
    condition: Condition,
}

#[derive(Clone, Debug, Default)]
struct LogSource {
    product: Option<String>,
    category: Option<String>,
    service: Option<String>,
}

/// Metadata for a rule that matched an event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DetectionMatch {
    pub rule_id: Option<String>,
    pub title: String,
    pub level: Option<String>,
    pub tags: Vec<String>,
}

/// An ordered collection of Sigma rules evaluated against each event.
#[derive(Clone, Debug, Default)]
pub struct SigmaEngine {
    rules: Vec<SigmaRule>,
}

#[derive(Clone, Debug)]
struct FieldMatcher {
    path: Vec<String>,
    modifier: Modifier,
    all_values: bool,
    expected: Vec<serde_json::Value>,
}

#[derive(Clone, Copy, Debug)]
enum Modifier {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    Exists,
}

#[derive(Clone, Debug)]
enum Condition {
    Selection(String),
    Quantified {
        minimum: usize,
        all: bool,
        selector: String,
    },
    Not(Box<Condition>),
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
}

impl SigmaRule {
    /// Parse the supported Sigma subset from a YAML document.
    pub fn from_yaml(source: &str) -> Result<Self, RuleError> {
        let root: YamlValue = serde_yaml::from_str(source)?;
        let root = root.as_mapping().ok_or(RuleError::RootNotMapping)?;
        let title = string_field(root, "title").ok_or(RuleError::MissingTitle)?;
        let id = string_field(root, "id");
        let description = string_field(root, "description");
        let level = string_field(root, "level");
        let tags = string_sequence_field(root, "tags")?;
        let logsource = parse_logsource(root)?;
        let detection = mapping_field(root, "detection").ok_or(RuleError::MissingDetection)?;
        let condition_text =
            string_field(detection, "condition").ok_or(RuleError::MissingCondition)?;

        let mut selections = BTreeMap::new();
        for (key, value) in detection {
            let Some(name) = key.as_str() else { continue };
            if name == "condition" {
                continue;
            }
            let matchers = parse_selection(name, value)?;
            selections.insert(name.to_owned(), matchers);
        }
        let condition = ConditionParser::parse(&condition_text)?;
        validate_condition_selections(&condition, &selections)?;

        Ok(Self {
            title,
            id,
            description,
            level,
            tags,
            logsource,
            selections,
            condition,
        })
    }

    /// Return true when the event satisfies the rule's condition.
    pub fn matches(&self, event: &serde_json::Value) -> bool {
        self.evaluate(event).is_some()
    }

    /// Return rule metadata when the event satisfies the rule.
    pub fn evaluate(&self, event: &serde_json::Value) -> Option<DetectionMatch> {
        if !self.logsource.matches(event) {
            return None;
        }
        let values: BTreeMap<_, _> = self
            .selections
            .iter()
            .map(|(name, matchers)| {
                let matched = !matchers.is_empty() && matchers.iter().all(|m| m.matches(event));
                (name.as_str(), matched)
            })
            .collect();
        self.condition.evaluate(&values).then(|| DetectionMatch {
            rule_id: self.id.clone(),
            title: self.title.clone(),
            level: self.level.clone(),
            tags: self.tags.clone(),
        })
    }
}

impl SigmaEngine {
    /// Parse and add a rule to the engine.
    pub fn add_rule_yaml(&mut self, source: &str) -> Result<(), RuleError> {
        self.rules.push(SigmaRule::from_yaml(source)?);
        Ok(())
    }

    /// Add an already parsed rule to the engine.
    pub fn add_rule(&mut self, rule: SigmaRule) {
        self.rules.push(rule);
    }

    /// Evaluate every loaded rule and return metadata for all matches.
    pub fn evaluate(&self, event: &serde_json::Value) -> Vec<DetectionMatch> {
        self.rules
            .iter()
            .filter_map(|rule| rule.evaluate(event))
            .collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn string_field(mapping: &Mapping, key: &str) -> Option<String> {
    mapping
        .get(YamlValue::String(key.to_owned()))
        .and_then(YamlValue::as_str)
        .map(str::to_owned)
}

fn string_sequence_field(mapping: &Mapping, key: &str) -> Result<Vec<String>, RuleError> {
    let Some(value) = mapping.get(YamlValue::String(key.to_owned())) else {
        return Ok(Vec::new());
    };
    let sequence = value
        .as_sequence()
        .ok_or_else(|| RuleError::InvalidMetadata {
            field: key.to_owned(),
            reason: "expected a sequence of strings".into(),
        })?;
    sequence
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| RuleError::InvalidMetadata {
                    field: key.to_owned(),
                    reason: "expected a sequence of strings".into(),
                })
        })
        .collect()
}

fn mapping_field<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Mapping> {
    mapping
        .get(YamlValue::String(key.to_owned()))
        .and_then(YamlValue::as_mapping)
}

fn parse_logsource(root: &Mapping) -> Result<LogSource, RuleError> {
    let Some(value) = root.get(YamlValue::String("logsource".to_owned())) else {
        return Ok(LogSource::default());
    };
    let mapping = value
        .as_mapping()
        .ok_or_else(|| RuleError::InvalidLogSource("expected a mapping".into()))?;
    let read = |key: &str| -> Result<Option<String>, RuleError> {
        let Some(value) = mapping.get(YamlValue::String(key.to_owned())) else {
            return Ok(None);
        };
        value
            .as_str()
            .map(str::to_owned)
            .map(Some)
            .ok_or_else(|| RuleError::InvalidLogSource(format!("`{key}` must be a string")))
    };
    Ok(LogSource {
        product: read("product")?,
        category: read("category")?,
        service: read("service")?,
    })
}

impl LogSource {
    fn matches(&self, event: &serde_json::Value) -> bool {
        if let Some(product) = &self.product {
            let Some(os) = event
                .get("host")
                .and_then(|host| host.get("os"))
                .and_then(|v| v.as_str())
            else {
                return false;
            };
            if !product_matches(product, os) {
                return false;
            }
        }

        if let Some(category) = &self.category {
            let Some(event_category) = event.get("category").and_then(|v| v.as_str()) else {
                return false;
            };
            let action = event
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if !category_matches(category, event_category, action) {
                return false;
            }
        }

        if let Some(service) = &self.service {
            let raw = event.get("raw");
            let source = raw
                .and_then(|raw| raw.get("source"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let provider = raw
                .and_then(|raw| raw.get("provider"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let service = service.to_ascii_lowercase();
            if !source.to_ascii_lowercase().contains(&service)
                && !provider.to_ascii_lowercase().contains(&service)
            {
                return false;
            }
        }
        true
    }
}

fn product_matches(product: &str, os: &str) -> bool {
    let product = product.to_ascii_lowercase();
    let os = os.to_ascii_lowercase();
    match product.as_str() {
        "windows" | "win" => os.starts_with("windows") || os == "win",
        "linux" => os.starts_with("linux"),
        "macos" | "osx" => os.starts_with("macos") || os.starts_with("osx"),
        _ => product == os,
    }
}

fn category_matches(sigma_category: &str, event_category: &str, action: &str) -> bool {
    match sigma_category.to_ascii_lowercase().as_str() {
        "process_creation" => event_category == "process" && action == "create",
        "network_connection" => event_category == "network" && action == "connect",
        "authentication" => event_category == "authentication",
        "file_event" | "file_access" | "file_change" => event_category == "file",
        "service" => event_category == "service",
        "registry_event" => event_category == "persistence",
        other => other == event_category,
    }
}

fn parse_selection(name: &str, value: &YamlValue) -> Result<Vec<FieldMatcher>, RuleError> {
    let fields = value
        .as_mapping()
        .ok_or_else(|| RuleError::InvalidSelection {
            selection: name.to_owned(),
            reason: "expected a field mapping".into(),
        })?;
    let mut matchers = Vec::with_capacity(fields.len());
    for (key, value) in fields {
        let field = key.as_str().ok_or_else(|| RuleError::InvalidSelection {
            selection: name.to_owned(),
            reason: "field names must be strings".into(),
        })?;
        let mut parts = field.split('|');
        let path = parts.next().unwrap_or_default();
        if path.is_empty() {
            return invalid_selection(name, "field path cannot be empty");
        }
        let mut modifier = Modifier::Exact;
        let mut all_values = false;
        for part in parts {
            modifier = match part {
                "contains" => Modifier::Contains,
                "startswith" => Modifier::StartsWith,
                "endswith" => Modifier::EndsWith,
                "re" => Modifier::Regex,
                "exists" => Modifier::Exists,
                "all" => {
                    all_values = true;
                    continue;
                }
                other => return Err(RuleError::UnsupportedModifier(other.to_owned())),
            };
        }
        let expected = if matches!(modifier, Modifier::Exists) {
            vec![yaml_to_json(value).unwrap_or(serde_json::Value::Bool(true))]
        } else {
            match value {
                YamlValue::Sequence(items) => items
                    .iter()
                    .map(yaml_to_json)
                    .collect::<Result<Vec<_>, _>>()?,
                scalar => vec![yaml_to_json(scalar)?],
            }
        };
        if expected.is_empty() {
            return invalid_selection(name, "field values cannot be an empty list");
        }
        matchers.push(FieldMatcher {
            path: normalize_field_path(path),
            modifier,
            all_values,
            expected,
        });
    }
    if matchers.is_empty() {
        return invalid_selection(name, "selection cannot be empty");
    }
    Ok(matchers)
}

fn normalize_field_path(path: &str) -> Vec<String> {
    let normalized = match path.to_ascii_lowercase().as_str() {
        "image" | "process.executable" | "process.path" => "process.path",
        "commandline" | "process.command_line" => "process.command_line",
        "processid" | "process.pid" => "process.pid",
        "parentimage" => "process.parent.name",
        "parentprocessid" => "process.parent.pid",
        "user" | "username" | "user.name" => "user.name",
        "targetfilename" | "file.path" => "file.path",
        "destinationip" | "destination.address" | "destination.ip" => "network.remote_address",
        "destinationport" | "destination.port" => "network.remote_port",
        "sourceip" | "source.address" | "source.ip" => "network.local_address",
        "sourceport" | "source.port" => "network.local_port",
        "protocol" | "network.protocol" => "network.protocol",
        _ => path,
    };
    normalized.split('.').map(str::to_owned).collect()
}

fn invalid_selection<T>(name: &str, reason: &str) -> Result<T, RuleError> {
    Err(RuleError::InvalidSelection {
        selection: name.to_owned(),
        reason: reason.to_owned(),
    })
}

fn yaml_to_json(value: &YamlValue) -> Result<serde_json::Value, RuleError> {
    serde_json::to_value(value).map_err(|error| RuleError::InvalidSelection {
        selection: "<unknown>".into(),
        reason: format!("value cannot be represented as JSON: {error}"),
    })
}

impl FieldMatcher {
    fn matches(&self, event: &serde_json::Value) -> bool {
        let actual = self
            .path
            .iter()
            .try_fold(event, |value, part| value.get(part));
        match &self.modifier {
            Modifier::Exists => {
                let wanted = self
                    .expected
                    .first()
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true);
                actual.is_some_and(|value| !value.is_null()) == wanted
            }
            _ if self.all_values => actual.is_some_and(|value| {
                self.expected
                    .iter()
                    .all(|wanted| scalar_matches(value, wanted, self.modifier))
            }),
            modifier => actual.is_some_and(|value| {
                self.expected
                    .iter()
                    .any(|wanted| scalar_matches(value, wanted, *modifier))
            }),
        }
    }
}

fn scalar_matches(
    actual: &serde_json::Value,
    expected: &serde_json::Value,
    modifier: Modifier,
) -> bool {
    if let Some(items) = actual.as_array() {
        return items
            .iter()
            .any(|item| scalar_matches(item, expected, modifier.clone()));
    }
    match (actual, expected) {
        (serde_json::Value::String(actual), serde_json::Value::String(expected)) => {
            let actual = actual.to_lowercase();
            let expected = expected.to_lowercase();
            match modifier {
                Modifier::Exact => wildcard_match(&actual, &expected),
                Modifier::Contains => actual.contains(&expected),
                Modifier::StartsWith => actual.starts_with(&expected),
                Modifier::EndsWith => actual.ends_with(&expected),
                Modifier::Regex => Regex::new(&expected).is_ok_and(|regex| regex.is_match(&actual)),
                Modifier::Exists => false,
            }
        }
        (_, _) if matches!(modifier, Modifier::Exact) => actual == expected,
        _ => false,
    }
}

fn wildcard_match(actual: &str, pattern: &str) -> bool {
    let mut expression = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => expression.push_str(".*"),
            '?' => expression.push('.'),
            ch => expression.push_str(&regex::escape(&ch.to_string())),
        }
    }
    expression.push('$');
    Regex::new(&expression).is_ok_and(|regex| regex.is_match(actual))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    And,
    Or,
    Not,
    LeftParen,
    RightParen,
}

struct ConditionParser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl ConditionParser {
    fn parse(source: &str) -> Result<Condition, RuleError> {
        let tokens = tokenize_condition(source)?;
        let mut parser = Self { tokens, cursor: 0 };
        let condition = parser.parse_or()?;
        if parser.cursor != parser.tokens.len() {
            return Err(RuleError::InvalidCondition(
                "unexpected trailing token".into(),
            ));
        }
        Ok(condition)
    }

    fn parse_or(&mut self) -> Result<Condition, RuleError> {
        let mut left = self.parse_and()?;
        while self.take(&Token::Or) {
            left = Condition::Or(Box::new(left), Box::new(self.parse_and()?));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Condition, RuleError> {
        let mut left = self.parse_unary()?;
        while self.take(&Token::And) {
            left = Condition::And(Box::new(left), Box::new(self.parse_unary()?));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Condition, RuleError> {
        if self.take(&Token::Not) {
            return Ok(Condition::Not(Box::new(self.parse_unary()?)));
        }
        if self.take(&Token::LeftParen) {
            let condition = self.parse_or()?;
            if !self.take(&Token::RightParen) {
                return Err(RuleError::InvalidCondition("missing `)`".into()));
            }
            return Ok(condition);
        }
        match self.tokens.get(self.cursor).cloned() {
            Some(Token::Word(name)) => {
                self.cursor += 1;
                let all = name.eq_ignore_ascii_case("all");
                let minimum = if all {
                    Some(0)
                } else {
                    name.parse::<usize>().ok()
                };
                if let Some(minimum) = minimum {
                    if !all && minimum == 0 {
                        return Err(RuleError::InvalidCondition(
                            "numeric quantifiers must be greater than zero".into(),
                        ));
                    }
                    if matches!(self.tokens.get(self.cursor), Some(Token::Word(word)) if word.eq_ignore_ascii_case("of"))
                    {
                        self.cursor += 1;
                        let Some(Token::Word(selector)) = self.tokens.get(self.cursor).cloned()
                        else {
                            return Err(RuleError::InvalidCondition(
                                "expected a selection pattern after `of`".into(),
                            ));
                        };
                        self.cursor += 1;
                        return Ok(Condition::Quantified {
                            minimum,
                            all,
                            selector,
                        });
                    }
                    if !all {
                        return Err(RuleError::InvalidCondition(
                            "numeric quantifiers must use the form `<count> of <selection>`".into(),
                        ));
                    }
                }
                Ok(Condition::Selection(name))
            }
            _ => Err(RuleError::InvalidCondition(
                "expected a selection name".into(),
            )),
        }
    }

    fn take(&mut self, token: &Token) -> bool {
        if self.tokens.get(self.cursor) == Some(token) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }
}

fn tokenize_condition(source: &str) -> Result<Vec<Token>, RuleError> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let flush = |word: &mut String, tokens: &mut Vec<Token>| {
        if !word.is_empty() {
            let token = match word.to_ascii_lowercase().as_str() {
                "and" => Token::And,
                "or" => Token::Or,
                "not" => Token::Not,
                _ => Token::Word(std::mem::take(word)),
            };
            tokens.push(token);
            word.clear();
        }
    };
    for ch in source.chars() {
        match ch {
            '(' => {
                flush(&mut word, &mut tokens);
                tokens.push(Token::LeftParen);
            }
            ')' => {
                flush(&mut word, &mut tokens);
                tokens.push(Token::RightParen);
            }
            ch if ch.is_whitespace() => flush(&mut word, &mut tokens),
            ch => word.push(ch),
        }
    }
    flush(&mut word, &mut tokens);
    if tokens.is_empty() {
        return Err(RuleError::InvalidCondition(
            "condition cannot be empty".into(),
        ));
    }
    Ok(tokens)
}

fn validate_condition_selections(
    condition: &Condition,
    selections: &BTreeMap<String, Vec<FieldMatcher>>,
) -> Result<(), RuleError> {
    match condition {
        Condition::Selection(name) if !selections.contains_key(name) => Err(
            RuleError::InvalidCondition(format!("condition references unknown selection `{name}`")),
        ),
        Condition::Selection(_) => Ok(()),
        Condition::Quantified { selector, .. } => {
            if selector.eq_ignore_ascii_case("them") {
                return if selections.is_empty() {
                    Err(RuleError::InvalidCondition(
                        "quantifier `them` has no selections to match".into(),
                    ))
                } else {
                    Ok(())
                };
            }
            if selections
                .keys()
                .any(|name| selection_pattern_matches(selector, name))
            {
                Ok(())
            } else {
                Err(RuleError::InvalidCondition(format!(
                    "quantifier references no selections matching `{selector}`"
                )))
            }
        }
        Condition::Not(inner) => validate_condition_selections(inner, selections),
        Condition::And(left, right) | Condition::Or(left, right) => {
            validate_condition_selections(left, selections)?;
            validate_condition_selections(right, selections)
        }
    }
}

impl Condition {
    fn evaluate(&self, selections: &BTreeMap<&str, bool>) -> bool {
        match self {
            Self::Selection(name) => selections.get(name.as_str()).copied().unwrap_or(false),
            Self::Quantified {
                minimum,
                all,
                selector,
            } => {
                let matching: Vec<_> = selections
                    .iter()
                    .filter(|(name, _)| {
                        selector.eq_ignore_ascii_case("them")
                            || selection_pattern_matches(selector, name)
                    })
                    .collect();
                if matching.is_empty() {
                    return false;
                }
                let matched = matching.iter().filter(|(_, matched)| **matched).count();
                if *all {
                    matched == matching.len()
                } else {
                    matched >= *minimum
                }
            }
            Self::Not(inner) => !inner.evaluate(selections),
            Self::And(left, right) => left.evaluate(selections) && right.evaluate(selections),
            Self::Or(left, right) => left.evaluate(selections) || right.evaluate(selections),
        }
    }
}

fn selection_pattern_matches(pattern: &str, name: &str) -> bool {
    wildcard_match(&name.to_ascii_lowercase(), &pattern.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{RuleError, SigmaEngine, SigmaRule};
    use serde_json::json;

    fn event() -> serde_json::Value {
        json!({
            "host": {"os": "windows"},
            "category": "process",
            "action": "create",
            "process": {
                "path": "C:\\Windows\\System32\\PowerShell.exe",
                "command_line": "powershell.exe -enc payload",
                "pid": 42
            }
        })
    }

    #[test]
    fn evaluates_conditions_modifiers_and_metadata() {
        let rule = SigmaRule::from_yaml(
            r#"
title: Encoded PowerShell
id: test-rule
level: high
tags: [attack.execution]
logsource:
  product: windows
  category: process_creation
detection:
  image:
    Image|endswith: powershell.exe
  command:
    CommandLine|contains: -enc
  condition: image and command
"#,
        )
        .unwrap();

        let matched = rule.evaluate(&event()).unwrap();
        assert_eq!(matched.rule_id.as_deref(), Some("test-rule"));
        assert_eq!(matched.title, "Encoded PowerShell");
        assert_eq!(matched.level.as_deref(), Some("high"));
        assert_eq!(matched.tags, ["attack.execution"]);
    }

    #[test]
    fn supports_selection_quantifiers_and_field_existence() {
        let rule = SigmaRule::from_yaml(
            r#"
title: Process field checks
detection:
  selection_a:
    Image|endswith: powershell.exe
  selection_b:
    ProcessId|exists: true
  condition: 2 of selection_*
"#,
        )
        .unwrap();
        assert!(rule.matches(&event()));

        let absent_field = SigmaRule::from_yaml(
            r#"
title: Missing field
detection:
  selection:
    Authentication|exists: false
  condition: selection
"#,
        )
        .unwrap();
        assert!(absent_field.matches(&event()));
    }

    #[test]
    fn rejects_unknown_selections_and_unsupported_modifiers() {
        let unknown_selection = SigmaRule::from_yaml(
            r#"
title: Invalid reference
detection:
  selection:
    Image: powershell.exe
  condition: missing
"#,
        );
        assert!(matches!(
            unknown_selection,
            Err(RuleError::InvalidCondition(_))
        ));

        let unsupported_modifier = SigmaRule::from_yaml(
            r#"
title: Unsupported modifier
detection:
  selection:
    Image|cidr: 192.0.2.0/24
  condition: selection
"#,
        );
        assert!(matches!(
            unsupported_modifier,
            Err(RuleError::UnsupportedModifier(_))
        ));
    }

    #[test]
    fn engine_returns_all_matching_rules() {
        let mut engine = SigmaEngine::default();
        engine
            .add_rule_yaml(
                r#"
title: First
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
"#,
            )
            .unwrap();
        engine
            .add_rule_yaml(
                r#"
title: Second
detection:
  selection:
    ProcessId: 42
  condition: selection
"#,
            )
            .unwrap();

        let matches = engine.evaluate(&event());
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].title, "First");
        assert_eq!(matches[1].title, "Second");
    }
}
