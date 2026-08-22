//! Offline producer/consumer contract checks for the bundled Prometheus and Grafana assets.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::Value as JsonValue;
use serde_yaml_ng::Value as YamlValue;

const RAW_PREFIX: &str = "httprove_";
const RECORD_PREFIX: &str = "httprove:";
const INTENTIONAL_STANDALONE_RULES: [&str; 2] = [
    "httprove:availability_strict:ratio5m",
    "httprove:slo_burn_rate:30m",
];

fn identifiers(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut result = BTreeSet::new();
    let mut index = 0;
    while index < bytes.len() {
        let tail = &text[index..];
        if tail.starts_with(RAW_PREFIX) || tail.starts_with(RECORD_PREFIX) {
            let end = tail
                .char_indices()
                .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':')))
                .map(|(offset, _)| offset)
                .unwrap_or(tail.len());
            result.insert(tail[..end].to_string());
            index += end;
        } else {
            index += text[index..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
        }
    }
    result
}

fn yaml_rules(value: &YamlValue, records: &mut Vec<String>, expressions: &mut Vec<String>) {
    match value {
        YamlValue::Mapping(map) => {
            for (key, value) in map {
                match key.as_str() {
                    Some("record") => {
                        if let Some(name) = value.as_str() {
                            records.push(name.to_string());
                        }
                    }
                    Some("expr") => {
                        if let Some(expr) = value.as_str() {
                            expressions.push(expr.to_string());
                        }
                    }
                    _ => yaml_rules(value, records, expressions),
                }
            }
        }
        YamlValue::Sequence(items) => {
            for item in items {
                yaml_rules(item, records, expressions);
            }
        }
        _ => {}
    }
}

fn json_expressions(value: &JsonValue, expressions: &mut Vec<String>) {
    match value {
        JsonValue::Object(map) => {
            for (key, value) in map {
                if key == "expr" {
                    if let Some(expr) = value.as_str() {
                        expressions.push(expr.to_string());
                    }
                } else {
                    json_expressions(value, expressions);
                }
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                json_expressions(item, expressions);
            }
        }
        _ => {}
    }
}

fn validate_graph(
    raw: &BTreeSet<String>,
    records: &[String],
    expressions: &[String],
    allowed_orphans: &BTreeSet<String>,
) -> Result<(), String> {
    let mut counts = BTreeMap::new();
    for record in records {
        *counts.entry(record.as_str()).or_insert(0_usize) += 1;
    }
    let duplicates: Vec<_> = counts
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(name, _)| (*name).to_string())
        .collect();
    if !duplicates.is_empty() {
        return Err(format!(
            "duplicate recording rules: {}",
            duplicates.join(", ")
        ));
    }

    let produced: BTreeSet<_> = records.iter().cloned().collect();
    let referenced: BTreeSet<_> = expressions
        .iter()
        .flat_map(|expr| identifiers(expr))
        .collect();
    let unknown: Vec<_> = referenced
        .iter()
        .filter(|name| {
            (name.starts_with(RAW_PREFIX) && !raw.contains(*name))
                || (name.starts_with(RECORD_PREFIX) && !produced.contains(*name))
        })
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(format!("unknown metric references: {}", unknown.join(", ")));
    }

    let orphans: Vec<_> = produced
        .difference(&referenced)
        .filter(|name| !allowed_orphans.contains(*name))
        .cloned()
        .collect();
    if !orphans.is_empty() {
        return Err(format!("orphan recording rules: {}", orphans.join(", ")));
    }
    Ok(())
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).expect("read contract fixture")
}

#[test]
fn production_metrics_bundle_matches_the_rust_metric_inventory() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let raw = identifiers(&read(root.join("src/output/prom.rs")))
        .into_iter()
        .filter(|name| name.starts_with(RAW_PREFIX))
        .collect();

    let recording: YamlValue =
        serde_yaml_ng::from_str(&read(root.join("examples/prometheus-recording-rules.yml")))
            .expect("valid recording rules YAML");
    let alerts: YamlValue =
        serde_yaml_ng::from_str(&read(root.join("examples/prometheus-alerts.yml")))
            .expect("valid alerts YAML");
    let dashboard: JsonValue =
        serde_json::from_str(&read(root.join("examples/grafana-dashboard.json")))
            .expect("valid dashboard JSON");

    let mut records = Vec::new();
    let mut expressions = Vec::new();
    yaml_rules(&recording, &mut records, &mut expressions);
    yaml_rules(&alerts, &mut Vec::new(), &mut expressions);
    json_expressions(&dashboard, &mut expressions);
    let allowed_orphans = INTENTIONAL_STANDALONE_RULES
        .into_iter()
        .map(str::to_string)
        .collect();

    validate_graph(&raw, &records, &expressions, &allowed_orphans)
        .expect("production metrics bundle contract");
}

#[test]
fn identifier_scanner_ignores_promql_functions_durations_labels_and_templates() {
    let found = identifiers(
        r#"sum by (target) (rate(httprove_probes_total[5m])) + ${template} + on(target) group_left() httprove:availability:ratio5m"#,
    );
    assert_eq!(
        found,
        BTreeSet::from([
            "httprove:availability:ratio5m".to_string(),
            "httprove_probes_total".to_string(),
        ])
    );
}

#[test]
fn graph_rejects_unknown_duplicate_and_orphan_metrics() {
    let raw = BTreeSet::from(["httprove_known_total".to_string()]);
    let none = BTreeSet::new();

    let unknown = validate_graph(
        &raw,
        &["httprove:known:ratio".to_string()],
        &[
            "httprove_missing_total".to_string(),
            "httprove:known:ratio".to_string(),
        ],
        &none,
    )
    .unwrap_err();
    assert!(unknown.contains("httprove_missing_total"));

    let duplicate = validate_graph(
        &raw,
        &[
            "httprove:known:ratio".to_string(),
            "httprove:known:ratio".to_string(),
        ],
        &["httprove:known:ratio".to_string()],
        &none,
    )
    .unwrap_err();
    assert!(duplicate.contains("duplicate recording rules"));

    let orphan = validate_graph(
        &raw,
        &["httprove:orphan:ratio".to_string()],
        &["httprove_known_total".to_string()],
        &none,
    )
    .unwrap_err();
    assert!(orphan.contains("orphan recording rules"));
}
