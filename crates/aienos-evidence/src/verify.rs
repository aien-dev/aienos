//! Config A bundle verification.
//!
//! `errors` means the capture itself cannot be trusted as reference evidence.
//! `m0_open` lists what still keeps the M0 freeze from closing even when the
//! capture is sound (for example, an untested native-boot rollback).

use crate::canon::{checksum, CHECKSUM_FIELD};
use serde_json::Value;

/// Output tokens below this measure start-up latency, not decode speed.
pub const MIN_OUTPUT_TOKENS: u64 = 32;
pub const MIN_SAMPLES: usize = 3;

#[derive(Debug, Default)]
pub struct Report {
    pub errors: Vec<String>,
    pub m0_open: Vec<String>,
}

fn nonempty(v: &Value) -> bool {
    v.as_str().is_some_and(|s| !s.trim().is_empty())
}

fn is_hex(v: &Value, len: usize) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == len
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub fn check(bundle: &Value) -> Report {
    let mut r = Report::default();
    let mut err = |m: &str| r.errors.push(m.to_string());

    if bundle[CHECKSUM_FIELD].as_str() != Some(checksum(bundle).as_str()) {
        err("bundle checksum mismatch");
    }
    if bundle["schema_version"] != crate::SCHEMA_VERSION {
        err("unsupported evidence schema");
    }
    let id = &bundle["config_identity"];
    if ![
        "host",
        "kernel",
        "architecture",
        "os_distribution",
        "kernel_command_line",
    ]
    .iter()
    .all(|k| nonempty(&id[*k]))
    {
        err("incomplete host identity");
    }
    let capsule = &bundle["machine_capsule"];
    if capsule["firmware"]["uefi_present"] != true {
        err("UEFI was not observed");
    }
    let accel = capsule["accelerators"].as_array();
    if !accel.is_some_and(|a| {
        !a.is_empty()
            && a.iter()
                .all(|g| nonempty(&g["pci_bus_id"]) && nonempty(&g["vendor_device"]))
    }) {
        err("GPU identity was not observed");
    }
    let cores = capsule["cpu"]["cores"].as_u64().unwrap_or(0);
    let part_sum: u64 = capsule["cpu"]["parts"]
        .as_object()
        .map(|m| m.values().filter_map(Value::as_u64).sum())
        .unwrap_or(0);
    if cores == 0 || part_sum != cores {
        err("CPU core inventory missing or inconsistent with core types");
    }
    if capsule["memory"]["total_kb"].as_u64().unwrap_or(0) == 0 {
        err("memory size missing");
    }
    if capsule["block_devices"]
        .as_array()
        .is_none_or(Vec::is_empty)
    {
        err("block device inventory missing");
    }
    let model = &bundle["baseline_model"];
    if !is_hex(&model["sha256"], 64) || model["size_bytes"].as_u64().unwrap_or(0) == 0 {
        err("baseline model digest or size missing");
    }
    match bundle["workspace_repositories"].as_array() {
        Some(repos) if !repos.is_empty() => {
            for repo in repos {
                let name = repo["name"].as_str().unwrap_or("?");
                if !is_hex(&repo["commit"], 40) {
                    err(&format!("repository {name} has no commit"));
                }
                if repo["dirty"] != false {
                    err(&format!(
                        "repository {name} was dirty at capture; the freeze is not reproducible"
                    ));
                }
            }
        }
        _ => err("workspace commit inventory missing"),
    }
    let samples = bundle["reference_workload"]["samples"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let complete = samples.iter().all(|s| {
        s["ttft_ms"].as_f64().unwrap_or(0.0) > 0.0
            && s["output_tokens"].as_u64().unwrap_or(0) >= MIN_OUTPUT_TOKENS
            && s["decode_tokens_per_second"].as_f64().unwrap_or(0.0) > 0.0
    });
    if samples.len() < MIN_SAMPLES || !complete {
        err(&format!(
            "{MIN_SAMPLES}+ inference samples with at least {MIN_OUTPUT_TOKENS} output tokens and a measured decode rate required"
        ));
    }

    let recovery = &bundle["recovery_procedure"];
    if recovery["status"] != "verified" {
        r.m0_open.push(format!(
            "recovery procedure is {}",
            recovery["status"].as_str().unwrap_or("unknown")
        ));
    }
    if recovery["native_boot_rollback_tested"] != true {
        r.m0_open
            .push("native boot rollback has not been tested on Machine 1".into());
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::seal;
    use serde_json::json;

    fn good() -> Value {
        let sample = |i| json!({"index": i, "ttft_ms": 80.0, "total_ms": 2080.0, "output_tokens": 256, "decode_tokens_per_second": 127.5});
        json!({
            "schema_version": crate::SCHEMA_VERSION,
            "config_identity": {"host": "spark", "kernel": "7.0", "architecture": "aarch64", "os_distribution": "Ubuntu", "kernel_command_line": "ro"},
            "machine_capsule": {
                "firmware": {"uefi_present": true},
                "accelerators": [{"pci_bus_id": "000f:01:00.0", "vendor_device": "10de:2e12"}],
                "cpu": {"cores": 20, "parts": {"0xd85": 10, "0xd87": 10}},
                "memory": {"total_kb": 127598748},
                "block_devices": [{"name": "nvme0n1", "size_bytes": 4000000000000u64}]
            },
            "baseline_model": {"sha256": "3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1", "size_bytes": 807694368},
            "workspace_repositories": [{"name": "aienos", "commit": "f6350b548cccc53ec03825021112be75c2b30667", "dirty": false}],
            "reference_workload": {"samples": [sample(0), sample(1), sample(2)]},
            "recovery_procedure": {"status": "documented_only", "native_boot_rollback_tested": false}
        })
    }

    #[test]
    fn sound_capture_passes_but_m0_stays_open_until_rollback_is_tested() {
        let r = check(&seal(good()));
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(r.m0_open.len(), 2);
    }

    #[test]
    fn tampering_dirty_repos_and_toy_workloads_are_rejected() {
        let mut tampered = seal(good());
        tampered["machine_capsule"]["cpu"]["cores"] = json!(21);
        assert!(check(&tampered)
            .errors
            .iter()
            .any(|e| e.contains("checksum")));

        let mut dirty = good();
        dirty["workspace_repositories"][0]["dirty"] = json!(true);
        assert!(check(&seal(dirty))
            .errors
            .iter()
            .any(|e| e.contains("dirty")));

        let mut toy = good();
        toy["reference_workload"]["samples"][1]["output_tokens"] = json!(2);
        assert!(check(&seal(toy))
            .errors
            .iter()
            .any(|e| e.contains("output tokens")));

        let mut mismatched = good();
        mismatched["machine_capsule"]["cpu"]["parts"] = json!({"0xd85": 10});
        assert!(check(&seal(mismatched))
            .errors
            .iter()
            .any(|e| e.contains("CPU")));
    }

    #[test]
    fn verified_recovery_closes_m0() {
        let mut closed = good();
        closed["recovery_procedure"] =
            json!({"status": "verified", "native_boot_rollback_tested": true});
        let r = check(&seal(closed));
        assert!(r.errors.is_empty() && r.m0_open.is_empty());
    }
}
