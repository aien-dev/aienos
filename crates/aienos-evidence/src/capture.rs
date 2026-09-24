//! Read-only capture of the Linux reference machine (Config A).
//!
//! Sources are procfs, sysfs, git, and the local inference endpoint. GPU
//! identity comes from PCI sysfs rather than vendor userspace tools, and no
//! host boot state is changed.

use crate::http::{self, Endpoint};
use aienos_kernel::crypto::sha256::Sha256;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Options {
    pub model: PathBuf,
    pub endpoint: String,
    pub prompt: String,
    pub max_tokens: u32,
    pub samples: usize,
    pub warmup: usize,
    pub repos: Vec<(String, PathBuf)>,
    pub allow_dirty: bool,
}

pub const DEFAULT_PROMPT: &str = "Explain in about two hundred words how a copy-on-write page table lets two processes share memory until one of them writes, and what the kernel does on that first write.";

fn read(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn command(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `CPU part` counts from /proc/cpuinfo, e.g. {"0xd85": 10, "0xd87": 10}.
pub fn cpu_parts(cpuinfo: &str) -> BTreeMap<String, u64> {
    let mut parts = BTreeMap::new();
    for line in cpuinfo.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim() == "CPU part" {
                *parts.entry(value.trim().to_string()).or_insert(0) += 1;
            }
        }
    }
    parts
}

pub fn os_release_pretty(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
}

fn meminfo_kb(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
}

fn accelerators() -> Vec<Value> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") else {
        return found;
    };
    for entry in entries.flatten() {
        let dev = entry.path();
        let vendor = read(dev.join("vendor")).unwrap_or_default();
        let class = read(dev.join("class")).unwrap_or_default();
        // NVIDIA display or 3D controller.
        if vendor != "0x10de" || !class.starts_with("0x03") {
            continue;
        }
        let device = read(dev.join("device")).unwrap_or_default();
        let driver = fs::read_link(dev.join("driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
        let driver_version = driver
            .as_ref()
            .and_then(|d| read(format!("/sys/module/{d}/version")));
        found.push(json!({
            "pci_bus_id": entry.file_name().to_string_lossy(),
            "vendor_device": format!("{}:{}", vendor.trim_start_matches("0x"), device.trim_start_matches("0x")),
            "class": class,
            "driver": driver,
            "driver_version": driver_version,
        }));
    }
    found.sort_by_key(|v| v["pci_bus_id"].as_str().unwrap_or_default().to_string());
    found
}

fn block_devices() -> Vec<Value> {
    let mut devices = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/block") else {
        return devices;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if ["loop", "ram", "zram"].iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let dev = entry.path();
        let sectors: u64 = read(dev.join("size"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        devices.push(json!({
            "name": name,
            "size_bytes": sectors * 512,
            "model": read(dev.join("device/model")),
        }));
    }
    devices.sort_by_key(|v| v["name"].as_str().unwrap_or_default().to_string());
    devices
}

pub fn file_sha256(path: &Path) -> std::io::Result<(u64, String)> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 4 << 20];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((size, crate::canon::hex(&hasher.finalize())))
}

fn repositories(repos: &[(String, PathBuf)]) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for (name, path) in repos {
        let p = path.to_string_lossy();
        let commit = command("git", &["-C", &p, "rev-parse", "HEAD"])
            .ok_or_else(|| format!("{name}: not a git checkout at {p}"))?;
        let status = command("git", &["-C", &p, "status", "--porcelain"])
            .ok_or_else(|| format!("{name}: git status failed"))?;
        out.push(json!({
            "name": name,
            "commit": commit,
            "branch": command("git", &["-C", &p, "branch", "--show-current"]).filter(|b| !b.is_empty()),
            "dirty": !status.is_empty(),
        }));
    }
    Ok(out)
}

fn workload(opts: &Options) -> Result<Value, String> {
    let ep = Endpoint::parse(&opts.endpoint)?;
    let model = http::model_ids(&ep)?
        .into_iter()
        .next()
        .ok_or("endpoint lists no models")?;
    for _ in 0..opts.warmup {
        http::chat_sample(&ep, &model, &opts.prompt, opts.max_tokens)?;
    }
    let mut samples = Vec::new();
    for index in 0..opts.samples {
        let s = http::chat_sample(&ep, &model, &opts.prompt, opts.max_tokens)?;
        let round = |x: f64| (x * 1000.0).round() / 1000.0;
        samples.push(json!({
            "index": index,
            "ttft_ms": round(s.ttft_ms),
            "total_ms": round(s.total_ms),
            "output_tokens": s.output_tokens,
            "decode_tokens_per_second": round(s.decode_tokens_per_second),
        }));
    }
    Ok(json!({
        "endpoint": opts.endpoint,
        "model": model,
        "prompt": opts.prompt,
        "max_tokens": opts.max_tokens,
        "temperature": 0,
        "warmup_samples": opts.warmup,
        "samples": samples,
    }))
}

pub fn capture(opts: &Options) -> Result<Value, String> {
    let repos = repositories(&opts.repos)?;
    let dirty: Vec<&str> = repos
        .iter()
        .filter(|r| r["dirty"] == json!(true))
        .filter_map(|r| r["name"].as_str())
        .collect();
    if !dirty.is_empty() && !opts.allow_dirty {
        return Err(format!(
            "refusing to freeze dirty repositories: {} (commit or use --allow-dirty)",
            dirty.join(", ")
        ));
    }
    let (model_size, model_sha) =
        file_sha256(&opts.model).map_err(|e| format!("model {}: {e}", opts.model.display()))?;
    let cpuinfo = read("/proc/cpuinfo").unwrap_or_default();
    let meminfo = read("/proc/meminfo").unwrap_or_default();
    let parts = cpu_parts(&cpuinfo);

    let mut bundle = Map::new();
    bundle.insert("schema_version".into(), json!(crate::SCHEMA_VERSION));
    bundle.insert("generated_at_utc".into(), json!(crate::time::now_utc()));
    bundle.insert(
        "capture_tool".into(),
        json!({"name": "aienos-evidence", "version": env!("CARGO_PKG_VERSION")}),
    );
    bundle.insert(
        "config_identity".into(),
        json!({
            "host": read("/proc/sys/kernel/hostname"),
            "kernel": read("/proc/sys/kernel/osrelease"),
            "architecture": std::env::consts::ARCH,
            "os_distribution": read("/etc/os-release").as_deref().and_then(os_release_pretty),
            "kernel_command_line": read("/proc/cmdline"),
        }),
    );
    bundle.insert(
        "machine_capsule".into(),
        json!({
            "firmware": {
                "uefi_present": Path::new("/sys/firmware/efi").is_dir(),
                "platform_bits": read("/sys/firmware/efi/fw_platform_size"),
            },
            "cpu": {
                "architecture": std::env::consts::ARCH,
                "cores": parts.values().sum::<u64>(),
                "parts": parts,
            },
            "accelerators": accelerators(),
            "memory": {
                "total_kb": meminfo_kb(&meminfo, "MemTotal"),
                "swap_kb": meminfo_kb(&meminfo, "SwapTotal"),
            },
            "block_devices": block_devices(),
        }),
    );
    bundle.insert(
        "toolchains".into(),
        json!({
            "rustc": command("rustc", &["--version"]),
            "cargo": command("cargo", &["--version"]),
        }),
    );
    bundle.insert(
        "baseline_model".into(),
        json!({"path": opts.model, "size_bytes": model_size, "sha256": model_sha}),
    );
    bundle.insert("workspace_repositories".into(), Value::Array(repos));
    bundle.insert("reference_workload".into(), workload(opts)?);
    bundle.insert(
        "recovery_procedure".into(),
        json!({"status": "documented_only", "native_boot_rollback_tested": false}),
    );
    Ok(crate::canon::seal(Value::Object(bundle)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_heterogeneous_cpu_parts() {
        let info = "processor\t: 0\nCPU part\t: 0xd85\n\nprocessor\t: 1\nCPU part\t: 0xd87\n\nprocessor\t: 2\nCPU part\t: 0xd87\n";
        let parts = cpu_parts(info);
        assert_eq!(parts.get("0xd85"), Some(&1));
        assert_eq!(parts.get("0xd87"), Some(&2));
    }

    #[test]
    fn reads_os_release_and_meminfo() {
        assert_eq!(
            os_release_pretty("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n").as_deref(),
            Some("Ubuntu 24.04.5 LTS")
        );
        assert_eq!(
            meminfo_kb(
                "MemTotal:       127598748 kB\nSwapTotal: 0 kB\n",
                "MemTotal"
            ),
            Some(127_598_748)
        );
        assert_eq!(meminfo_kb("MemTotal: 1 kB\n", "SwapTotal"), None);
    }

    #[test]
    fn streams_file_hash_matches_one_shot_hash() {
        let path =
            std::env::temp_dir().join(format!("aienos-evidence-hash-{}", std::process::id()));
        let data: Vec<u8> = (0..(9 << 20)).map(|i| (i % 251) as u8).collect();
        fs::write(&path, &data).unwrap();
        let (size, digest) = file_sha256(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(size, data.len() as u64);
        assert_eq!(
            digest,
            crate::canon::hex(&aienos_kernel::crypto::sha256::hash(&data))
        );
    }
}
