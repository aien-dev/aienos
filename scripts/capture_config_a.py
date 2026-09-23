#!/usr/bin/env python3
"""Read-only Config A hardware capture and local streaming inference probe."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MODEL = Path(os.environ.get("AIENOS_BASELINE_MODEL", "/home/drakestapleton/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf"))
ENDPOINT = os.environ.get("AIENOS_REFERENCE_ENDPOINT", "http://127.0.0.1:18094/v1")


def command(*args):
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def memory():
    result = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ("MemTotal", "SwapTotal"):
            result[key] = int(value.strip().split()[0])
    return result


def gpu():
    raw = command("nvidia-smi", "--query-gpu=name,driver_version,pci.bus_id", "--format=csv,noheader")
    if not raw:
        return None
    return [dict(zip(("model", "driver_version", "pci_bus_id"),
                     (part.strip() for part in row.split(",", 2)))) for row in raw.splitlines()]


def repositories():
    result = []
    for name in ("aienos-repo", "aegis-runtime", "aien-sovereign-core", "spark-sentinel"):
        path = ROOT.parent / name
        if not (path / ".git").exists():
            continue
        status = command("git", "-C", str(path), "status", "--porcelain")
        result.append({"name": name,
                       "commit": command("git", "-C", str(path), "rev-parse", "HEAD"),
                       "branch": command("git", "-C", str(path), "branch", "--show-current"),
                       "dirty": None if status is None else bool(status)})
    return result


def request(url, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    return urllib.request.urlopen(urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}), timeout=30)


def workload():
    try:
        with request(ENDPOINT + "/models") as response:
            model = json.load(response)["data"][0]["id"]
    except (OSError, ValueError, KeyError, IndexError) as error:
        return {"endpoint": ENDPOINT, "error": str(error), "samples": []}
    prompt = "Reply with one word: ready"
    samples = []
    for index in range(3):
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}],
                   "temperature": 0, "max_tokens": 32, "stream": True,
                   "stream_options": {"include_usage": True}}
        started = time.monotonic_ns()
        first = None
        usage = None
        try:
            with request(ENDPOINT + "/chat/completions", payload) as response:
                for line in response:
                    if not line.startswith(b"data: ") or line.strip() == b"data: [DONE]":
                        continue
                    chunk = json.loads(line[6:])
                    usage = chunk.get("usage") or usage
                    if first is None and any(c.get("delta", {}).get("content") for c in chunk.get("choices", [])):
                        first = time.monotonic_ns()
            finished = time.monotonic_ns()
            tokens = usage.get("completion_tokens") if usage else None
            samples.append({"index": index, "ttft_ms": None if first is None else round((first-started)/1e6, 3),
                            "total_ms": round((finished-started)/1e6, 3), "output_tokens": tokens,
                            "output_tokens_per_second": None if not tokens else round(tokens/((finished-started)/1e9), 3)})
        except (OSError, ValueError) as error:
            samples.append({"index": index, "error": str(error)})
    return {"endpoint": ENDPOINT, "model": model, "prompt": prompt, "samples": samples}


def main():
    if not MODEL.is_file():
        raise SystemExit(f"Baseline model does not exist: {MODEL}")
    stat = os.statvfs("/")
    nvcc = command("nvcc", "--version")
    cpu = sorted({line.partition(":")[2].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                  if line.partition(":")[0].strip() in ("model name", "CPU part")})
    fw_bits = Path("/sys/firmware/efi/fw_platform_size")
    bundle = {
        "schema_version": "2.0.0",
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "config_identity": {"host": platform.node(), "kernel": platform.release(),
                            "architecture": platform.machine(),
                            "os_distribution": platform.freedesktop_os_release().get("PRETTY_NAME"),
                            "kernel_command_line": Path("/proc/cmdline").read_text().strip()},
        "machine_capsule": {
            "firmware": {"uefi_present": Path("/sys/firmware/efi").is_dir(),
                         "platform_bits": fw_bits.read_text().strip() if fw_bits.exists() else None},
            "cpu": {"models": cpu, "cores": os.cpu_count(), "architecture": platform.machine()},
            "accelerator": gpu(),
            "memory": {"total_kb": memory().get("MemTotal"), "swap_kb": memory().get("SwapTotal")},
            "storage": {"root_available_bytes": stat.f_bavail * stat.f_frsize,
                        "block_devices": json.loads(command("lsblk", "--json", "--output", "NAME,TYPE,SIZE,MODEL,MOUNTPOINTS") or "{}")}},
        "toolchains": {"rustc": command("rustc", "--version"), "cargo": command("cargo", "--version"),
                       "python": platform.python_version(),
                       "cuda_compiler_release": re.search(r"release ([^,]+)", nvcc).group(1)
                       if nvcc and re.search(r"release ([^,]+)", nvcc) else None},
        "baseline_model": {"path": str(MODEL), "size_bytes": MODEL.stat().st_size, "sha256": file_hash(MODEL)},
        "workspace_repositories": repositories(),
        "reference_workload": workload(),
        "recovery_procedure": {"status": "documented_only", "native_boot_rollback_tested": False},
    }
    canonical = json.dumps(bundle, indent=2, sort_keys=True)
    bundle["bundle_checksum_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
    output = ROOT / "evidence" / "config_a_reference_bundle.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(bundle, indent=2) + "\n")
    print(f"Captured observed Config A data: {output}")
    print(f"Workload samples: {len(bundle['reference_workload']['samples'])}")


if __name__ == "__main__":
    main()
