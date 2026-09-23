#!/usr/bin/env python3
"""Validate observed Config A evidence, not merely its self-checksum."""

import hashlib
import json
from pathlib import Path
import re
import sys


def check(bundle):
    errors = []
    stored = bundle.pop("bundle_checksum_sha256", None)
    actual = hashlib.sha256(json.dumps(bundle, indent=2, sort_keys=True).encode()).hexdigest()
    if stored != actual:
        errors.append("bundle checksum mismatch")
    if bundle.get("schema_version") != "2.0.0":
        errors.append("unsupported evidence schema")
    identity = bundle.get("config_identity", {})
    if not all(identity.get(k) for k in ("host", "kernel", "architecture", "os_distribution", "kernel_command_line")):
        errors.append("incomplete host identity")
    capsule = bundle.get("machine_capsule", {})
    if not capsule.get("firmware", {}).get("uefi_present"):
        errors.append("UEFI was not observed")
    if not capsule.get("accelerator") or not all(
            gpu.get("model") and gpu.get("driver_version") and gpu.get("pci_bus_id")
            for gpu in capsule.get("accelerator") or []):
        errors.append("GPU identity was not observed")
    if not capsule.get("cpu", {}).get("cores") or not capsule.get("memory", {}).get("total_kb"):
        errors.append("CPU or memory identity missing")
    if not capsule.get("storage", {}).get("block_devices", {}).get("blockdevices"):
        errors.append("block device inventory missing")
    model = bundle.get("baseline_model", {})
    if not re.fullmatch(r"[0-9a-f]{64}", model.get("sha256", "")) or not model.get("size_bytes"):
        errors.append("baseline model digest or size missing")
    if not bundle.get("workspace_repositories") or any(not item.get("commit") for item in bundle["workspace_repositories"]):
        errors.append("workspace commit inventory missing")
    samples = bundle.get("reference_workload", {}).get("samples", [])
    if len(samples) < 3 or any(not sample.get("ttft_ms") or not sample.get("output_tokens")
                               or not sample.get("output_tokens_per_second") for sample in samples):
        errors.append("three complete measured inference samples required")
    return errors


def main():
    path = Path(sys.argv[1])
    try:
        bundle = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise SystemExit(f"Evidence unavailable: {error}") from error
    errors = check(bundle)
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        raise SystemExit(1)
    samples = bundle["reference_workload"]["samples"]
    print(f"Config A capture verified for {bundle['config_identity']['host']}: {len(samples)} measured inference samples")
    print("Native boot and recovery qualification remain separate gates.")


if __name__ == "__main__":
    main()
