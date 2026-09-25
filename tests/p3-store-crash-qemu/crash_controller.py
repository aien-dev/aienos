#!/usr/bin/env python3
"""
tests/p3-store-crash-qemu/crash_controller.py

P3 Crash/Reboot Qualification Harness - Deterministic Crash Controller
Component: Subagent G2 (Deterministic Crash Controller)

Responsibilities:
  1. Own mechanisms for terminating or resetting QEMU at named test persistence checkpoints.
  2. Monitor guest serial stream (file, named pipe/fifo, unix socket, or stdin) without
     host timing assumptions or race-prone sleep delays.
  3. Immediately upon encountering the target checkpoint marker, execute:
     - Hard kill (kill -9 on QEMU process to simulate instant loss of power)
     - Cold reset (QEMU monitor command system_reset via QMP or HMP monitor socket/pipe)
     - Clean exit (for control baseline runs without interrupting execution)
  4. Enforce watchdog timeouts if the guest hangs or fails to reach the marker.
  5. Provide detailed structured JSON telemetry and standard verification logging.

Supported Named Checkpoints (ADR 0015 / System Store v1):
  1.  before first write
  2.  during payload writes
  3.  after payload
  4.  during Catalog
  5.  after Catalog
  6.  during CommitRecord
  7.  before first flush
  8.  after first flush
  9.  during inactive Superblock write
  10. before final flush
  11. after final flush
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import select
import signal
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# -----------------------------------------------------------------------------
# Checkpoint Specification & Normalization
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class CheckpointSpec:
    index: int
    canonical_id: str
    display_name: str
    aliases: Tuple[str, ...]
    description: str

CHECKPOINTS: List[CheckpointSpec] = [
    CheckpointSpec(
        index=1,
        canonical_id="before_first_write",
        display_name="before first write",
        aliases=(
            "before first write",
            "before_first_write",
            "before-first-write",
            "before_write",
            "pre_write",
        ),
        description="Prior to submitting any write commands to block media (media untouched).",
    ),
    CheckpointSpec(
        index=2,
        canonical_id="during_payload_writes",
        display_name="during payload writes",
        aliases=(
            "during payload writes",
            "during_payload_writes",
            "during-payload-writes",
            "during payload write",
            "during_payload_write",
            "payload_writes",
            "payload_write",
        ),
        description="During emission of payload extent data blocks before catalog or commit record.",
    ),
    CheckpointSpec(
        index=3,
        canonical_id="after_payload",
        display_name="after payload",
        aliases=(
            "after payload",
            "after_payload",
            "after-payload",
            "after payload writes",
            "after_payload_writes",
            "payload_done",
        ),
        description="After all payload extent data blocks are submitted to block device.",
    ),
    CheckpointSpec(
        index=4,
        canonical_id="during_catalog",
        display_name="during Catalog",
        aliases=(
            "during catalog",
            "during Catalog",
            "during_catalog",
            "during-catalog",
            "during catalog write",
            "during_catalog_write",
            "catalog_write",
        ),
        description="During emission and write of Catalog metadata blocks.",
    ),
    CheckpointSpec(
        index=5,
        canonical_id="after_catalog",
        display_name="after Catalog",
        aliases=(
            "after catalog",
            "after Catalog",
            "after_catalog",
            "after-catalog",
            "after catalog write",
            "after_catalog_write",
            "catalog_done",
        ),
        description="After Catalog metadata blocks are completely submitted to device.",
    ),
    CheckpointSpec(
        index=6,
        canonical_id="during_commit_record",
        display_name="during CommitRecord",
        aliases=(
            "during commitrecord",
            "during commit record",
            "during CommitRecord",
            "during_commit_record",
            "during-commit-record",
            "during_commitrecord",
            "commit_record_write",
        ),
        description="During emission and write of the CommitRecord block.",
    ),
    CheckpointSpec(
        index=7,
        canonical_id="before_first_flush",
        display_name="before first flush",
        aliases=(
            "before first flush",
            "before_first_flush",
            "before-first-flush",
            "pre_first_flush",
            "before flush 1",
        ),
        description="Before issuing the first hardware cache flush barrier (payload + catalog + commit).",
    ),
    CheckpointSpec(
        index=8,
        canonical_id="after_first_flush",
        display_name="after first flush",
        aliases=(
            "after first flush",
            "after_first_flush",
            "after-first-flush",
            "post_first_flush",
            "after flush 1",
        ),
        description="Immediately following confirmation of the first hardware cache flush barrier.",
    ),
    CheckpointSpec(
        index=9,
        canonical_id="during_inactive_superblock_write",
        display_name="during inactive Superblock write",
        aliases=(
            "during inactive superblock write",
            "during inactive Superblock write",
            "during_inactive_superblock_write",
            "during-inactive-superblock-write",
            "during inactive superblock",
            "during_inactive_superblock",
            "during_superblock_write",
            "during superblock write",
        ),
        description="During write of the inactive Superblock slot with new generation and CRC.",
    ),
    CheckpointSpec(
        index=10,
        canonical_id="before_final_flush",
        display_name="before final flush",
        aliases=(
            "before final flush",
            "before_final_flush",
            "before-final-flush",
            "pre_final_flush",
            "before flush 2",
        ),
        description="After inactive superblock write, before issuing final hardware cache flush barrier.",
    ),
    CheckpointSpec(
        index=11,
        canonical_id="after_final_flush",
        display_name="after final flush",
        aliases=(
            "after final flush",
            "after_final_flush",
            "after-final-flush",
            "post_final_flush",
            "after flush 2",
            "commit_complete",
        ),
        description="Immediately following confirmation of final flush (transaction committed).",
    ),
]

_CANONICAL_MAP: Dict[str, CheckpointSpec] = {}
for _cp in CHECKPOINTS:
    _CANONICAL_MAP[_cp.canonical_id] = _cp
    _CANONICAL_MAP[_cp.display_name.lower()] = _cp
    for _alias in _cp.aliases:
        _CANONICAL_MAP[_alias.lower().replace("-", " ").replace("_", " ").strip()] = _cp
        _CANONICAL_MAP[_alias.lower().replace(" ", "_").strip()] = _cp

def normalize_text(text: str) -> str:
    """Normalize text by lowering, replacing hyphens/underscores with space, collapsing spaces."""
    t = text.lower()
    t = re.sub(r"[\-_\t\r\n]+", " ", t)
    t = re.sub(r"[^\w\s]", " ", t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()

def resolve_checkpoint(query: str) -> Optional[CheckpointSpec]:
    """Resolve a checkpoint string or alias to its CheckpointSpec."""
    if not query:
        return None
    raw = query.strip()
    low = raw.lower()
    if low in _CANONICAL_MAP:
        return _CANONICAL_MAP[low]
    norm = normalize_text(raw)
    if norm in _CANONICAL_MAP:
        return _CANONICAL_MAP[norm]
    # Check partial alias matches
    for cp in CHECKPOINTS:
        for alias in cp.aliases:
            if normalize_text(alias) == norm:
                return cp
    return None

# -----------------------------------------------------------------------------
# Telemetry and Execution Result
# -----------------------------------------------------------------------------

@dataclass
class ControllerResult:
    status: str                         # PASS, TIMEOUT, ERROR
    checkpoint_target: str              # Target requested by user
    checkpoint_canonical: str           # Canonical identifier if resolved
    checkpoint_matched_line: str        # Raw line that triggered match
    action: str                         # kill, reset, clean
    qemu_pid: Optional[int]             # Target process PID
    start_time: str                     # ISO 8601
    trigger_time: Optional[str] = None  # ISO 8601 when checkpoint hit
    action_complete_time: Optional[str] = None
    elapsed_seconds: float = 0.0        # Time from start to trigger
    action_latency_ms: float = 0.0      # Time taken to execute action
    watchdog_timeout: float = 0.0       # Configured watchdog timeout
    details: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent)

# -----------------------------------------------------------------------------
# QEMU Process & Termination Control
# -----------------------------------------------------------------------------

class QEMUController:
    """Controls QEMU process termination and monitor interactions."""

    def __init__(
        self,
        pid: Optional[int] = None,
        qmp_path: Optional[str] = None,
        monitor_path: Optional[str] = None,
        quiet: bool = False,
        log_file: Optional[Path] = None,
    ):
        self.pid = pid
        self.qmp_path = Path(qmp_path) if qmp_path else None
        self.monitor_path = Path(monitor_path) if monitor_path else None
        self.quiet = quiet
        self.log_file = log_file

    def log(self, level: str, msg: str) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        line = f"[{now}] [crash_controller:{level}] {msg}"
        if not self.quiet or level in ("ERROR", "FATAL", "HIT"):
            print(line, file=sys.stderr, flush=True)
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass

    def is_pid_alive(self, pid: Optional[int] = None) -> bool:
        target = pid or self.pid
        if not target:
            return False
        try:
            os.kill(target, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def hard_kill(self, pid: Optional[int] = None) -> Tuple[bool, float]:
        """
        Simulate instantaneous loss of power by sending SIGKILL (kill -9) to QEMU.
        Returns (success, latency_in_ms).
        """
        target = pid or self.pid
        if not target:
            self.log("ERROR", "hard_kill: No target PID provided")
            return False, 0.0

        t0 = time.perf_counter_ns()
        self.log("INFO", f"Executing HARD KILL (SIGKILL / power-cut) on PID {target}")

        try:
            # Send SIGKILL directly to process
            os.kill(target, signal.SIGKILL)
        except ProcessLookupError:
            self.log("WARN", f"PID {target} already dead before SIGKILL")
            t1 = time.perf_counter_ns()
            return True, (t1 - t0) / 1_000_000.0
        except Exception as e:
            self.log("ERROR", f"Failed to send SIGKILL to PID {target}: {e}")
            t1 = time.perf_counter_ns()
            return False, (t1 - t0) / 1_000_000.0

        # Wait briefly for process reap/exit
        reaped = False
        deadline = time.perf_counter_ns() + 2_000_000_000  # 2.0s
        while time.perf_counter_ns() < deadline:
            if not self.is_pid_alive(target):
                reaped = True
                break
            time.sleep(0.001)

        t1 = time.perf_counter_ns()
        latency_ms = (t1 - t0) / 1_000_000.0

        if reaped:
            self.log("INFO", f"PID {target} terminated successfully in {latency_ms:.3f} ms")
            return True, latency_ms
        else:
            self.log("WARN", f"PID {target} still exists in process table after {latency_ms:.3f} ms")
            return True, latency_ms

    def cold_reset_qmp(self, qmp_sock_path: Path) -> Tuple[bool, float]:
        """
        Send QEMU Machine Protocol (QMP) system_reset.
        """
        t0 = time.perf_counter_ns()
        self.log("INFO", f"Executing COLD RESET via QMP socket: {qmp_sock_path}")

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect(str(qmp_sock_path))

            # Step 1: Read QMP greeting banner
            data = b""
            while b"\r\n" not in data and b"\n" not in data:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk

            # Step 2: Negotiate capabilities
            sock.sendall(json.dumps({"execute": "qmp_capabilities"}).encode("utf-8") + b"\r\n")
            cap_resp = sock.recv(1024)

            # Step 3: Issue system_reset
            sock.sendall(json.dumps({"execute": "system_reset"}).encode("utf-8") + b"\r\n")
            reset_resp = sock.recv(1024)
            sock.close()

            t1 = time.perf_counter_ns()
            latency_ms = (t1 - t0) / 1_000_000.0
            self.log("INFO", f"QMP system_reset executed in {latency_ms:.3f} ms")
            return True, latency_ms

        except Exception as e:
            t1 = time.perf_counter_ns()
            latency_ms = (t1 - t0) / 1_000_000.0
            self.log("ERROR", f"QMP system_reset failed: {e}")
            return False, latency_ms

    def cold_reset_hmp(self, monitor_path: Path) -> Tuple[bool, float]:
        """
        Send QEMU Human Monitor Protocol (HMP) system_reset via UNIX socket or pipe.
        """
        t0 = time.perf_counter_ns()
        self.log("INFO", f"Executing COLD RESET via monitor: {monitor_path}")

        try:
            # Check if it's a pipe (path.in) or socket
            if monitor_path.is_fifo() or (monitor_path.parent / (monitor_path.name + ".in")).is_fifo():
                pipe_path = monitor_path if monitor_path.is_fifo() else (monitor_path.parent / (monitor_path.name + ".in"))
                with open(pipe_path, "w", encoding="utf-8") as f:
                    f.write("system_reset\n")
                    f.flush()
                t1 = time.perf_counter_ns()
                latency_ms = (t1 - t0) / 1_000_000.0
                self.log("INFO", f"HMP pipe system_reset sent in {latency_ms:.3f} ms")
                return True, latency_ms

            # UNIX domain socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect(str(monitor_path))
            sock.sendall(b"system_reset\n")
            # Give QEMU monitor time to process
            time.sleep(0.01)
            sock.close()

            t1 = time.perf_counter_ns()
            latency_ms = (t1 - t0) / 1_000_000.0
            self.log("INFO", f"HMP socket system_reset executed in {latency_ms:.3f} ms")
            return True, latency_ms

        except Exception as e:
            t1 = time.perf_counter_ns()
            latency_ms = (t1 - t0) / 1_000_000.0
            self.log("ERROR", f"HMP system_reset failed: {e}")
            return False, latency_ms

    def cold_reset(self) -> Tuple[bool, float]:
        """Execute cold reset using available QMP or Monitor configuration."""
        if self.qmp_path and self.qmp_path.exists():
            return self.cold_reset_qmp(self.qmp_path)
        if self.monitor_path and (self.monitor_path.exists() or (self.monitor_path.parent / (self.monitor_path.name + ".in")).exists()):
            return self.cold_reset_hmp(self.monitor_path)
        self.log("ERROR", "cold_reset: No accessible QMP socket or monitor path specified")
        return False, 0.0

# -----------------------------------------------------------------------------
# Checkpoint Matcher & Stream Monitor
# -----------------------------------------------------------------------------

class SerialCheckpointMatcher:
    """Matches serial lines against target checkpoints or explicit markers."""

    def __init__(self, target_spec: Optional[CheckpointSpec], custom_marker: Optional[str] = None):
        self.target_spec = target_spec
        self.custom_marker = custom_marker.strip() if custom_marker else None
        if self.custom_marker:
            self.custom_regex = re.compile(re.escape(self.custom_marker), re.IGNORECASE)
        else:
            self.custom_regex = None

    def matches(self, line: str) -> bool:
        """Evaluate if the serial line matches the target checkpoint."""
        if not line:
            return False

        clean_line = line.strip()

        # 1. Custom marker override
        if self.custom_regex:
            return bool(self.custom_regex.search(clean_line))

        if not self.target_spec:
            return False

        # 2. Checkpoint marker extraction:
        # Matches patterns like:
        #   CHECKPOINT: <name>
        #   [CHECKPOINT] <name>
        #   CHECKPOINT [<name>]
        #   AIEN_STORE_CHECKPOINT: <name>
        #   CHECKPOINT: <name> [extra parameters]
        m = re.search(r'(?:CHECKPOINT|checkpoint|STORE_CHECKPOINT)[\s:\[\]]+([^\r\n]+)', clean_line)
        if m:
            extracted = m.group(1).strip()
            # Test direct resolve on extracted token
            resolved = resolve_checkpoint(extracted)
            if resolved and resolved.canonical_id == self.target_spec.canonical_id:
                return True
            # Check normalized prefix or words
            norm_extracted = normalize_text(extracted)
            norm_target = normalize_text(self.target_spec.display_name)
            if norm_extracted.startswith(norm_target) or norm_target in norm_extracted:
                return True
            for alias in self.target_spec.aliases:
                norm_alias = normalize_text(alias)
                if norm_extracted.startswith(norm_alias) or norm_alias in norm_extracted:
                    return True

        # 3. Direct line match against aliases
        norm_line = normalize_text(clean_line)
        norm_target = normalize_text(self.target_spec.display_name)
        if f"checkpoint {norm_target}" in norm_line or norm_line == norm_target:
            return True
        for alias in self.target_spec.aliases:
            norm_alias = normalize_text(alias)
            if f"checkpoint {norm_alias}" in norm_line or norm_line == norm_alias:
                return True

        return False

# -----------------------------------------------------------------------------
# Stream Consumer & Deterministic Event Loop
# -----------------------------------------------------------------------------

def open_serial_stream(path_str: str) -> Tuple[Any, str]:
    """
    Open serial source. Supports:
      - '-' for stdin
      - Regular file (followed like tail -f)
      - FIFO pipe
      - UNIX domain socket
    Returns (handle, stream_type).
    """
    if path_str == "-" or path_str == "/dev/stdin":
        return sys.stdin, "stdin"

    p = Path(path_str)

    # Check if unix domain socket
    if p.exists() and p.is_socket():
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(p))
        return sock, "socket"

    # Check if FIFO
    if p.exists() and p.is_fifo():
        fd = os.open(str(p), os.O_RDONLY | os.O_NONBLOCK)
        f = os.fdopen(fd, "r", encoding="utf-8", errors="replace")
        return f, "fifo"

    # Regular file (wait for file creation if not yet existing)
    deadline = time.time() + 5.0
    while not p.exists() and time.time() < deadline:
        time.sleep(0.01)

    if not p.exists():
        # Create empty file so tailing can start
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch()

    f = open(p, "r", encoding="utf-8", errors="replace")
    return f, "file"

def monitor_and_act(
    serial_path: str,
    target_checkpoint: str,
    action: str,
    pid: Optional[int] = None,
    qmp_path: Optional[str] = None,
    monitor_path: Optional[str] = None,
    timeout_sec: float = 30.0,
    poll_interval: float = 0.001,
    custom_marker: Optional[str] = None,
    quiet: bool = False,
    log_file: Optional[Path] = None,
    kill_on_timeout: bool = True,
) -> ControllerResult:
    """
    Primary monitoring loop.
    Reads serial stream line by line in real time, checks for target checkpoint,
    and immediately triggers the selected action.
    """
    spec = resolve_checkpoint(target_checkpoint)
    if not spec and not custom_marker:
        raise ValueError(f"Unknown checkpoint: '{target_checkpoint}'. Run with --list-checkpoints to view valid names.")

    canonical_id = spec.canonical_id if spec else "custom_marker"
    target_name = spec.display_name if spec else (custom_marker or target_checkpoint)

    controller = QEMUController(
        pid=pid,
        qmp_path=qmp_path,
        monitor_path=monitor_path,
        quiet=quiet,
        log_file=log_file,
    )
    matcher = SerialCheckpointMatcher(target_spec=spec, custom_marker=custom_marker)

    start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    t_start = time.perf_counter()

    controller.log("INFO", "============================================================")
    controller.log("INFO", "AIENOS P3 DETERMINISTIC CRASH CONTROLLER")
    controller.log("INFO", f"Target Checkpoint : '{target_name}' (canonical: {canonical_id})")
    controller.log("INFO", f"Action Mode       : {action.upper()}")
    controller.log("INFO", f"Target PID        : {pid if pid else 'None'}")
    controller.log("INFO", f"Serial Source     : {serial_path}")
    controller.log("INFO", f"Watchdog Timeout  : {timeout_sec}s")
    controller.log("INFO", "============================================================")

    stream_handle, stream_type = open_serial_stream(serial_path)
    controller.log("INFO", f"Opened serial stream type: {stream_type}")

    buffer = ""
    result = ControllerResult(
        status="PENDING",
        checkpoint_target=target_name,
        checkpoint_canonical=canonical_id,
        checkpoint_matched_line="",
        action=action,
        qemu_pid=pid,
        start_time=start_iso,
        watchdog_timeout=timeout_sec,
    )

    checkpoint_hit = False
    matched_line = ""

    try:
        while True:
            t_now = time.perf_counter()
            elapsed = t_now - t_start

            # Watchdog timeout check
            if timeout_sec > 0 and elapsed >= timeout_sec:
                controller.log("ERROR", f"WATCHDOG TIMEOUT: checkpoint '{target_name}' not seen after {elapsed:.2f}s")
                result.status = "TIMEOUT"
                result.elapsed_seconds = elapsed
                result.error_message = f"Watchdog timeout expired ({timeout_sec}s) before checkpoint reached"
                if kill_on_timeout and pid and controller.is_pid_alive(pid):
                    controller.log("WARN", f"Killing hanging QEMU process PID {pid} due to watchdog expiration")
                    controller.hard_kill(pid)
                break

            # Read available chunks
            chunk = ""
            if stream_type == "socket":
                r, _, _ = select.select([stream_handle], [], [], poll_interval)
                if r:
                    raw = stream_handle.recv(4096)
                    if not raw:
                        # Socket closed
                        time.sleep(poll_interval)
                    else:
                        chunk = raw.decode("utf-8", errors="replace")
                else:
                    time.sleep(poll_interval)
            elif stream_type == "stdin":
                r, _, _ = select.select([stream_handle], [], [], poll_interval)
                if r:
                    chunk = stream_handle.read(4096)
                else:
                    time.sleep(poll_interval)
            else:
                # Regular file or FIFO
                chunk = stream_handle.read()
                if not chunk:
                    time.sleep(poll_interval)

            if chunk:
                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.rstrip("\r")

                    # Check for match
                    if matcher.matches(line):
                        t_trigger = time.perf_counter()
                        trigger_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                        result.elapsed_seconds = t_trigger - t_start
                        result.trigger_time = trigger_iso
                        result.checkpoint_matched_line = line
                        matched_line = line
                        checkpoint_hit = True
                        controller.log("HIT", f"CHECKPOINT OBSERVED in serial stream: '{line}' (elapsed: {result.elapsed_seconds:.4f}s)")
                        break

            if checkpoint_hit:
                break

            # Verify if QEMU died unexpectedly before reaching checkpoint
            if pid and not controller.is_pid_alive(pid):
                # Drain remaining buffer
                final_chunk = ""
                try:
                    final_chunk = stream_handle.read()
                except Exception:
                    pass
                if final_chunk:
                    buffer += final_chunk
                    for l in buffer.splitlines():
                        if matcher.matches(l):
                            t_trigger = time.perf_counter()
                            result.elapsed_seconds = t_trigger - t_start
                            result.trigger_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
                            result.checkpoint_matched_line = l
                            matched_line = l
                            checkpoint_hit = True
                            controller.log("HIT", f"CHECKPOINT OBSERVED in final drain: '{l}'")
                            break
                if checkpoint_hit:
                    break

                result.status = "ERROR"
                result.elapsed_seconds = elapsed
                result.error_message = f"Target PID {pid} died unexpectedly before checkpoint '{target_name}' was emitted"
                controller.log("ERROR", result.error_message)
                break

    finally:
        try:
            stream_handle.close()
        except Exception:
            pass

    # If checkpoint hit, execute the designated action
    if checkpoint_hit:
        t_action_start = time.perf_counter()
        act_ok = False
        latency_ms = 0.0

        if action in ("kill", "hard-kill", "hard_kill", "power-cut"):
            act_ok, latency_ms = controller.hard_kill(pid)
        elif action in ("reset", "cold-reset", "cold_reset", "system_reset"):
            act_ok, latency_ms = controller.cold_reset()
        elif action in ("clean", "clean-exit", "none", "baseline"):
            controller.log("INFO", "Clean action requested: baseline run continues uninterrupted")
            act_ok = True
            latency_ms = 0.0
        else:
            controller.log("ERROR", f"Unrecognized action mode: {action}")
            act_ok = False

        t_action_end = time.perf_counter()
        result.action_complete_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result.action_latency_ms = latency_ms if latency_ms > 0 else (t_action_end - t_action_start) * 1000.0

        if act_ok:
            result.status = "PASS"
            controller.log("INFO", f"ACTION '{action.upper()}' SUCCESSFUL (action latency: {result.action_latency_ms:.3f} ms)")
        else:
            result.status = "ERROR"
            result.error_message = f"Failed to execute action '{action}' on checkpoint hit"
            controller.log("ERROR", result.error_message)

    # Standard qualification harness output tokens
    print("\n--- CRASH CONTROLLER REPORT ---")
    print(f"CHECKPOINT_HIT: {result.checkpoint_canonical}")
    print(f"CHECKPOINT_DISPLAY: {result.checkpoint_target}")
    if result.checkpoint_matched_line:
        print(f"CHECKPOINT_RAW_LINE: {result.checkpoint_matched_line}")
    print(f"TERMINATION_MODE: {result.action}")
    print(f"EXIT_TIMING_SEC: {result.elapsed_seconds:.4f}")
    print(f"ACTION_LATENCY_MS: {result.action_latency_ms:.3f}")
    print(f"CRASH_CONTROLLER_STATUS: {result.status}")

    return result

# -----------------------------------------------------------------------------
# CLI Entrypoint
# -----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AIENOS Deterministic QEMU Crash Controller (Subagent G2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported Checkpoints:
  1.  before first write
  2.  during payload writes
  3.  after payload
  4.  during Catalog
  5.  after Catalog
  6.  during CommitRecord
  7.  before first flush
  8.  after first flush
  9.  during inactive Superblock write
  10. before final flush
  11. after final flush

Examples:
  # Hard kill immediately when 'during payload writes' is emitted:
  ./crash_controller.py --serial /tmp/serial.log --pid 12345 --checkpoint "during payload writes" --action kill

  # Cold reset via QMP socket on 'before first flush':
  ./crash_controller.py --serial /tmp/serial.log --qmp /tmp/qmp.sock --checkpoint "before first flush" --action reset

  # Clean control run:
  ./crash_controller.py --serial /tmp/serial.log --checkpoint "after final flush" --action clean
""",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # List checkpoints
    subparsers.add_parser("list-checkpoints", help="List all 11 supported checkpoints and aliases")

    # Validate checkpoint
    p_val = subparsers.add_parser("validate-checkpoint", help="Validate a checkpoint name or alias")
    p_val.add_argument("name", help="Checkpoint name to validate")

    # Watch command
    p_watch = subparsers.add_parser("watch", help="Monitor serial stream and trigger action at checkpoint")
    for p in (parser, p_watch):
        p.add_argument("-s", "--serial", help="Path to serial log, named FIFO, or unix socket (or '-' for stdin)")
        p.add_argument("-c", "--checkpoint", help="Named checkpoint to target")
        p.add_argument("-a", "--action", choices=["kill", "reset", "clean"], default="kill", help="Action to execute on hit")
        p.add_argument("-p", "--pid", type=int, help="Target QEMU process PID")
        p.add_argument("--qmp", help="Path to QEMU QMP unix domain socket (for reset)")
        p.add_argument("--monitor", help="Path to QEMU HMP monitor socket or pipe (for reset)")
        p.add_argument("-t", "--timeout", type=float, default=30.0, help="Watchdog timeout in seconds (default: 30.0)")
        p.add_argument("--poll-interval", type=float, default=0.001, help="Polling interval in seconds (default: 0.001)")
        p.add_argument("-m", "--marker", help="Explicit custom regex or text marker to override checkpoint matching")
        p.add_argument("--log-file", type=Path, help="File to append detailed controller logs to")
        p.add_argument("-o", "--json-output", type=Path, help="File to write JSON execution telemetry to")
        p.add_argument("-q", "--quiet", action="store_true", help="Quiet operational logging")
        p.add_argument("--no-kill-on-timeout", action="store_true", help="Do not kill QEMU process on watchdog timeout")

    # Trigger action standalone
    p_trig = subparsers.add_parser("trigger-action", help="Directly trigger an action without waiting for serial stream")
    p_trig.add_argument("action", choices=["kill", "reset", "clean"], help="Action to trigger")
    p_trig.add_argument("-p", "--pid", type=int, help="Target process PID")
    p_trig.add_argument("--qmp", help="Path to QMP unix socket")
    p_trig.add_argument("--monitor", help="Path to monitor socket or pipe")

    return parser

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    sub = args.subcommand

    if sub == "list-checkpoints":
        print(f"{'Idx':<4} {'Canonical ID':<35} {'Display Name':<35}")
        print("-" * 75)
        for cp in CHECKPOINTS:
            print(f"{cp.index:<4} {cp.canonical_id:<35} {cp.display_name:<35}")
            print(f"     Aliases: {', '.join(cp.aliases)}")
            print(f"     Desc   : {cp.description}")
        return 0

    if sub == "validate-checkpoint":
        resolved = resolve_checkpoint(args.name)
        if resolved:
            print(f"VALID: {resolved.canonical_id}")
            print(f"DISPLAY: {resolved.display_name}")
            print(f"INDEX: {resolved.index}")
            return 0
        else:
            print(f"INVALID: '{args.name}' is not a recognized checkpoint", file=sys.stderr)
            return 1

    if sub == "trigger-action":
        ctrl = QEMUController(
            pid=args.pid,
            qmp_path=args.qmp,
            monitor_path=args.monitor,
        )
        if args.action == "kill":
            ok, lat = ctrl.hard_kill(args.pid)
            return 0 if ok else 1
        elif args.action == "reset":
            ok, lat = ctrl.cold_reset()
            return 0 if ok else 1
        elif args.action == "clean":
            return 0

    # Default to watch mode
    if not args.serial:
        parser.error("--serial is required for monitoring")
    if not args.checkpoint and not args.marker:
        parser.error("Either --checkpoint or --marker must be specified")

    res = monitor_and_act(
        serial_path=args.serial,
        target_checkpoint=args.checkpoint or "",
        action=args.action,
        pid=args.pid,
        qmp_path=args.qmp,
        monitor_path=args.monitor,
        timeout_sec=args.timeout,
        poll_interval=args.poll_interval,
        custom_marker=args.marker,
        quiet=args.quiet,
        log_file=args.log_file,
        kill_on_timeout=not args.no_kill_on_timeout,
    )

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.json_output, "w", encoding="utf-8") as f:
            f.write(res.to_json())

    if res.status == "PASS":
        return 0
    elif res.status == "TIMEOUT":
        return 124  # Standard timeout exit code
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())
