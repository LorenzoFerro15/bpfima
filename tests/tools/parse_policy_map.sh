#!/usr/bin/env bash
#
# parse_bpfima_map.sh - Parse bpfima_policy_map via Python
# Not yet a fully automated test, can be useful to manually inspect the content of the eBPF map
# Usage:
#   ./parse_bpfima_map.sh                              # Reads live from /sys/fs/bpf/bpfima_policy_map
#   ./parse_bpfima_map.sh /path/to/pinned/map          # Reads live from custom pinned path
#   ./parse_bpfima_map.sh dump.txt                     # Parses saved plain-text or JSON dump file

set -euo pipefail

TARGET="${1:-/sys/fs/bpf/bpfima_policy_map}"

# Pass the target path directly to Python as an argument
python3 - "$TARGET" << 'EOF'
import sys
import re
import json
import subprocess
import os
import ctypes

target = sys.argv[1]

raw_input = ""
if target == "-":
    raw_input = sys.stdin.read()
elif os.path.isfile(target) and not target.startswith("/sys/fs/bpf/"):
    with open(target, "r", encoding="utf-8", errors="replace") as f:
        raw_input = f.read()
else:
    # Try running bpftool with JSON first
    res = subprocess.run(["sudo", "bpftool", "map", "dump", "pinned", target, "-j"], capture_output=True, text=True)
    if res.returncode != 0 or not res.stdout.strip():
        # Fallback to plain text bpftool dump
        res = subprocess.run(["sudo", "bpftool", "map", "dump", "pinned", target], capture_output=True, text=True)

    raw_input = res.stdout

raw_input = raw_input.strip()
if not raw_input:
    sys.exit(f"Error: No data found for target '{target}'. Check if the map exists and requires root.")

# --- ABI Constants ---
MAX_PATTERN_LEN = 64
MAX_IGNORE_PATTERNS = 8
MAX_PATH_FILTERS = 8
HOOK_MAX = 8
BPFIMA_NAMESPACE_SIZE = 128
BPFIMA_POLICY_NAMESPACES = 32

HOOK_NAMES = [
    "HOOK_LSM_BPRM_CHECK_SECURITY",
    "HOOK_LSM_FILE_OPEN",
    "HOOK_LSM_FILE_POST_OPEN",
    "HOOK_LSM_MMAP_FILE",
    "HOOK_LSM_SOCKET_CONNECT",
    "HOOK_LSM_CONTAINER_EVENTS",
    "HOOK_KPROBE_FILE_OPEN",
    "HOOK_LSM_INODE_SETATTR",
]

MATCH_TYPES = {0: "exact", 1: "prefix", 2: "suffix", 3: "contains"}
LOG_LEVELS = {0: "none", 1: "errors", 2: "info", 3: "debug"}
SCOPES = {0: "global", 1: "root-only"}

# --- C Struct Definitions ---
class PatternEntry(ctypes.LittleEndianStructure):
    _fields_ = [
        ("pattern", ctypes.c_char * MAX_PATTERN_LEN),
        ("enabled", ctypes.c_uint8),
        ("match_type", ctypes.c_uint8),
        ("reserved", ctypes.c_uint16),
    ]

class HookConfig(ctypes.LittleEndianStructure):
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("filter_override", ctypes.c_uint32),
        ("action_override", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32 * 1),
    ]

class PolicyConfig(ctypes.LittleEndianStructure):
    _fields_ = [
        ("enabled", ctypes.c_uint8),
        ("filter_flags", ctypes.c_uint32),
        ("action_flags", ctypes.c_uint32),
        ("min_file_size", ctypes.c_uint32),
        ("max_path_depth", ctypes.c_uint32),
        ("log_level", ctypes.c_uint32),
        ("merkle_history_max_size", ctypes.c_uint32),
        ("merkle_history_scope", ctypes.c_uint8),
        ("reserved", ctypes.c_uint32 * 1),
    ]

class PolicySnapshot(ctypes.LittleEndianStructure):
    _fields_ = [
        ("config", PolicyConfig),
        ("cgroups", PatternEntry * MAX_IGNORE_PATTERNS),
        ("paths", PatternEntry * MAX_PATH_FILTERS),
        ("hooks", HookConfig * HOOK_MAX),
    ]

class PolicyRecord(ctypes.LittleEndianStructure):
    _fields_ = [
        ("namespace_id", ctypes.c_char * BPFIMA_NAMESPACE_SIZE),
        ("snapshot", PolicySnapshot),
    ]

class PolicyState(ctypes.LittleEndianStructure):
    _fields_ = [
        ("generation", ctypes.c_uint64),
        ("namespace_count", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("records", PolicyRecord * (BPFIMA_POLICY_NAMESPACES + 1)),
    ]

def c_str(val):
    if isinstance(val, (bytes, bytearray)):
        return val.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    if isinstance(val, list):
        b = bytes([x & 0xFF if isinstance(x, int) else int(str(x), 0) for x in val])
        return b.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return str(val).rstrip("\x00")

def print_state_ctypes(key_int, state):
    role = key_int
    print("=" * 72)
    print(f"MAP KEY [{key_int}] - {role}")
    print(f"  Generation:      {state.generation}")
    print(f"  Namespace Count: {state.namespace_count}")
    print("=" * 72)

    if state.generation == 0 and state.namespace_count == 0 and key_int != 0:
        print("  (Empty / Uninitialized State)\n")
        return

    limit = min(state.namespace_count + 1, BPFIMA_POLICY_NAMESPACES + 1)
    for idx in range(limit):
        rec = state.records[idx]
        ns_id = c_str(rec.namespace_id)
        cfg = rec.snapshot.config

        if idx > 0 and not ns_id and not cfg.enabled:
            continue

        label = ns_id if ns_id else ("<default/cluster-wide>" if idx == 0 else "<empty>")
        print(f"\n  Record [{idx}] Namespace: {label}")
        print(f"    Config:")
        print(f"      Enabled:                 {bool(cfg.enabled)} ({cfg.enabled})")
        print(f"      Filter Flags:            0x{cfg.filter_flags:08x}")
        print(f"      Action Flags:            0x{cfg.action_flags:08x}")
        print(f"      Min File Size:           {cfg.min_file_size} bytes")
        print(f"      Max Path Depth:          {cfg.max_path_depth}")
        print(f"      Log Level:               {cfg.log_level} ({LOG_LEVELS.get(cfg.log_level, 'unknown')})")
        print(f"      Merkle History Max Size: {cfg.merkle_history_max_size}")
        print(f"      Merkle History Scope:    {cfg.merkle_history_scope} ({SCOPES.get(cfg.merkle_history_scope, 'unknown')})")

        active_cgroups = [(i, p) for i, p in enumerate(rec.snapshot.cgroups) if p.enabled or c_str(p.pattern)]
        if active_cgroups:
            print("    Cgroup Ignore Patterns:")
            for i, p in active_cgroups:
                m_str = MATCH_TYPES.get(p.match_type, f"unknown({p.match_type})")
                print(f"      [{i}] pattern=\"{c_str(p.pattern)}\" | enabled={bool(p.enabled)} | match={m_str}")

        active_paths = [(i, p) for i, p in enumerate(rec.snapshot.paths) if p.enabled or c_str(p.pattern)]
        if active_paths:
            print("    Path Filters:")
            for i, p in active_paths:
                m_str = MATCH_TYPES.get(p.match_type, f"unknown({p.match_type})")
                print(f"      [{i}] pattern=\"{c_str(p.pattern)}\" | enabled={bool(p.enabled)} | match={m_str}")

        active_hooks = [
            (i, h) for i, h in enumerate(rec.snapshot.hooks)
            if h.flags != 0 or h.filter_override != 0 or h.action_override != 0
        ]
        if active_hooks:
            print("    Hook Overrides:")
            for i, h in active_hooks:
                h_name = HOOK_NAMES[i] if i < len(HOOK_NAMES) else f"HOOK_{i}"
                print(f"      [{i}] {h_name}: flags=0x{h.flags:08x}, filter_ovr=0x{h.filter_override:08x}, action_ovr=0x{h.action_override:08x}")
    print()

def print_state_btf_dict(key_int, val_dict):
    role = key_int
    gen = val_dict.get("generation", 0)
    ns_cnt = val_dict.get("namespace_count", 0)
    print("=" * 72)
    print(f"MAP KEY [{key_int}] - {role} (Parsed from BTF JSON)")
    print(f"  Generation:      {gen}")
    print(f"  Namespace Count: {ns_cnt}")
    print("=" * 72)

    records = val_dict.get("records", [])
    limit = min(ns_cnt + 1, len(records))
    for idx in range(limit):
        rec = records[idx]
        ns_id = c_str(rec.get("namespace_id", ""))
        snap = rec.get("snapshot", {})
        cfg = snap.get("config", {})

        if idx > 0 and not ns_id and not cfg.get("enabled", 0):
            continue

        label = ns_id if ns_id else ("<default/cluster-wide>" if idx == 0 else "<empty>")
        print(f"\n  Record [{idx}] Namespace: {label}")
        print(f"    Config:")
        print(f"      Enabled:                 {bool(cfg.get('enabled', 0))} ({cfg.get('enabled', 0)})")
        print(f"      Filter Flags:            0x{cfg.get('filter_flags', 0):08x}")
        print(f"      Action Flags:            0x{cfg.get('action_flags', 0):08x}")
        print(f"      Min File Size:           {cfg.get('min_file_size', 0)} bytes")
        print(f"      Max Path Depth:          {cfg.get('max_path_depth', 0)}")
        ll = cfg.get("log_level", 0)
        print(f"      Log Level:               {ll} ({LOG_LEVELS.get(ll, 'unknown')})")
        print(f"      Merkle History Max Size: {cfg.get('merkle_history_max_size', 0)}")
        sc = cfg.get("merkle_history_scope", 0)
        print(f"      Merkle History Scope:    {sc} ({SCOPES.get(sc, 'unknown')})")
    print()

def parse_bytes_to_state(key_bytes, val_bytes):
    if len(key_bytes) == 4:
        key_int = int.from_bytes(key_bytes, byteorder="little")
    else:
        key_int = int(key_bytes[0]) if key_bytes else 0

    expected = ctypes.sizeof(PolicyState)
    if len(val_bytes) < expected:
        val_bytes = val_bytes.ljust(expected, b"\x00")

    state = PolicyState.from_buffer_copy(val_bytes)
    print_state_ctypes(key_int, state)

# --- Parsing Execution ---
try:
    data = json.loads(raw_input)
    if isinstance(data, dict):
        data = [data]
    for item in data:
        if "formatted" in item and isinstance(item["formatted"].get("value"), dict):
            k = item["formatted"].get("key", 0)
            print_state_btf_dict(int(k), item["formatted"]["value"])
        elif isinstance(item.get("value"), dict):
            k = item.get("key", 0)
            print_state_btf_dict(int(k), item["value"])
        else:
            k_list = item.get("key", [])
            v_list = item.get("value", [])
            k_bytes = bytes([int(x, 16) if isinstance(x, str) else int(x) for x in k_list]) if isinstance(k_list, list) else int(k_list).to_bytes(4, "little")
            v_bytes = bytes([int(x, 16) if isinstance(x, str) else int(x) for x in v_list])
            parse_bytes_to_state(k_bytes, v_bytes)
    sys.exit(0)
except json.JSONDecodeError:
    pass

# Plain text fallback
if "key:" in raw_input and "value:" in raw_input:
    blocks = re.split(r"(?=^key:\s*)", raw_input, flags=re.MULTILINE)
    for block in blocks:
        if not block.strip():
            continue
        parts = re.split(r"\bvalue:\s*", block, maxsplit=1)
        if len(parts) != 2:
            continue
        key_part, val_part = parts
        val_part = re.sub(r"^Found \d+ elements.*$", "", val_part, flags=re.MULTILINE)

        k_hex = re.findall(r"\b[0-9a-fA-F]{2}\b", key_part)
        v_hex = re.findall(r"\b[0-9a-fA-F]{2}\b", val_part)

        if k_hex and v_hex:
            k_bytes = bytes([int(x, 16) for x in k_hex])
            v_bytes = bytes([int(x, 16) for x in v_hex])
            parse_bytes_to_state(k_bytes, v_bytes)
    sys.exit(0)

print("Raw input output:")
print(raw_input)
EOF
