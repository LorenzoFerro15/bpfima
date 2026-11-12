#!/usr/bin/env python3
"""Validate and decode 56-byte BPF_CHECK records in IMA ascii_runtime_measurements."""

import hashlib
import os
import struct
import sys

BPF_EVENTS = {
    "bpf_prog_load",
    "bpf_prog_unload",
    "bpf_link_attach",
    "bpf_link_update_prog",
    "bpf_link_detach",
    "bpf_link_release",
}

PROG_TYPES = {
    0: "UNSPEC", 1: "SOCKET_FILTER", 2: "KPROBE", 3: "SCHED_CLS",
    4: "SCHED_ACT", 5: "TRACEPOINT", 6: "XDP", 7: "PERF_EVENT",
    8: "CGROUP_SKB", 9: "CGROUP_SOCK", 10: "LWT_IN", 11: "LWT_OUT",
    12: "LWT_XMIT", 13: "SOCK_OPS", 14: "SK_SKB", 15: "CGROUP_DEVICE",
    16: "SK_MSG", 17: "RAW_TP", 18: "CGROUP_SOCK_ADDR", 26: "TRACING",
    27: "STRUCT_OPS", 28: "EXT", 29: "LSM", 30: "SK_LOOKUP",
    31: "SYSCALL", 32: "NETFILTER",
}

LINK_TYPES = {
    0: "NONE", 1: "RAW_TP", 2: "TRACING", 3: "CGROUP", 4: "ITER",
    5: "NETNS", 6: "XDP", 7: "PERF", 8: "KPROBE_MULTI", 9: "STRUCT_OPS",
    10: "NETFILTER", 11: "TCX", 12: "UPROBE_MULTI", 13: "NETKIT",
}

ATTACH_TYPES = {
    0: "INET_INGRESS", 1: "INET_EGRESS", 2: "INET_SOCK_CREATE",
    3: "SOCK_OPS", 6: "CGROUP_DEVICE", 8: "INET4_BIND", 9: "INET6_BIND",
    22: "TRACE_RAW_TP", 23: "TRACE_FENTRY", 24: "TRACE_FEXIT",
    25: "MODIFY_RETURN", 26: "LSM_MAC", 37: "PERF_EVENT",
}

# 56-byte struct bpf_ima_event:
# u32 prog_id, u32 prog_type, u32 attach_btf_id,
# u32 link_id, u32 link_type, u32 attach_type, u8 prog_digest[32]
EVENT_FMT_56 = "<6I32s"
assert struct.calcsize(EVENT_FMT_56) == 56

IMA_LOG_PATHS = [
    "/sys/kernel/security/integrity/ima/ascii_runtime_measurements",
    "/sys/kernel/security/ima/ascii_runtime_measurements",
]

LEGEND = """\
========================================================================================================================
BPF IMA MEASUREMENT LOG VALIDATOR - LEGEND (56-byte struct bpf_ima_event)
========================================================================================================================
  +--------+-------+----------+--------------+-------------------------------------------------------------------------+
  | Offset | Bytes | C Type   | Column       | Explanation                                                             |
  +--------+-------+----------+--------------+-------------------------------------------------------------------------+
  |  n-ng  |  var  | char[]   | EVENT        | IMA event name (bpf_prog_load/unload, bpf_link_attach/update/detach/rel)|
  |    0   |   4   | __le32   | PROG         | Kernel BPF program ID (prog->aux->id, matches `bpftool prog show`)      |
  |    4   |   4   | __le32   | PTYPE        | enum bpf_prog_type (e.g., 8:CGROUP_SKB, 17:RAW_TP, 26:TRACING, 29:LSM)  |
  |    8   |   4   | __le32   | BTF_ID       | Target kernel BTF ID for tracing/LSM hooks (0 if not applicable)        |
  |   12   |   4   | __le32   | LINK         | 0 on bpf_prog_load/unload; >0 = kernel bpf_link ID (`bpftool link`)     |
  |   16   |   4   | __le32   | LTYPE        | enum bpf_link_type (0:NONE on prog events; 1:RAW_TP, 3:CGROUP, etc.)    |
  |   20   |   4   | __le32   | ATYPE        | enum bpf_attach_type (expected_attach_type or link->attach_type)        |
  |   24   |  32   | u8[32]   | PROG_SHA256  | Canonical SHA-256 digest over (submitted insns || frozen rodata maps)   |
  +--------+-------+----------+--------------+-------------------------------------------------------------------------+
  |  --    |  --   | status   | HASH_OK      | OK if d-ng == SHA256(buf) AND IMA template hash matches (d-ng,n-ng,buf) |
  |  --    |  --   | text     | EXPLANATION  | Plain-English summary of the lifecycle transition                       |
  +--------+-------+----------+--------------+-------------------------------------------------------------------------+
========================================================================================================================
"""


def pack_template_field(raw_bytes: bytes) -> bytes:
    return struct.pack("<I", len(raw_bytes)) + raw_bytes


def verify_template_hash(
    tmpl_hash_hex: str, d_ng: str, event_name: str, buf: bytes
) -> bool:
    """Verify the IMA ima-buf template hash over (d-ng, n-ng, buf)."""
    algo, digest_hex = d_ng.split(":", 1)
    d_ng_field = f"{algo}:".encode("ascii") + b"\x00" + bytes.fromhex(digest_hex)
    n_ng_field = event_name.encode("ascii") + b"\x00"

    blob = (
        pack_template_field(d_ng_field)
        + pack_template_field(n_ng_field)
        + pack_template_field(buf)
    )

    h_algo = "sha1" if len(tmpl_hash_hex) == 40 else "sha256"
    computed = hashlib.new(h_algo, blob).hexdigest()
    return computed == tmpl_hash_hex


def explain_event(
    event_name: str, prog_id: int, ptype_name: str, link_id: int, ltype_name: str, btf_id: int
) -> str:
    btf_note = f" (btf_id={btf_id})" if btf_id else ""
    if event_name == "bpf_prog_load":
        return f"Loaded {ptype_name} prog #{prog_id}{btf_note} (unattached)"
    if event_name == "bpf_prog_unload":
        return f"Unloaded & freed {ptype_name} prog #{prog_id}"
    if event_name == "bpf_link_attach":
        return f"Attached {ptype_name} prog #{prog_id} via {ltype_name} link #{link_id}"
    if event_name == "bpf_link_update_prog":
        return f"Switched {ltype_name} link #{link_id} to {ptype_name} prog #{prog_id}"
    if event_name == "bpf_link_detach":
        return f"Explicitly detached {ltype_name} link #{link_id} (prog #{prog_id})"
    if event_name == "bpf_link_release":
        return f"Closed/released {ltype_name} link #{link_id} (prog #{prog_id})"
    return event_name


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else next(
        (p for p in IMA_LOG_PATHS if os.path.exists(p)), None
    )
    if not log_path:
        sys.exit("Error: IMA ascii_runtime_measurements not found. Pass path as argv[1].")

    records = 0
    errors = 0
    prog_digests = {}

    print(LEGEND)
    header = (
        f"{'EVENT':<20} {'PROG':>4} {'PTYPE':<19} {'BTF_ID':>6} "
        f"{'LINK':>4} {'LTYPE':<10} {'ATYPE':<18} {'PROG_SHA256':<64}  {'HASH_OK':<7}  {'EXPLANATION'}"
    )
    print(header)
    print("-" * len(header))

    with open(log_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            parts = line.strip().split()
            if len(parts) < 6:
                continue

            pcr, tmpl_hash, tmpl_name, d_ng, event_name, buf_hex = parts[:6]
            if event_name not in BPF_EVENTS:
                continue

            records += 1

            if tmpl_name != "ima-buf":
                print(f"[FAIL] line {line_no}: expected ima-buf, got {tmpl_name}")
                errors += 1
                continue

            buf = bytes.fromhex(buf_hex)
            if len(buf) != 56:
                print(f"[FAIL] line {line_no}: expected 56B buf, got {len(buf)}B")
                errors += 1
                continue

            (
                prog_id,
                prog_type,
                btf_id,
                link_id,
                link_type,
                attach_type,
                prog_digest,
            ) = struct.unpack(EVENT_FMT_56, buf)

            # 1. Verify d-ng (hash of the 56-byte buffer)
            algo, expected_buf_hash = d_ng.split(":", 1)
            actual_buf_hash = hashlib.new(algo, buf).hexdigest()
            buf_hash_ok = actual_buf_hash == expected_buf_hash

            # 2. Verify IMA template hash
            tmpl_hash_ok = verify_template_hash(tmpl_hash, d_ng, event_name, buf)

            hash_status = "OK" if (buf_hash_ok and tmpl_hash_ok) else "FAIL"
            if not (buf_hash_ok and tmpl_hash_ok):
                errors += 1

            digest_str = prog_digest.hex()
            if event_name == "bpf_prog_load":
                prog_digests[prog_id] = digest_str
            elif prog_id in prog_digests and prog_digests[prog_id] != digest_str:
                print(f"[FAIL] line {line_no}: prog_id {prog_id} digest changed mid-lifecycle!")
                errors += 1

            ptype_name = PROG_TYPES.get(prog_type, "UNKNOWN")
            ltype_name = LINK_TYPES.get(link_type, "UNKNOWN")
            if attach_type == 0 and prog_type != 8:
                atype_name = "NONE"
            else:
                atype_name = ATTACH_TYPES.get(attach_type, "OTHER")

            ptype_col = f"{prog_type}:{ptype_name}"
            ltype_col = f"{link_type}:{ltype_name}"
            atype_col = f"{attach_type}:{atype_name}"
            explanation = explain_event(
                event_name, prog_id, ptype_name, link_id, ltype_name, btf_id
            )

            print(
                f"{event_name:<20} {prog_id:>4} {ptype_col:<19} {btf_id:>6} "
                f"{link_id:>4} {ltype_col:<10} {atype_col:<18} {digest_str:<64}  {hash_status:<7}  {explanation}"
            )
            if not buf_hash_ok:
                print(f"      -> [FAIL] d-ng hash mismatch: computed {actual_buf_hash} != {expected_buf_hash}")
            if not tmpl_hash_ok:
                print(f"      -> [FAIL] IMA template hash mismatch on line {line_no}")

    print("-" * len(header))
    print(f"Validated {records} BPF IMA records with {errors} error(s).")
    sys.exit(1 if errors or records == 0 else 0)


if __name__ == "__main__":
    main()
