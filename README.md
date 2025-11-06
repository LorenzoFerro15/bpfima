# bpfima

eBPF-based integrity monitoring system with container tracking, Merkle tree verification, and TPM integration.

## Overview

This system monitors file operations and container events using eBPF LSM and kprobe hooks. Measurements are organized per-container in a Merkle tree structure, with the root hash extended to TPM PCR 23 for hardware-backed attestation.

## Directory Structure

```
bpfima/
├── build/              # Build output (auto-generated)
├── hooks/              # eBPF hook implementations
│   ├── kprobe/         # Kprobe hooks
│   └── lsm/            # LSM hooks
├── include/            # Header files
├── src/                # Kernel module source (modular)
├── scripts/            # Test scripts
├── templates/          # Code templates
├── utils/              # Utility headers
├── loader.c            # eBPF program loader
└── Makefile            # Build system
```

## Components

### eBPF Hooks
- `lsm_container_events.c` - Container lifecycle tracking
- `lsm_bprm_check_security.c` - Process execution monitoring
- `lsm_file_open.c` / `lsm_file_post_open.c` - File access monitoring
- `lsm_mmap_file.c` - Memory-mapped file monitoring
- `lsm_socket_connect.c` - Network connection monitoring
- `kprobe_file_open.c` - Alternative file open tracking

### Kernel Module
The module provides custom BPF kfuncs and manages:
- Container tracking with per-container measurement lists
- Merkle tree with SHA-256 hashing
- TPM PCR 23 extensions
- SecurityFS interface at `/sys/kernel/security/bpfima/`

### Loader
Generic userspace loader that automatically attaches eBPF programs (LSM, kprobe, tracepoint, fentry/fexit).

## Build

Requirements:
- Linux kernel 5.8+ with BPF LSM enabled
- clang, llvm, libbpf-devel, elfutils-libelf-devel, zlib-devel
- kernel-devel, kernel-debuginfo (for BTF)

```bash
# Install dependencies (Fedora)
sudo dnf install kernel-devel libbpf-devel elfutils-libelf-devel zlib-devel clang llvm
sudo dnf debuginfo-install kernel

# Build
make all
```

Output: `build/bpfima.ko`, `build/loader`, `build/*.o`

## Usage

### Testing

```bash
# script helper
./scripts/test.sh --help

# verbose mode
sudo ./scripts/test.sh --verbose

# Test hook
sudo ./scripts/test.sh lsm_bprm_check_security 

# Validation mode
sudo ./scripts/test.sh --validate
```

### Manual

```bash
# Load kernel module
sudo insmod build/bpfima.ko

# Attach eBPF program
sudo ./build/loader lsm_bprm_check_security

# View trace output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Cleanup
sudo rmmod bpfima
```

## SecurityFS Interface

```
/sys/kernel/security/bpfima/
├── merkle_root              # Current Merkle tree root hash
├── measurements             # Global measurement list
├── container_list           # Tracked containers
└── containers/
    └── <container_id>/
        └── measurements     # Per-container measurements
```

Read example:
```bash
cat /sys/kernel/security/bpfima/merkle_root
cat /sys/kernel/security/bpfima/containers/*/measurements
```

## Architecture

The system uses 6 communication channels between eBPF and kernel:

1. Kfunc: `bpf_container_create_or_get()` - Container registration
2. Kfunc: `bpf_container_add_measurement()` - Add measurement entry
3. Kfunc: `bpf_get_merkle_root()` - Read current root hash
4. BPF Map: Statistics counters
5. BPF Map: Active container LRU cache
6. Ring Buffer: Asynchronous event notifications

Merkle tree structure:
```
        Root Hash (PCR 23)
        /      |      \
   Leaf1    Leaf2    Leaf3
     /         |         \
[Container1][Container2][Container3]
```

Each leaf hash is computed from a container's measurement list. Root hash updates extend TPM PCR 23.

## Measurement Flow

When an event is detected by an eBPF hook:

1. **Get namespace** - Extract container ID from task's cgroup namespace
2. **Measure** - Compute hash of the event data (file path, process, etc.)
3. **Record in list** - Add measurement entry to container's measurement list
4. **Extend leaf** - Recompute container's leaf hash from updated measurement list
5. **Add to history** - Store measurement in global history list
6. **Extend root** - Recompute Merkle root hash from all leaf hashes
7. **Extend PCR** - Extend TPM PCR 23 with new root hash

This ensures each measurement is both container-specific and contributes to the global integrity state backed by hardware.

## Troubleshooting

**Missing BTF**: Install kernel-debuginfo and create vmlinux symlink
```bash
sudo dnf debuginfo-install kernel
sudo ln -sf $(find /usr/lib/debug -name vmlinux -type f | head -1) /lib/modules/$(uname -r)/build/vmlinux
```

**Module load fails**: Check dmesg for errors
```bash
sudo dmesg | tail -20
```

**No trace output**: Verify program attachment
```bash
sudo bpftool prog list
sudo cat /sys/kernel/debug/tracing/trace
```