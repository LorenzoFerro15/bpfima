# bpfima

eBPF-based integrity monitoring system with container tracking, Merkle tree verification, TPM integration, and **policy-based configuration**.

## Overview

This system monitors file operations and container events using eBPF LSM and kprobe hooks. Measurements are organized per-container in a Merkle tree structure, with the root hash extended to TPM PCR 23 for hardware-backed attestation.

**NEW:** Policy-based configuration system allows fine-grained control over what gets measured, filtered, and how events are processed - configured via BPF maps and enforced at the kernel level.

## Directory Structure

```
bpfima/
├── build/              # Build output (auto-generated)
├── hooks/              # eBPF hook implementations
│   └── lsm/            # LSM hooks
├── include/            # Header files
├── src/                # Kernel module source (modular)
├── scripts/            # Test scripts
├── tools/              # Userspace tools (policy_init)
├── utils/              # Utility headers
├── loader.c            # eBPF program loader
└── Makefile            # Build system
```

## Components

### eBPF Hooks
- `lsm_container_events.c` - Container lifecycle tracking
- `lsm_bprm_check_security.c` - Process execution monitoring (policy-enabled)
- `lsm_file_open.c` / `lsm_file_post_open.c` - File access monitoring (policy-enabled)
- `lsm_mmap_file.c` - Memory-mapped file monitoring
- `lsm_socket_connect.c` - Network connection monitoring

### Kernel Module
The module provides custom BPF kfuncs and manages:
- Container tracking with per-container measurement lists
- Merkle tree with SHA-256 hashing
- TPM PCR 23 extensions
- **Policy management and enforcement**
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
# 1. Load kernel module
sudo insmod build/bpfima.ko

# 2. Attach eBPF program (automatically pins policy maps)
sudo ./build/loader build/lsm_bprm_check_security.o &

# 3. Initialize policy maps (REQUIRED!)
sudo ./build/policy_init

# 4. View trace output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# 5. Check measurements
sudo cat /sys/kernel/security/bpfima/status

# Cleanup
sudo pkill loader
sudo rmmod bpfima
```

**Note:** Step 3 (policy_init) is essential! Without it, policy maps remain empty and the system uses restrictive hardcoded fallbacks that filter out most activity.

## SecurityFS Interface

```
/sys/kernel/security/bpfima/
├── merkle_root              # Current Merkle tree root hash
├── measurements             # Global measurement list
├── status                   # Module status and configuration
├── container_list           # Tracked containers
└── containers/
    └── <container_id>/
        └── measurements     # Per-container measurements
```

Read example:
```bash
cat /sys/kernel/security/bpfima/merkle_root
cat /sys/kernel/security/bpfima/status
cat /sys/kernel/security/bpfima/containers/*/measurements
```

## Policy Configuration

BPF IMA uses a policy system to control what gets measured and how:

### Architecture

- **BPF Maps**: Store policy configuration in pinned BPF maps at `/sys/fs/bpf/`
- **Kernel Enforcement**: Policies enforced in eBPF hooks (secure, fast, kernel-level)
- **Userspace Init**: `policy_init` tool populates maps with default values

### Default Policy (as configured by policy_init)

**What Gets Measured:**
- Executable binaries
- Scripts and interpreted code
- Container workloads (Docker, Podman)
- User processes (user.slice)
- System services (system.slice)
- Files in /dev/, /tmp/
- Shared libraries (.so)

**What Gets Filtered (too noisy):**
- Files in /proc/
- Files in /sys/
- Root cgroup `/`
- init.scope processes

**Actions Enabled:**
- TPM PCR 23 extension
- SecurityFS logging
- Kernel log output
- Per-container tracking
- Dependency chain building

### Policy Configuration Options

The policy system supports:

1. **Filter Flags** - Control what to skip/ignore:
   ```c
   POLICY_FILTER_SYSTEM_CGROUPS   // Skip init.scope, system.slice
   POLICY_FILTER_PROC_SYS         // Skip /proc/, /sys/
   POLICY_FILTER_DEV              // Skip /dev/
   POLICY_FILTER_READONLY_FILES   // Skip readonly opens
   POLICY_FILTER_SMALL_FILES      // Skip files below min size
   POLICY_FILTER_NON_EXECUTABLE   // Skip non-executable files
   POLICY_FILTER_LIBRARIES        // Skip .so files
   POLICY_FILTER_TMP_FILES        // Skip /tmp/ files
   ```

2. **Action Flags** - Control what actions to take:
   ```c
   POLICY_ACTION_EXTEND_TPM       // Extend measurements to TPM
   POLICY_ACTION_LOG_SECURITYFS   // Log to securityfs
   POLICY_ACTION_LOG_KERNEL       // Log to kernel (printk)
   POLICY_ACTION_ALERT_SUSPICIOUS // Alert on suspicious activity
   POLICY_ACTION_BLOCK            // Block operations (future)
   POLICY_ACTION_TRACK_CONTAINER  // Track per-container
   POLICY_ACTION_BUILD_DEPS       // Build dependency chains
   ```

3. **Pattern Matching** - Ignore specific cgroups or paths:
   - Cgroup patterns: Exact match on cgroup names
   - Path patterns: Prefix match on file paths

4. **Per-Hook Configuration**:
   - Enable/disable individual hooks
   - Track containers per-hook
   - Enable/disable hash calculation

5. **Runtime Settings**:
   - Log level (0=none, 1=errors, 2=info, 3=debug)
   - Minimum file size threshold
   - Maximum path depth

### Customizing Policy

There are three ways to customize the policy:

#### 1. Edit policy_init.c (Recommended)

Modify `tools/policy_init.c` to change default values:

```c
struct bpfima_policy_config policy = {
    .enabled = 1,
    .filter_flags = POLICY_FILTER_PROC_SYS | POLICY_FILTER_DEV,  // Add more filters
    .action_flags = POLICY_ACTION_EXTEND_TPM | POLICY_ACTION_LOG_SECURITYFS,
    .min_file_size = 1024,      // Only measure files > 1KB
    .max_path_depth = 32,
    .log_level = 3,             // Debug level
};
```

Rebuild and run:
```bash
make build/policy_init
sudo ./build/policy_init
```

#### 2. Use bpftool (Runtime)

Directly update BPF maps at runtime:

```bash
# View current policy
sudo bpftool map dump pinned /sys/fs/bpf/bpfima_policy_map

# Update filter flags (example: add DEV filter)
sudo bpftool map update pinned /sys/fs/bpf/bpfima_policy_map \
    key 0 0 0 0 value 1 6 0 0 ...  # Complex, see bpftool docs

# Add a new cgroup ignore pattern
sudo bpftool map update pinned /sys/fs/bpf/bpfima_cgroup_patterns_map \
    key 4 0 0 0 value ...
```

#### 3. Kernel Module Headers (Build-time)

Edit default values in `include/bpfima_policy.h`:

```c
#define DEFAULT_FILTER_FLAGS (POLICY_FILTER_PROC_SYS | POLICY_FILTER_DEV)
#define DEFAULT_ACTION_FLAGS (POLICY_ACTION_EXTEND_TPM | ...)
#define DEFAULT_LOG_LEVEL 2
```

Rebuild the kernel module:
```bash
make clean && make all
```

### Verifying Policy

Check current policy status:

```bash
# View policy configuration
sudo bpftool map dump pinned /sys/fs/bpf/bpfima_policy_map

# Check which hooks are enabled
sudo bpftool map dump pinned /sys/fs/bpf/bpfima_hook_config_map

# View measurements (verify things are being recorded)
sudo cat /sys/kernel/security/bpfima/status

# Check kernel logs for policy messages
sudo dmesg | grep -i bpfima | grep -i policy
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