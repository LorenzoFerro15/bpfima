# bpfima

eBPF-based integrity monitoring system with container tracking, Merkle tree verification, TPM integration, and **policy-based configuration**.

## Overview

This system monitors file operations and container events using eBPF LSM and kprobe hooks. Measurements are organized per-container in a Merkle tree structure, with the root hash extended to a configurable TPM PCR (default: PCR 23) for hardware-backed attestation.

**NEW:** Policy-based configuration system allows fine-grained control over what gets measured, filtered, and how events are processed - configured via BPF maps and enforced at the kernel level.

## Directory Structure

```
bpfima/
├── build/              # Build output (auto-generated)
├── config/             # Policy configuration files
├── hooks/              # eBPF hook implementations
│   └── lsm/            # LSM hooks
├── include/            # Header files
├── src/                # Kernel module source (modular)
├── scripts/            # Test scripts
├── tools/              # Userspace management tool (bpfima-tool)
├── config/             # YAML policy configuration files
├── utils/              # Utility headers
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
- TPM PCR extensions (configurable index, default: 23)
- **Policy management and enforcement**
- SecurityFS interface at `/sys/kernel/security/bpfima/`

### Management Tool (bpfima-tool)
Unified userspace tool that handles:
- Loading and attaching eBPF programs (LSM, kprobe, tracepoint, fentry/fexit)
- Policy initialization and management
- System status monitoring
- Daemon mode for background operation

## Build

Requirements:
- Linux kernel 5.8+ with BPF LSM enabled
- clang, llvm, libbpf-devel, elfutils-libelf-devel, zlib-devel
- kernel-devel, kernel-debuginfo (for BTF)

```bash
# Install dependencies (Fedora)
sudo dnf install kernel-devel libbpf-devel elfutils-libelf-devel zlib-devel clang llvm libyaml-devel
sudo dnf debuginfo-install kernel

# Build
make all
```

Output: `build/bpfima.ko`, `build/bpfima-tool`, `build/*.o`

### Python Dependencies

For running performance tests and generating graphs:

```bash
sudo pip3 install matplotlib pandas seaborn
```


## Usage

### Testing

```bash
# Script helper
./scripts/test.sh --help

# Verbose mode
sudo ./scripts/test.sh -v

# Test specific hook
sudo ./scripts/test.sh lsm_bprm_check_security -v
```

### Manual

```bash
# 1. Load kernel module
sudo insmod build/bpfima.ko

# Optional: Configure TPM PCR index (default: 23)
# sudo insmod build/bpfima.ko tpm_pcr_index=10

# 2. Load eBPF program (daemon mode)
sudo ./build/bpfima-tool load build/lsm_bprm_check_security.o -d

# 3. Initialize policy maps (REQUIRED!)
sudo ./build/bpfima-tool policy-init

# 4. Check status
sudo ./build/bpfima-tool status

# 5. View measurements
sudo cat /sys/kernel/security/bpfima/status

# Cleanup
sudo ./build/bpfima-tool unload
sudo rmmod bpfima
```

**Note:** The unified `bpfima-tool` replaces the old separate `loader` and `policy_init` utilities.

## Module Parameters

The bpfima kernel module supports the following runtime parameters:

### TPM PCR Index

Configure which TPM PCR (Platform Configuration Register) to use for measurements:

```bash
# Load with custom PCR index
sudo insmod build/bpfima.ko tpm_pcr_index=10

# View current PCR index
cat /sys/module/bpfima/parameters/tpm_pcr_index

# Change at runtime (if module was loaded with writable permissions)
echo 15 | sudo tee /sys/module/bpfima/parameters/tpm_pcr_index
```

**Default:** PCR 23 (commonly used for custom measurements)  
**Valid range:** 0-23 (most TPMs)  
**Note:** PCR 0-15 are typically reserved for BIOS/bootloader. PCR 16-23 are available for OS and application use.

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
- **Userspace Management**: `bpfima-tool` manages policies (init defaults or load from YAML)
- **YAML Configuration**: Policies can be defined in `config/*.yaml` files

### Default Policy

**What Gets Measured:**
- Executable binaries
- Scripts and interpreted code
- Container workloads (Docker, Podman)
- User processes (user.slice)
- System services (system.slice)
- Files in /dev/, /tmp/
- Shared libraries (.so)
- **Everything except the minimal filters below**

**What Gets Filtered (minimal - only truly noisy system internals):**
- Root cgroup `/` (exact match only)
- init.scope processes

**Optional Filters (disabled by default, can be enabled via policy):**
- Files in /proc/ (enable with POLICY_FILTER_PROC_SYS)
- Files in /sys/ (enable with POLICY_FILTER_PROC_SYS)
- System cgroups (enable with POLICY_FILTER_SYSTEM_CGROUPS)
- /dev/ files (enable with POLICY_FILTER_DEV)
- Small files (enable with POLICY_FILTER_SMALL_FILES)
- Libraries (enable with POLICY_FILTER_LIBRARIES)
- /tmp/ files (enable with POLICY_FILTER_TMP_FILES)

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
   POLICY_FILTER_SYSTEM_CGROUPS   // Skip /, init.scope (already minimal by default)
   POLICY_FILTER_PROC_SYS         // Skip /proc/, /sys/ (disabled by default)
   POLICY_FILTER_DEV              // Skip /dev/ (disabled by default)
   POLICY_FILTER_READONLY_FILES   // Skip readonly opens (disabled by default)
   POLICY_FILTER_SMALL_FILES      // Skip files below min size (disabled by default)
   POLICY_FILTER_NON_EXECUTABLE   // Skip non-executable files (disabled by default)
   POLICY_FILTER_LIBRARIES        // Skip .so files (disabled by default)
   POLICY_FILTER_TMP_FILES        // Skip /tmp/ files (disabled by default)
   ```
   
   **Default: ALL filters disabled (0x0) - tracks everything except / and init.scope**

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

#### 1. Use YAML Configuration Files (Recommended)

Edit `config/policy.yaml` or `config/policy-minimal.yaml`:

```yaml
policy:
  enabled: true
  log_level: 2
  measure_enabled: true
  appraise_enabled: false
  enforce_enabled: false
  container_tracking: true

filters:
  cgroup_patterns:
    - "/system.slice/"
    - "/docker/"
  path_patterns:
    - "/usr/bin/"
    - "/usr/sbin/"

hooks:
  - name: "lsm_bprm_check_security"
    enabled: true
    measure: true
```

Load the policy:
```bash
sudo ./build/bpfima-tool policy-update config/policy.yaml
```

#### 2. Use SecurityFS Interface (Runtime)

#### 2. Use SecurityFS Interface (Runtime)

Update policy through the securityfs interface:

```bash
# View current policy
cat /sys/kernel/security/bpfima/policy

# Update individual settings
echo "log_level=3" | sudo tee /sys/kernel/security/bpfima/policy
echo "filter_flags=0x7" | sudo tee /sys/kernel/security/bpfima/policy
echo "action_flags=0x1F" | sudo tee /sys/kernel/security/bpfima/policy
echo "min_file_size=4096" | sudo tee /sys/kernel/security/bpfima/policy
```

#### 3. Use bpftool (Advanced)

Directly update BPF maps at runtime (advanced users):

```bash
# View current policy
sudo bpftool map dump pinned /sys/fs/bpf/bpfima_policy_map

# Update with bpftool (requires knowledge of struct layout)
sudo bpftool map update pinned /sys/fs/bpf/bpfima_policy_map \
    key 0 0 0 0 value 1 6 0 0 ...
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