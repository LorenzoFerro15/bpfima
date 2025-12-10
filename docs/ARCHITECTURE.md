# BPF IMA Architecture

## Overview

BPF IMA is an eBPF-based integrity monitoring system that provides runtime integrity measurement and attestation for Linux systems. It combines eBPF hooks, a kernel module with custom kfuncs, and userspace management tools to track file operations, container lifecycles, and system events, storing measurements in a Merkle tree backed by TPM hardware.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Space                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ bpfima-tool  │  │ Test Scripts │  │ Monitoring Tools     │  │
│  │              │  │              │  │ (read securityfs)    │  │
│  │ - load/unload│  │ - test.sh    │  │                      │  │
│  │ - policy mgmt│  │ - validation │  │                      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                  │                     │               │
│         └──────────────────┼─────────────────────┘               │
│                            │                                     │
└────────────────────────────┼─────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │   libbpf API    │
                    └────────┬────────┘
═════════════════════════════╪══════════════════════════════════════
                             │  Kernel Space
┌────────────────────────────┼─────────────────────────────────────┐
│                            │                                      │
│  ┌─────────────────────────▼───────────────────────────────┐     │
│  │              BPF Maps (pinned to /sys/fs/bpf/)           │     │
│  │  - bpfima_policy_map                                     │     │
│  │  - bpfima_hook_config_map                                │     │
│  │  - bpfima_cgroup_patterns_map                            │     │
│  │  - bpfima_path_patterns_map                              │     │
│  └────────────────┬─────────────────────────────────────────┘     │
│                   │                                               │
│  ┌────────────────▼──────────────────────────────────────────┐   │
│  │              eBPF Programs (LSM Hooks)                     │   │
│  │                                                            │   │
│  │  ┌──────────────────┐  ┌──────────────────┐              │   │
│  │  │ lsm_bprm_check   │  │ lsm_file_post    │              │   │
│  │  │ _security        │  │ _open            │              │   │
│  │  │ (exec monitor)   │  │ (file access)    │              │   │
│  │  └────────┬─────────┘  └────────┬─────────┘              │   │
│  │           │                      │                        │   │
│  │  ┌────────▼─────────┐  ┌────────▼─────────┐              │   │
│  │  │ lsm_mmap_file    │  │ Other LSM Hooks  │              │   │
│  │  │ (mmap monitor)   │  │ (socket, etc.)   │              │   │
│  │  └────────┬─────────┘  └────────┬─────────┘              │   │
│  │           │                      │                        │   │
│  │           └──────────┬───────────┘                        │   │
│  │                      │                                    │   │
│  └──────────────────────┼────────────────────────────────────┘   │
│                         │                                        │
│            ┌────────────▼────────────┐                           │
│            │   BPF Helper Calls      │                           │
│            └────────────┬────────────┘                           │
│                         │                                        │
│  ┌──────────────────────▼──────────────────────────────────┐    │
│  │         bpfima Kernel Module (Custom kfuncs)             │    │
│  │                                                          │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │  Container Tracking                              │    │    │
│  │  │  - Detect container creation/destruction         │    │    │
│  │  │  - Track per-container namespaces                │    │    │
│  │  │  - Maintain per-container measurement lists      │    │    │
│  │  └──────────────────┬───────────────────────────────┘    │    │
│  │                     │                                     │    │
│  │  ┌──────────────────▼──────────────────────────────┐    │    │
│  │  │  Measurement Engine                              │    │    │
│  │  │  - Hash file contents (SHA-256)                  │    │    │
│  │  │  - Create measurement entries                    │    │    │
│  │  │  - Apply policy filters                          │    │    │
│  │  └──────────────────┬───────────────────────────────┘    │    │
│  │                     │                                     │    │
│  │  ┌──────────────────▼──────────────────────────────┐    │    │
│  │  │  Merkle Tree Management                          │    │    │
│  │  │  - Build Merkle tree from measurements           │    │    │
│  │  │  - Calculate root hash                           │    │    │
│  │  │  - Per-container leaf hashes                     │    │    │
│  │  └──────────────────┬───────────────────────────────┘    │    │
│  │                     │                                     │    │
│  │  ┌──────────────────▼──────────────────────────────┐    │    │
│  │  │  TPM Integration                                 │    │    │
│  │  │  - Extend PCR with Merkle root                   │    │    │
│  │  │  - Configurable PCR index (default: 23)          │    │    │
│  │  └──────────────────┬───────────────────────────────┘    │    │
│  │                     │                                     │    │
│  │  ┌──────────────────▼──────────────────────────────┐    │    │
│  │  │  SecurityFS Interface                            │    │    │
│  │  │  /sys/kernel/security/bpfima/                    │    │    │
│  │  │  - merkle_root                                   │    │    │
│  │  │  - measurements                                  │    │    │
│  │  │  - status                                        │    │    │
│  │  │  - containers/<id>/measurements                  │    │    │
│  │  └──────────────────────────────────────────────────┘    │    │
│  └───────────────────────────────────────────────────────────┘    │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Component Interaction Flow

### 1. System Initialization

```
┌─────────────┐
│ bpfima-tool │ load build/lsm_bprm_check_security.o -d
└──────┬──────┘
       │
       ├─ 1. Load kernel module (insmod)
       │  └─► bpfima.ko registers kfuncs, creates securityfs
       │
       ├─ 2. Load eBPF program
       │  ├─► Parse BPF object file
       │  ├─► Load programs into kernel
       │  ├─► Attach to LSM hooks
       │  └─► Pin BPF maps to /sys/fs/bpf/
       │
       └─ 3. Initialize policy
          └─► bpfima-tool policy-init
              └─► Populate policy maps with defaults
```

### 2. Event Processing Flow

When a monitored event occurs (e.g., process execution):

```
┌───────────────────┐
│  User Process     │
│  execve("/bin/ls")│
└────────┬──────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│  LSM Hook: security_bprm_check()             │
│  (Linux Security Module framework)           │
└────────┬─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│  eBPF Program: lsm_bprm_check_security       │
│                                              │
│  1. Read policy from BPF maps                │
│  2. Check filters (cgroup, path patterns)    │
│  3. If not filtered:                         │
│     └─► Call kfunc: bpfima_measure_file()    │
└────────┬─────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────┐
│  Kernel Module: bpfima_measure_file()        │
│  (Custom kfunc)                              │
│                                              │
│  1. Get current task and namespace info      │
│  2. Check if in container                    │
│     ├─ YES: Update container tracking        │
│     └─ NO:  Track as host process            │
│                                              │
│  3. Read and hash file contents              │
│     └─► SHA-256 hash                         │
│                                              │
│  4. Create measurement entry                 │
│     └─► timestamp, hash, path, pid, etc.     │
│                                              │
│  5. Update Merkle tree                       │
│     ├─► Add to appropriate container leaf    │
│     ├─► Recalculate container leaf hash      │
│     └─► Recalculate Merkle root              │
│                                              │
│  6. Extend TPM PCR                           │
│     └─► TPM_Extend(PCR23, merkle_root)       │
│                                              │
│  7. Log to securityfs and/or kernel log      │
│     └─► /sys/kernel/security/bpfima/...      │
└──────────────────────────────────────────────┘
```

### 3. Policy Configuration Flow

```
┌──────────────────────┐
│ config/policy.yaml   │
│ (User-editable)      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────────────────┐
│ bpfima-tool policy-update            │
│                                      │
│ 1. Parse YAML configuration          │
│ 2. Convert to BPF map format         │
│ 3. Update BPF maps via libbpf        │
└──────────┬───────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│ BPF Maps (in kernel)                 │
│ - Policy flags                       │
│ - Filter patterns                    │
│ - Hook configurations                │
└──────────┬───────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│ eBPF Programs read policy            │
│ Apply filters in real-time           │
└──────────────────────────────────────┘
```

## Key Components Deep Dive

### A. Kernel Module (`bpfima.ko`)

**Location**: `src/`

**Purpose**: Provides custom BPF kfuncs that eBPF programs can call to perform privileged operations not available through standard BPF helpers.

**Main Components**:

1. **Container Tracking** (`src/container.c`, `src/kfuncs_container.c`)
   - Detects container boundaries using namespace IDs
   - Maintains per-container state
   - Tracks container lifecycle events

2. **Measurement Engine** (`src/measurements.c`, `src/kfuncs_measure.c`)
   - Hashes file contents using kernel crypto API
   - Creates measurement entries
   - Maintains global and per-container measurement lists

3. **Merkle Tree** (`src/merkle.c`)
   - Builds hierarchical hash tree
   - Container measurements → leaf hashes
   - Leaf hashes → root hash
   - Optimized for incremental updates

4. **TPM Operations** (`src/tpm_ops.c`)
   - Interfaces with TPM 2.0 chip
   - Extends configurable PCR (default: 23)
   - Provides hardware-backed attestation anchor

5. **Policy Manager** (`src/policy_manager.c`, `src/policy_namespace.c`)
   - Per-namespace policy configuration
   - Global policy fallback
   - Runtime policy updates

6. **SecurityFS Interface** (`src/securityfs_utils.c`, `src/policy_securityfs.c`)
   - Exposes measurements to userspace
   - Read-only access to Merkle tree state
   - Per-container measurement views

**Kfunc Export**: Functions in `src/kfuncs_*.c` are exported as BPF kfuncs using `BTF_KFUNCS_START` / `BTF_KFUNCS_END` macros, making them callable from eBPF programs.

### B. eBPF Programs

**Location**: `hooks/lsm/`

**Purpose**: Lightweight, safe hooks that run in kernel context at security-critical points.

**Hook Types**:

1. **lsm_bprm_check_security.c**
   - Triggers: Process execution (execve)
   - Use case: Track binary launches, script execution
   - Measurement: Executable file hash

2. **lsm_file_post_open.c**
   - Triggers: After file is successfully opened
   - Use case: Track file access patterns
   - Measurement: File hash (if applicable)

3. **lsm_mmap_file.c**
   - Triggers: Memory-mapped file operations
   - Use case: Track shared library loads, JIT code
   - Measurement: Mapped file hash

4. **lsm_socket_connect.c** (optional)
   - Triggers: Network connection attempts
   - Use case: Network policy enforcement
   - Currently disabled by default (high volume)

**Common Pattern in eBPF Programs**:
```c
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm, int ret)
{
    // 1. Check if policy is enabled
    if (!is_policy_enabled())
        return 0;
    
    // 2. Apply filters (cgroup, path)
    if (should_filter_by_cgroup() || should_filter_by_path())
        return 0;
    
    // 3. Call kfunc to measure
    bpfima_measure_file(bprm->file, HOOK_LSM_BPRM_CHECK_SECURITY);
    
    return 0;
}
```

### C. Userspace Tools

**1. bpfima-tool** (NEW - unified management)
   - **Location**: `tools/bpfima_tool.c`
   - **Commands**:
     - `load <bpf_obj> [-d]`: Load and attach eBPF program
     - `unload`: Stop and detach programs
     - `policy-init`: Initialize policy maps with defaults
     - `policy-update <yaml>`: Update policy from config (TODO: YAML parsing)
     - `status`: Show system status

**2. Test Infrastructure**
   - `scripts/test.sh`: Comprehensive integration tests
   - `scripts/test_utils.sh`: Polling and synchronization utilities

## Data Structures

### Measurement Entry
```c
struct bpfima_measurement {
    u64 timestamp;           // When measured
    u32 pid;                 // Process ID
    u32 uid;                 // User ID
    u64 inode;               // File inode
    u8 hash[32];             // SHA-256 hash
    u8 hook_id;              // Which hook triggered this
    char comm[16];           // Process name
    char path[256];          // File path
    struct list_head list;   // Kernel list linkage
};
```

### Container Tracking
```c
struct bpfima_container {
    u64 ns_inum;                    // Namespace ID
    u32 init_pid;                   // Container init PID
    char name[64];                  // Container name
    struct list_head measurements;  // Per-container measurements
    u8 leaf_hash[32];               // Merkle leaf hash
    struct list_head list;          // Global container list
};
```

### Policy Configuration
```c
struct bpfima_policy_config {
    u8 enabled;              // Policy enabled?
    u32 filter_flags;        // What to filter out
    u32 action_flags;        // What actions to take
    u32 min_file_size;       // Minimum file size to measure
    u32 max_path_depth;      // Maximum path depth
    u32 log_level;           // Verbosity
};
```

## Security Considerations

1. **eBPF Verification**: All eBPF programs are verified by the kernel verifier for safety
2. **LSM Integration**: Hooks run with LSM_HOOK_INIT, part of kernel security framework
3. **Read-Only User Access**: SecurityFS provides read-only views of measurements
4. **TPM Anchoring**: Root hash extended to TPM PCR provides tamper-evident audit log
5. **Namespace Isolation**: Per-container measurements prevent cross-container interference

## Performance Characteristics

- **eBPF Overhead**: < 1% for most workloads (hooks are highly optimized)
- **Memory**: Measurements stored in kernel memory (configurable limits)
- **TPM Operations**: Async to avoid blocking critical path
- **Merkle Tree**: O(log n) update complexity

## Future Enhancements

1. **YAML Policy Support**: Full YAML parsing in bpfima-tool
2. **Remote Attestation**: gRPC API for remote TPM quote verification
3. **Policy Enforcement**: Blocking mode (deny operations based on policy)
4. **Machine Learning**: Anomaly detection on measurement patterns
5. **Distributed Merkle Trees**: Cross-node verification for container orchestration

## Troubleshooting

### Common Issues

**Problem**: eBPF program fails to load
- **Cause**: BTF (BPF Type Format) not available
- **Solution**: Install kernel-debuginfo, ensure CONFIG_DEBUG_INFO_BTF=y

**Problem**: Policy maps not found
- **Cause**: eBPF program not loaded or crashed
- **Solution**: Check `bpfima-tool status`, verify loader process running

**Problem**: No measurements appearing
- **Cause**: Policy filters too restrictive
- **Solution**: Run `bpfima-tool policy-init` to reset to permissive defaults

**Problem**: TPM extend fails
- **Cause**: TPM device not accessible or PCR locked
- **Solution**: Check `/dev/tpm0` permissions, verify PCR index not reserved

## References

- [eBPF Documentation](https://ebpf.io/)
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/security/lsm.html)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [BPF kfuncs](https://docs.kernel.org/bpf/kfuncs.html)
