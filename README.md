# eBPF File Monitoring with TPM Integration

eBPF-based file integrity monitoring system with TPM hardware support for secure measurement and attestation.

## Directory Structure

```
bpfima/
├── build/              # Compiled objects (auto-generated)
│   ├── *.ko           # Kernel modules
│   ├── *.o            # eBPF and object files
│   └── loader         # Minimal eBPF program loader
├── scripts/           # Test and validation scripts
│   ├── test.sh        # Integrated test & validation script (interactive + validation modes)
│   └── validate.sh    # Standalone comprehensive validation script
├── hooks/             # eBPF hook implementations
│   ├── kprobe/        # Kprobe-based hooks
│   └── lsm/           # LSM (Linux Security Module) hooks
│       ├── lsm_container_events.c  # Container tracking with multi-channel communication
│       ├── lsm_bprm_check_security.c  # Process execution tracking
│       ├── lsm_mmap_file.c  # File mmap operations
│       └── ...        # Other LSM hooks
├── include/           # Header files
│   ├── bpfima_common.h      # Common data structures
│   ├── bpfima_merkle.h      # Merkle tree functions
│   ├── bpfima_securityfs.h  # SecurityFS interface
│   └── bpfima_kfuncs.h      # BPF kfunc declarations
├── src/               # Kernel module source (modular)
│   ├── main.c         # Module initialization
│   ├── merkle.c       # Merkle tree implementation
│   ├── securityfs.c   # SecurityFS implementation
│   └── kfuncs_container.c  # Container tracking kfuncs
├── templates/         # Code templates
├── utils/             # Utility headers
├── loader.c           # Loader source
├── bpfima.c          # Kernel module source (monolithic)
├── Makefile           # Build system
├── README.md          # This file
└── VALIDATION.md      # Comprehensive validation guide
```

## Components

### eBPF Programs
- `hooks/lsm/lsm_mmap_file.c` - LSM hook for file mmap operations
- `hooks/lsm/lsm_file_open.c` - LSM hook for file open operations
- `hooks/lsm/lsm_socket_connect.c` - LSM hook for socket connections
- `hooks/kprobe/kprobe_file_open.c` - Kprobe for file open tracking

### User Space Loader
- `loader` - Minimal loader that loads and attaches a single eBPF object file

### Kernel Module
- `bpfima.ko` - Provides custom kfuncs for TPM operations and measurement extension

### User Space Loader
- `loader` - Generic loader that automatically detects and attaches any eBPF program type (LSM, kprobe, tracepoint, fentry/fexit)

### Kernel Module
- `bpfima.ko` - Provides custom kfuncs for TPM operations and measurement extension

## TPM Features

The TPM integration provides:
- Platform Configuration Register (PCR) extensions
- Hardware-backed measurement chains
- SHA1 hash calculations using kernel crypto APIs
- Real-time measurement count tracking
- TPM hardware availability detection

### TPM Functions
- `bpf_tpm_extend_pcr()` - Extend TPM PCR with measurement data
- `bpf_tpm_is_available()` - Check TPM hardware availability
- `bpf_ima_extend_measurement()` - Extend IMA-style measurement list
- `bpf_ima_get_measurement_count()` - Get current measurement count
- `bpf_ima_get_pcr_value()` - Retrieve PCR values
## Build

Requirements:
- Linux kernel 5.8+
- libbpf, libelf, zlib development packages
- clang, llvm
- kernel headers

```bash
# Install dependencies (Fedora)
sudo dnf install kernel-devel libbpf-devel elfutils-libelf-devel zlib-devel clang llvm dwarves

# Build all components (outputs to build/ directory)
make all
```

All compiled objects will be placed in the `build/` directory.

## Usage

The integrated test script supports two modes: **Interactive Testing** and **Validation**.

### Interactive Test Mode (Default)

Run live monitoring with eBPF hooks:

```bash
# Normal mode (default BPF program: lsm_mmap_file.o)
sudo ./scripts/test.sh

# Verbose mode (detailed insights)
sudo ./scripts/test.sh --verbose

# Test specific eBPF program
sudo ./scripts/test.sh build/kprobe_file_open.o
sudo ./scripts/test.sh build/lsm_file_open.o
sudo ./scripts/test.sh build/lsm_container_events.o

# With container runtime testing
sudo ./scripts/test.sh --container --verbose
```

### Validation Mode

Comprehensive validation of all system components:

```bash
# Validate all tasks (1-7)
sudo ./scripts/test.sh --validate

# Validate with verbose output
sudo ./scripts/test.sh --validate --verbose

# Validate specific tasks
sudo ./scripts/test.sh --task 2 --task 3      # SecurityFS + Merkle Tree
sudo ./scripts/test.sh --task 7 --verbose     # End-to-end testing

# Full validation with container tests
sudo ./scripts/test.sh --validate --verbose --container

# Debug mode (no cleanup after tests)
sudo ./scripts/test.sh --validate --skip-cleanup
```

**Validation Tasks:**
1. Data Structures - Kernel data types validation
2. SecurityFS Setup - Filesystem interface verification
3. Merkle Tree - Tree operations and SHA-256 hashing
4. TPM Integration - PCR extension testing
5. eBPF Hooks - LSM attachment validation
6. Kernel-eBPF Communication - Kfuncs and BPF maps
7. Interactive Validation - End-to-end comprehensive tests

For detailed validation documentation, see [VALIDATION.md](VALIDATION.md).

### Quick Reference

```bash
# Interactive testing (press Ctrl-C to stop)
sudo ./scripts/test.sh --verbose

# Quick validation check
sudo ./scripts/test.sh --validate

# Full system validation
sudo ./scripts/test.sh --validate --verbose --container

# Help and options
./scripts/test.sh --help
```

**Available programs:**
- `build/lsm_mmap_file.o` - LSM file mmap monitoring (default for interactive)
- `build/lsm_file_open.o` - LSM file open monitoring
- `build/lsm_file_post_open.o` - LSM file post-open with hash computation
- `build/lsm_bprm_check_security.o` - LSM process execution tracking
- `build/lsm_container_events.o` - Container tracking with multi-channel communication (default for validation)
- `build/lsm_socket_connect.o` - LSM socket connection monitoring
- `build/kprobe_file_open.o` - Kprobe file open tracking

Verbose mode provides:
- Build output
- Module information
- Target BPF object path
- Trace file locations
- Recent trace data
- Validation test results

## Container Tracking Features

The system provides comprehensive container/pod tracking with Merkle tree-based integrity:

### Architecture

1. **Data Structures** - Per-container measurement lists and Merkle tree nodes
2. **SecurityFS Interface** - `/sys/kernel/security/bpfima/` hierarchy
3. **Merkle Tree** - Non-binary tree with SHA-256 leaf and root hashing
4. **TPM Integration** - Hardware-backed PCR 23 extension on root updates
5. **eBPF Hooks** - LSM-based container event detection (cgroup tracking)
6. **Multi-Channel Communication** - Kfuncs, BPF maps, and ring buffers

### SecurityFS Hierarchy

```
/sys/kernel/security/bpfima/
├── merkle_root              # Current Merkle tree root hash (virtual PCR)
├── measurements             # Global measurement list
├── container_list           # List of tracked containers
└── containers/
    ├── <container_id_1>/
    │   └── measurements     # Container-specific measurements
    └── <container_id_2>/
        └── measurements
```

### Communication Channels

The system uses 6 communication channels between eBPF and kernel:

1. **Kfunc: Container Creation** - `bpf_container_create_or_get()`
2. **Kfunc: Add Measurement** - `bpf_container_add_measurement()`
3. **Kfunc: Read Merkle Root** - `bpf_get_merkle_root()`
4. **BPF Map: Statistics** - Per-container and global counters
5. **BPF Map: Active Tracking** - LRU cache of active containers
6. **Ring Buffer: Events** - Asynchronous event notifications

### Merkle Tree Structure

```
              Root Hash (Virtual PCR)
              /        |        \
             /         |         \
   Container1_Hash  Container2_Hash  Container3_Hash
        |                |                |
   [Measurements]   [Measurements]   [Measurements]
```

Each container's leaf hash is computed from its measurement list. The root hash combines all leaf hashes and is extended into TPM PCR 23.

### Reading Container Data

```bash
# View current Merkle root
cat /sys/kernel/security/bpfima/merkle_root

# List tracked containers
ls /sys/kernel/security/bpfima/containers/

# View container measurements
cat /sys/kernel/security/bpfima/containers/<container_id>/measurements

# View all measurements
cat /sys/kernel/security/bpfima/measurements
```

## Manual Usage

```bash
# Build
make all

# Load kernel module
sudo insmod build/bpfima.ko

# Run loader with any eBPF program
sudo ./build/loader build/lsm_mmap_file.o

# View trace output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Cleanup
sudo rmmod bpfima
```

## File Structure

Source files:
- `loader.c` - Minimal eBPF program loader
- `bpfima.c` - Kernel module providing custom kfuncs
- `hooks/` - eBPF hook implementations
  - `hooks/lsm/*.c` - LSM hooks (file_open, mmap_file, socket_connect)
  - `hooks/kprobe/*.c` - Kprobe hooks
- `scripts/test.sh` - Minimal test script

Build outputs (in `build/` directory):
- `bpfima.ko` - Kernel module
- `loader` - Loader executable
- `*.o` - eBPF object files

## Error Diagnosis

### Build Errors

**Missing BTF**: `Skipping BTF generation for bpfima.ko`
```bash
# Install kernel debug info
sudo dnf install kernel-debuginfo-$(uname -r)
# If the previous command does not work, use
sudo dnf debuginfo-install kernel

# Then, create a symlink to the existing vmlinux
echo "found vmlinux: $(sudo find /usr/lib/debug -name vmlinux -type f | head -1)"
sudo ln -sf <found_vmlinux> /lib/modules/$(uname -r)/build/vmlinux
```

**BPF target not supported**: `unknown target triple 'bpf'`
```bash
sudo dnf install clang llvm
```

**Missing headers**: `bpf/bpf.h not found`
```bash
sudo dnf install libbpf-devel libelf-devel kernel-devel
```

### Runtime Errors

**Permission denied**: BPF operations require root
```bash
sudo ./run_test.sh
```

**No events**: Check if programs attached and trace enabled
```bash
sudo bpftool prog list | grep handle_unlinkat
echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_unlinkat/enable
```

**TPM not found**: TPM hardware optional, will use simulation
```bash
ls -la /dev/tpm*  # Check TPM device
sudo modprobe tpm_tis tpm_crb  # Load TPM modules
```

**Module load failed**: Check kernel module dependencies
```bash
sudo dmesg | tail -10  # Check error messages
lsmod | grep bpfima     # Verify module loaded
```