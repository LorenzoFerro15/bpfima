# eBPF File Monitoring with TPM Integration

eBPF-based file integrity monitoring system with TPM hardware support for secure measurement and attestation.

## Directory Structure

```
bpfima/
├── build/              # Compiled objects (auto-generated)
│   ├── *.ko           # Kernel modules
│   ├── *.o            # eBPF and object files
│   └── loader         # Minimal eBPF program loader
├── scripts/           # Test scripts
│   └── test.sh        # Minimal test script
├── hooks/             # eBPF hook implementations
│   ├── kprobe/        # Kprobe-based hooks
│   └── lsm/           # LSM (Linux Security Module) hooks
├── templates/         # Code templates
├── utils/             # Utility headers
├── loader.c           # Loader source
├── bpfima.c          # Kernel module source
└── Makefile           # Build system
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

Run the minimal test:

```bash
# Normal mode (default BPF program)
sudo ./scripts/test.sh

# Verbose mode (detailed insights)
sudo ./scripts/test.sh --verbose

# Test specific eBPF program
sudo ./scripts/test.sh build/kprobe_file_open.o
sudo ./scripts/test.sh build/lsm_file_open.o
sudo ./scripts/test.sh build/lsm_socket_connect.o

# Combine options
sudo ./scripts/test.sh --verbose build/kprobe_file_open.o
```

The script builds, loads the kernel module, and runs the eBPF monitor.

**Default BPF program:** `build/lsm_mmap_file.o`

**Available programs:**
- `build/lsm_mmap_file.o` - LSM file mmap monitoring (default)
- `build/lsm_file_open.o` - LSM file open monitoring
- `build/lsm_socket_connect.o` - LSM socket connection monitoring
- `build/kprobe_file_open.o` - Kprobe file open tracking
- `build/kfunc_tpm.o` - TPM-enhanced monitoring

Verbose mode provides:
- Build output
- Module information
- Target BPF object path
- Trace file locations
- Recent trace data

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