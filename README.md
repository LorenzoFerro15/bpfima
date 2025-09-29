# eBPF File Monitoring with TPM Integration

eBPF-based file integrity monitoring system with TPM hardware support for secure measurement and attestation.

## Components

### eBPF Programs
- `kfunc_simple.c` - Basic file monitoring using standard eBPF helpers
- `kfunc_tpm.c` - TPM-enhanced monitoring with hardware attestation
- `kfunc_tpm_sim.c` - TPM simulation for testing without hardware

### User Space Loaders
- `loader_simple` - Loads simple eBPF program
- `loader` - Loads TPM-enhanced eBPF program  
- `loader_tpm` - TPM-specific loader with hardware access

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

# Build all components
make all
```

## Usage

Run the complete test with TPM integration:

```bash
sudo ./run_test.sh
```

This script builds components, loads the kernel module, runs the TPM eBPF program, creates/removes a test file, and displays trace and kernel messages.

## Manual Usage

Individual components can be run manually:

```bash
# Build everything
make all

# Load kernel module
sudo insmod bpfima.ko

# Run simple eBPF monitor
sudo ./loader_simple kfunc_simple.o &

# Run TPM-enhanced monitor  
sudo ./loader kfunc_tpm.o &

# Create test file operations
echo "test" > /tmp/test.txt
rm /tmp/test.txt

# View trace output
sudo tail -30 /sys/kernel/debug/tracing/trace
sudo dmesg | tail -20
```

## File Structure

- `kfunc_simple.c` - Basic eBPF program using standard helpers
- `kfunc_tpm.c` - TPM-enhanced eBPF program with hardware integration
- `bpfima.c` - Kernel module providing custom kfuncs
- `loader.c`, `loader_simple.c` - User space loaders
- `run_test.sh` - Automated test script

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