# Kernel module integration tests

This suite exercises the loaded `bpfima` module through BPF kfuncs, the kernel
BPF verifier, LSM attachment, SecurityFS, and the TPM interface. It does not run
the Go verifier, YAML parser tests, or userspace-only buffer tests.

## Build and run

Run from the repository root on an isolated test host or VM:

```bash
make modules kernel-tests
./scripts/test_kernel.sh --check --load-module
sudo ./scripts/test_kernel.sh --load-module
```

`--load-module` loads `build/bpfima.ko` if it is absent and unloads it after the
tests. If a module is already loaded, the runner checks its ABI, uses it, and
leaves it loaded. It never replaces or forcibly unloads an existing module.

To test an already loaded, updated module:

```bash
sudo ./scripts/test_kernel.sh
```

To include concurrency tests:

```bash
sudo ./scripts/test_kernel.sh --load-module --stress
```

The runner has a 300-second timeout for each test executable. For a slow TPM or
an instrumented debug kernel, increase it and choose an explicit report folder:

```bash
sudo ./scripts/test_kernel.sh --load-module --stress \
    --timeout 900 --output-dir build/kernel-test-report
```

`./scripts/test_security.sh --kernel` is a compatibility entry point for the same
runner and accepts the same remaining options. Build with `make kernel-tests`
first; the runner does not compile programs as root.

## Host requirements

- Kernel headers and a module built for the running kernel.
- BPF LSM enabled in both the kernel configuration and the active LSM list at
  `/sys/kernel/security/lsm`.
- Kernel BTF at `/sys/kernel/btf/vmlinux` and module BTF at
  `/sys/kernel/btf/bpfima` once the module is loaded.
- SecurityFS mounted at `/sys/kernel/security`.
- BPF filesystem mounted at `/sys/fs/bpf` for the pinned-program unload test.
- Root privileges for BPF attachment, module loading, and kernel log access.
- The usual repository build dependencies, plus OpenSSL development headers and
  `libcrypto` for independent SHA-256 calculations, libyaml for exercising the
  management tool's production unload code, and pthreads for stress tests.
- Bash, GNU `timeout`, `dmesg`, `readelf`, `stat`, and `mktemp`; `insmod` and `rmmod` when
  the runner loads the module.

On Fedora, install the extra test dependencies with
`sudo dnf install openssl-devel libyaml-devel`. The `modules kernel-tests` build
does not require Go or build the management tool executable. The unload fixture
compiles its production cleanup implementation directly into the test.

A successful module compilation that prints
`Skipping BTF generation ... due to unavailability of vmlinux` is insufficient.
Install the debug information for the exact running kernel and provide its
matching `vmlinux` in `/lib/modules/$(uname -r)/build/vmlinux`, then rebuild:

```bash
make modules
./scripts/test_kernel.sh --check --load-module
```

The preflight rejects a module without a `.BTF` section. For an already loaded
module, it also checks all exported kfunc parameter names/size annotations and
the policy structure's size and field offsets before any test kfunc is called.
Rebuilding a file on disk does not update a module that is already loaded.

If SecurityFS is mounted elsewhere, pass the actual module directory:

```bash
sudo ./scripts/test_kernel.sh --securityfs-dir /path/to/securityfs/bpfima
```

Use a quiet host with other integrity-monitoring BPF programs stopped. Exact
container counts and global root/history comparisons require the test run to
be the only measurement producer. Use a fresh module with untrimmed history;
the tests reject aggregated history records instead of treating them as a
complete replay log.

## Coverage

| Area | Checks |
| --- | --- |
| Module lifecycle | BTF and SecurityFS publication on load; removal on unload when the runner owns the module |
| Pinned references | Pin an LSM link, kfunc-calling program, and map; close the original handles; verify that production unload removes pins and releases the program with missing, stale, and invalid PID files; check idempotence, persistence override, and cleanup failure reporting |
| Loaded ABI | All 17 exported kfunc signatures, verifier size annotations, policy size and field offsets |
| Kfunc registration | Load-only kprobe, tracepoint, and raw tracepoint callers plus the attached LSM tests verify that both kfunc registration slots remain available; duplicate-registration kernel warnings fail the run |
| Verifier boundaries | Ten undersized input/output-buffer programs must fail to load for a memory-access reason |
| Sleepability | A non-sleepable program calling the measurement kfunc must fail to load |
| Runtime validation | Malformed measurement requests, unterminated/empty identifiers, invalid namespace names, wrong output lengths, invalid filter strings |
| Output writes | Guard bytes after root, leaf, policy hash, policy configuration, and PCR output buffers remain intact |
| Namespace handling | Missing-namespace errors, successful creation, idempotent creation, initial zero leaf, unchanged root for empty containers |
| Measurement flow | Payload-only, payload plus dependencies, dependencies-only, maximum payload/dependency sizes, automatic namespace creation |
| Deduplication | Repeated measurements preserve count/leaf/root; the same digest is accepted in a different namespace |
| Integrity state | Independent OpenSSL SHA-256 expectations for template digest, leaf extension, root extension, and replay of SecurityFS logs |
| Policy | All four kfunc setters, full configuration reads, policy change hash, SecurityFS reads/writes, rejected writes preserving committed state, global policy isolation |
| Filters | Positive and negative cgroup/path filtering through module kfuncs |
| TPM | Availability and bounded PCR reads; actual PCR23 extension checked when a TPM exists and `tpm_pcr_index=23` |
| LSM composition | A denying BPF program is attached first; exec, open, chmod, mmap, and socket connect must remain denied after each corresponding production hook is attached |
| Setattr formatting | The production formatter runs inside BPF: empty and combined attributes, privilege flags, truncation preserving the existing prefix, negative/full-buffer offsets, exact fit, and one-byte overflow; lengths, contents, termination, and buffer guards are checked |
| Kernel diagnostics | New kernel warning splats, BUG reports, KASAN/KCSAN/UBSAN reports, lockdep reports, atomic-sleep warnings, and selected stall/refcount reports fail the run |

The LSM composition tests first verify a successful operation without the
denying program, then verify that the denying program works, then attach the
production hook and require the same `EACCES` denial. They do not treat a failed
program load or a missing executable as a successful denial test.
Independent hook checks continue after a failure so a single run reports all
affected hooks. Expected negative verifier tests print a PASS line; unexpected
rejections and failed production loads retain the verifier diagnostics.

The tests invoke successful measurement and policy operations through a small
BPF fixture. The production hooks are tested for loading and denial propagation;
the suite does not claim to test every production hook's filtering/hash-success
path under every IMA configuration.

## Concurrency tests

`--stress` starts eight threads together, with a separate BPF command/result map
entry for each thread. It checks:

1. Concurrent creation of one namespace publishes exactly one container and
   every caller succeeds.
2. Eight measurements per thread produce 64 records, and the public measurement
   order reproduces the leaf hash while global history reproduces the root.
3. Concurrent submissions of the same measurement commit exactly once.

These are regression checks for the creation, deduplication, and ordering races
identified in the review. The stress suite also mixes raw measurements,
namespace-policy updates and global SecurityFS policy writes, restores the global
log level, and replays the physical PCR23 extensions when a TPM is present.
A stress failure is reported as a failure. Passing one run does not establish
the absence of a race. For more visibility, also run on kernels built
with KASAN, KCSAN, or lockdep support; the suite collects their reports when those
facilities are enabled.

## Results and cleanup

The default report directory is `build/kernel-test-results/<timestamp>-<pid>/`.
It contains:

- `security-regression.log`: verifier diagnostics and LSM checks.
- `module-interactions.log`: successful-operation and optional concurrency checks.
- `pinned-unload.log`: retained BPF reference and production unload checks.
- `dmesg-before.log` and `dmesg-run.log`: kernel diagnostics.
- `kernel-errors.log`: matched warning/error reports, if any.
- `kernel-warning-context.log`: matching reports with surrounding kernel-log lines, also printed on failure; `dmesg-run.log` retains the complete backtrace if it exceeds that excerpt.
- `load.log` and `unload.log`: module lifecycle output when applicable.
- `result.txt`: final exit code, kernel version, and whether stress was requested.

Before loading the module or attaching test programs, the runner verifies that
`dmesg --since` accepts its local start timestamp. The timestamp omits the ISO
8601 timezone suffix, which some util-linux versions reject.

Exit code `0` means all requested checks passed. Exit code `1` means a test or
cleanup check failed. Exit code `2` identifies a prerequisite/setup error;
interrupts use `130` or `143`. Individual executable timeouts appear in their
suite status and cause the overall run to fail.

Temporary BPF links and maps are unpinned and closed after the tests. The runner
removes its temporary files on failure or interruption and retries a normal
module unload briefly to allow BPF references to be released. It never forces
an unload. Kernel deadlocks or crashes may require recovering the test VM.

Successful tests create namespace records and policy/measurement history and
can extend the configured TPM PCR. PCR extensions cannot be undone by unloading
the module. When an existing module is reused, test namespaces remain until
that module is unloaded because it has no namespace deletion API. Run this suite
on a disposable test system rather than a machine whose attestation state you
need to preserve.

## Direct execution for debugging

After loading the updated module, each executable can be run separately:

```bash
sudo ./build/security-regression build/security-regression.bpf.o build
sudo ./build/module-interactions build/module-interactions.bpf.o \
    /sys/kernel/security/bpfima
sudo ./build/pinned-unload build/module-interactions.bpf.o
```

The wrapper is the recommended entry point because it adds prerequisite checks,
timeouts, kernel log collection, temporary-file cleanup after forced termination,
and optional module lifecycle checks.

## A module that remains in use

Pinned BPF programs calling module kfuncs can retain module references after the
loader exits. The management tool's explicit `unload` removes retained links and
maps even when its PID file is missing or stale. Rebuild the tool, stop any
supervisor that would immediately restart it, then release the pins before
removing the module:

```bash
make build/bpfima-tool
sudo ./build/bpfima-tool unload
for attempt in {1..10}; do
    sudo rmmod bpfima && break
    sleep 1
done
```

If it remains busy, inspect `sudo bpftool prog show` and
`sudo bpftool link show` for another program or process retaining a reference.
The module reference count alone does not identify its holder. Forced module
removal does not release the BPF references safely.

The pin test uses private directories and leaves production pins untouched. A
filesystem-only smoke check of the same cleanup code is available without root
or a loaded module: `./build/pinned-unload --filesystem`. It cannot verify BPF
program lifetime or module reference release.

## Small audit fixes, October 2026

Container destruction now runs in a dedicated workqueue after an RCU grace
period. Module shutdown drains queued RCU callbacks and destruction work before
tearing down policy state. Namespace creation is serialized, and duplicate hash
insertion checks uniqueness under the table lock. The existing lifecycle and
`--stress` checks exercise these paths; run them with KASAN/lockdep when available.

The PCR parameter is validated on load and read-only thereafter. Status and PCR
reads use the configured index, and the test suite checks the corresponding
hardware/simulation prefix. SecurityFS invalid-write tests now include numeric
overflow and invalid log levels. Socket payload lengths exclude the formatter's
terminating NUL. Post-open/mmap respect hook enablement, setattr respects global
enablement, and post-open's fixed size window is replaced by the configured
small-file threshold.

The private unload fixture also checks PID file permissions, rejection of unsafe
modes, and symlink handling. Old group/world-writable PID files are now refused;
verify the owning process before replacing an unsafe file. PID reuse and atomic
singleton ownership still need a separate process-lifecycle change.

Userspace parser regressions run separately, without kernel mutations:

```bash
make test-security CC=clang
go test ./verifier/...
(cd operator && go test ./internal/...)
```

The sanitizer tests cover initialization of the complete YAML hook array, named
hook IDs, pattern clearing, invalid values, capacity limits, and update errors.
The bundled userspace YAML examples now use the parser's supported schema.
Operator tests check the 36-byte policy ABI and field offsets; CRD limits match
the eight-slot, 63-byte pattern contract. Kubernetes cleanup preserves shared
CRDs by default (`cleanup.deleteCRD=false`) and fails if the module remains loaded.

Remaining audit work includes resource quotas, authoritative policy
synchronization, target-log completeness/identity, authenticated history trimming,
and the missing Kubernetes policy-audit endpoint. Error handling and the daemon's
absolute output directory/health reporting also require further work. Local
module compilation succeeds, but live kernel results require matching module BTF.

## Synchronous measurement commits

Measurement, namespace-policy and global-policy events use one sleepable commit
mutex in the calling thread. They prepare their allocations and hashes first,
extend the TPM, and only then publish measurement/history entries, leaf/root
hashes, counts and deduplication state. Policy configuration and its audit bytes
are staged too. No background worker performs measurement commits or extensions.
The existing destruction workqueue is solely for safe container teardown.

Concurrent callers for the same digest wait for the earlier call. A duplicate
means a completed commit; failed preparation does not poison the digest and a
later caller can retry. Spinlocks protect the brief software-publication step;
the TPM operation runs outside spinlocks while the commit mutex remains held.
PCR reads use the same commit mutex, so they do not observe an in-flight commit.
Atomicity applies to module producers and coordinated readers; collecting
multiple SecurityFS files is still not a single snapshot operation.

TPM command failures are returned rather than treated as a successful record.
Measurement and policy commit state remains unchanged on failure; creating a
namespace can still leave an initialized empty namespace. Hardware anchoring
requires an allocated SHA-256 bank. Errors after a command may have
reached hardware latch `commit_error` in SecurityFS status and block subsequent
commits/PCR reads, preventing an unsafe automatic retry. Recover the physical PCR
state through a trusted recovery procedure before starting a fresh module epoch;
module reload alone does not reset a physical PCR. Failures allocating TPM command
buffers before submitting a command remain retryable. The existing no-TPM
software-only mode is supported, but an epoch cannot switch between software-only
and hardware anchoring without recovery/reload.

Native regression tests execute the production `src/merkle.c` with
mocked kernel allocation/hash/TPM primitives and pthread locks, under sanitizers:

```bash
make test-commit CC=clang
```

They cover every software allocation/hash preparation failure, TPM preparation
failure, successful retry, duplicate callers blocked during both successful and
failed commits, ambiguous hardware errors, device/mode changes, and mixed producer
history/root/PCR replay. These are control-flow/concurrency tests, not live TPM or
kernel scheduler/lockdep validation. Hardware tests require the fresh updated
module with BTF on a quiet disposable host:

```bash
make modules kernel-tests
sudo ./scripts/test_kernel.sh --load-module --stress
```

The stress suite requires untrimmed history. Checkpoint/replay-preserving history
aggregation remains separate audit work.
