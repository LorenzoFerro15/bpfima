# Policy management

## One authority

All active policy configuration is stored in the protected
`/sys/fs/bpf/bpfima_policy_map`. It contains the root configuration, cgroup/path
patterns, hook settings, and up to 32 explicit namespace extensions. A namespace
without an extension inherits the current root immediately; policies are no
longer copied into kernel namespace objects. Kernel lists store audit metadata,
not active configuration.

The tool, SecurityFS field writers, BPF namespace setters and Kubernetes operator
use the same kernel transaction. There are no independent pattern/hook maps to
update. Direct userspace and BPF writes to the policy map are forbidden through
a map freeze for all syscall FDs and `BPF_F_RDONLY_PROG` for programs; mmap-able,
unfrozen or incorrectly shaped maps are
not accepted. Privileged kernel code remains part of the trust boundary.

## Root and namespace composition

The root is a minimum measurement-coverage baseline. Namespace extensions can
strengthen it, but cannot exclude additional operations that the root measures.
In this framework **filter flags mean skip measurement**, so OR-ing exclusions
would weaken coverage.

| Setting | Effective namespace behavior |
| --- | --- |
| Enabled | Root OR namespace; a namespace cannot disable an enabled root |
| Skip/filter flags | Root AND namespace |
| Required actions | Root OR namespace |
| Minimum measured file size | Lower of root and namespace thresholds |
| Dependency ancestry depth (`max_path_depth`) | Higher value, bounded at 32 |
| Log level | Higher value |
| Enabled hook/tracking/hash flags | Root OR namespace |
| Ignore patterns | An operation is skipped only if both policies filter it |
| History retention configuration | Controlled by the root |

A namespace update is rejected with `EPERM` if it removes required root actions,
adds skip bits, raises the measurement threshold, lowers enabled/depth/log/hook
settings, or introduces ignore patterns outside the root's exclusions. Pattern
subset checks are conservative: exact matches and provably narrower matching
patterns are accepted; uncertain relationships are rejected.

Composition is evaluated against the current root on every policy lookup. A
later root update cannot let an old namespace extension weaken its coverage.
Scalar field edits rebase existing additions on the current root first. Old
ignore patterns that can no longer be proven narrower are dropped, strengthening
coverage rather than blocking an otherwise valid edit or adding exclusions.
Removing namespace audit metadata during container teardown does not remove map
rules; explicit rules persist for the module epoch.

`EXTEND_TPM` and `LOG_SECURITYFS` are mandatory parts of a measurement commit.
Appraisal/alert and discretionary blocking actions, and hook filter/action
overrides, are not implemented and are rejected instead of silently accepted.
Selected hooks propagate recording/extension failures regardless of a block
flag. File hash enablement controls file measurements; metadata events do not
require a file hash. Kernel measurement detail logging follows log settings;
important error diagnostics can still be emitted.

All five production hooks use the same resolver, including `inode_setattr` at
hook ID 7. Legacy IDs remain reserved for compatibility; configuring a slot does
not attach an absent hook. File/path filtering uses the context available at the
hook. In particular, `inode_setattr` supplies a dentry name rather than a complete
mount-aware path. Namespace identifiers still follow the existing cgroup-name
convention; they are not globally unique cgroup lifecycle IDs.

## Synchronous atomic update

The policy map is an array with three values. Key 0 contains the published
64-bit generation. Keys 1 and 2 hold complete policy states; the active key is
`1 + (generation & 1)`. Record 0 is the root (empty namespace identifier). The
remaining records contain explicit namespace identifiers and full extension
snapshots. Never interpret the inactive state as applied policy.

An update:

1. Copies and validates the complete request while holding the policy mutex.
2. Normalizes strings, unused entries and padding; prepares the audit record,
   hashes and inactive map state before issuing a TPM command.
3. Acquires `bpfima_commit_mutex` and synchronously commits the policy event
   through `src/merkle.c` in the caller's thread.
4. After successful hardware extension and Merkle publication, publishes audit
   metadata and the new generation. No required allocation or hashing remains.

Policy readers take the policy mutex and cannot see partial updates. Internal
root readers use a brief snapshot spinlock; TPM commands never run under it.
External map readers must read the control generation, copy the selected state,
and read the generation again, retrying if it changed. Separate SecurityFS reads
are not a combined snapshot. An already-resolved operation can finish under its
previous policy; this transaction does not roll back filesystem/network actions.

Identical normalized updates are idempotent and do not extend the TPM again.
`expected_generation` optionally rejects stale full requests with `EAGAIN`.
Even idempotent requests report a latched commit error. Failed preparation leaves
active policy unchanged. A failed command that may have reached hardware latches
`commit_error`, blocks unsafe retries, and requires trusted PCR recovery before
a fresh epoch. Module reload alone does not reset the PCR. Existing initial
no-TPM software simulation remains supported; an epoch cannot switch modes.

Every changed policy is a root-history event, including namespace changes.
Policy updates no longer inject file-shaped records into namespace measurement
lists. The snapshot digest covers the namespace identifier and **all** normalized
configuration, patterns and hooks, encoded little-endian. The event preimage is:

```text
policy_v2:<generation>:<namespace-or-[root]>:<snapshot-SHA256>
```

Its SHA-256 is committed to root history and displayed in the corresponding
`policy_changes` log. Namespace `changes_hash` is the rolling
`SHA256(previous_changes_hash || event_digest)`, starting at zero. The change
string shows the most recent event, rather than an eventually overflowing
concatenation. History trimming/remote completeness semantics remain separate
work; full PCR replay tests require untrimmed history.

## Load and apply

Build and load on a suitable host:

```bash
make modules kernel-tests
sudo insmod build/bpfima.ko
sudo ./build/bpfima-tool load build/lsm_bprm_check_security.o \
    build/lsm_file_post_open.o build/lsm_mmap_file.o \
    build/lsm_inode_setattr.o build/lsm_socket_connect.o -d
```

The loader creates/freezes or reuses the protected map, writes its FD to SecurityFS
`policy_map`, and commits the initial root **before attaching hooks**. Manual
hook attachment before binding the map fails closed with `ENXIO` for selected
operations. `policy-init` creates/binds the map and applies defaults; it can be
used before manually attaching hooks.

```bash
sudo ./build/bpfima-tool policy-init
sudo ./build/bpfima-tool policy-update config/policy.yaml
sudo ./build/bpfima-tool policy-update /etc/bpfima/tenant.yaml tenant-cgroup-name
cat /sys/kernel/security/bpfima/policy
cat /sys/kernel/security/bpfima/status
```

Use `BPFIMA_SECURITYFS_DIR` for an alternate module directory. A namespace YAML
file is a complete extension snapshot and must satisfy the root floor. YAML
supports `enabled`, `log_level`, `measure_enabled`, `container_tracking`,
`filter_flags`, `min_file_size`, `max_path_depth`, ignore-pattern arrays and hook
settings. `appraise_enabled`/`enforce_enabled` must be false. Omitted hooks use
explicit defaults; old hook values are not retained accidentally.

Example root threshold:

```yaml
policy:
  enabled: true
  measure_enabled: true
  container_tracking: true
  log_level: 2
  filter_flags: 16
  min_file_size: 8192
  max_path_depth: 16
```

A valid stronger namespace snapshot can use `filter_flags: 0`,
`min_file_size: 1024`, `max_path_depth: 32`, and `log_level: 3`, with the same
mandatory actions and no additional ignore patterns.

Text field updates remain available and use the same map transaction:

```bash
printf 'log_level=3\n' | sudo tee /sys/kernel/security/bpfima/policy
printf 'min_file_size=1024\n' | sudo tee \
    /sys/kernel/security/bpfima/namespaces/tenant-cgroup-name/policy
```

`securityfs_policy_writable=0` rejects policy writes, including root writes via
permission override; map binding with the audited default root is still allowed.
Load-time read-only deployments use that default root. YAML/operator updates need
writable policy endpoints; they are no longer a bypass around this setting.

The full transaction endpoint is SecurityFS `policy_apply`. It accepts one
1,400-byte, version-2, little-endian request. The shared definitions are in
`include/bpfima_kfunc_types.h`. The operator submits one request containing
configuration, patterns and hooks; it does not update maps and then write a
separate `measure_policy` endpoint. Writes are not retried automatically after
ambiguous errors.

## Migration and checks

This is a map ABI and policy-audit format change. Detach old programs, unload the module, remove its stale map pin and reload the
module before loading rebuilt hooks. An old map, an unprotected
map, a map from a previous epoch, or a second different map cannot silently
replace the bound authority. Hook unload preserves the map when its ID matches the loaded module authority,
so hook reload retains the same audited policy. Once the module is unloaded,
`bpfima-tool unload` can remove the stale pin. A failed initial binding retains the protected pin
for safe retry; explicit unload/cleanup can remove it. A module reload starts a
new software epoch but does not reset hardware PCR state.

```bash
make test-policy test-commit test-security CC=clang
(cd operator && go test ./internal/... ./api/...)
./scripts/test_kernel.sh --check --load-module
sudo ./scripts/test_kernel.sh --load-module --stress
```

Native policy tests link the actual policy manager, namespace wrappers and Merkle
engine with mocked kernel/map/TPM primitives. They cover hierarchy, staged
activation, failure handling, idempotence, canonical C/Go encoding and hardware
extension ordering. Live validation still needs matching module BTF and an
isolated BPF LSM host. The runner initializes policy and modifies it during the
suite; it may extend physical PCRs. See `docs/KERNEL_TESTS.md`.
