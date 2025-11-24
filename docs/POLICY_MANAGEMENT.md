# BPF IMA Policy Management

## Quick Start

BPF IMA policies control what gets measured and how. There are three methods to manage policies.

## Policy Methods

### 1. YAML Configuration (Recommended)

**Best for**: Production deployments, version control

```bash
# Apply policy from YAML file
sudo bpfima-tool policy-update config/policy.yaml
```

**Example YAML**:
```yaml
policy:
  enabled: true
  log_level: 2
  filter_flags: 0x0
  action_flags: 0x3F

filters:
  cgroup_patterns:
    - "/system.slice/"
  path_patterns:
    - "/usr/bin/"
```

### 2. SecurityFS Interface

**Best for**: Development, quick testing

```bash
# Read current policy
cat /sys/kernel/security/bpfima/policy

# Update policy (development only)
echo "log_level=3" > /sys/kernel/security/bpfima/policy
echo "filter_flags=0x7" > /sys/kernel/security/bpfima/policy
```

**Security Warning**: Disable in production with `securityfs_policy_writable=0`

### 3. bpftool (Advanced)

**Best for**: Debugging, direct map inspection

```bash
# View policy map
sudo bpftool map dump pinned /sys/fs/bpf/bpfima_policy_map
```

Not recommended for regular use

## Production Setup

**Step 1**: Load module with write protection
```bash
sudo modprobe bpfima securityfs_policy_writable=0
```

**Step 2**: Apply YAML policy
```bash
sudo bpfima-tool policy-update /etc/bpfima/policy.yaml
```

**Step 3**: Verify
```bash
cat /sys/kernel/security/bpfima/policy
```

## Policy Hierarchy

- **Global policy**: Applies to all namespaces/containers by default
- **Per-namespace policy**: Override global settings for specific containers
- **Precedence**: Last write wins (YAML → securityfs → bpftool)

```
/sys/kernel/security/bpfima/policy                           # Global
/sys/kernel/security/bpfima/namespaces/<ns_id>/policy       # Per-namespace
```

## Common Use Cases

### Increase Logging
```bash
echo "log_level=4" > /sys/kernel/security/bpfima/policy
```

### Filter Small Files
```bash
echo "min_file_size=4096" > /sys/kernel/security/bpfima/policy
```

### Update from YAML
```bash
sudo bpfima-tool policy-update config/policy-minimal.yaml
```

## Troubleshooting

**Policy not applied?**
```bash
dmesg | grep bpfima | tail -20
```

**Check current settings:**
```bash
cat /sys/kernel/security/bpfima/policy
sudo bpftool map dump pinned /sys/fs/bpf/bpfima_policy_map
```

**Policy reset after reboot?**

Create a systemd service:
```ini
[Unit]
Description=BPF IMA Policy
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/bpfima-tool policy-update /etc/bpfima/policy.yaml
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```
