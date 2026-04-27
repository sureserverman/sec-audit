# libvirt / QEMU / KVM — Domain XML Hardening

## Source

- https://libvirt.org/formatdomain.html — canonical domain XML reference
- https://libvirt.org/drvqemu.html — QEMU/KVM driver reference (sVirt, namespaces, security drivers)
- https://www.qemu.org/docs/master/system/security.html — QEMU security model
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/configuring_and_managing_virtualization/ — RHEL Virtualization (canonical libvirt deployment guide)
- https://www.cisecurity.org/benchmark/kvm — CIS Linux KVM Benchmark
- https://csrc.nist.gov/publications/detail/sp/800-125b/final — NIST SP 800-125B (Secure Virtual Network Configuration for Virtual Machine Protection)
- https://csrc.nist.gov/publications/detail/sp/800-125a/rev-1/final — NIST SP 800-125A r1 (Security Recommendations for Hypervisor Deployment)

## Scope

Covers libvirt domain XML for QEMU/KVM guests on Linux: machine type (`q35` vs `i440fx`), CPU model, sVirt confinement (SELinux / AppArmor security driver), UEFI Secure Boot + measured boot (swtpm/TPM 2.0), virtio device hardening, virtfs/9p host-path passthroughs, vhost-user backends, network device modes (`hostdev`, `bridge`, `direct`, `network`), and `<seclabel>` settings. Out of scope: GUI orchestration tools (`virt-manager`, `cockpit-machines` — these emit the same XML; audit the XML, not the GUI), Cloud Hypervisor / Firecracker microVMs (different XML schema; flagged as known-out-of-scope), nested virtualization correctness (separate concern).

## Dangerous patterns (regex/AST hints)

### `<seclabel type='none'/>` — sVirt confinement disabled — CWE-693

- Why: libvirt's sVirt driver applies an SELinux (Fedora/RHEL) or AppArmor (Debian/Ubuntu) MAC label to each QEMU process and to every disk image / device file the guest owns. With sVirt enabled (default `type='dynamic'`), one compromised QEMU process cannot read another guest's disk images even on the same host, because the labels differ. `<seclabel type='none'/>` disables this — a QEMU escape lands with the labels of the QEMU service account, and every other guest's disks become readable. CIS KVM Benchmark §3 mandates sVirt-enabled. The sole legitimate use is debugging, never production.
- Grep: `<seclabel\s+[^>]*type=['"]none['"]`
- File globs: `**/*.xml` (libvirt domain XML), `*.libvirt.xml`
- Source: https://libvirt.org/drvqemu.html

### `<emulator>` runs as root — CWE-269

- Why: libvirt's `qemu.conf` defaults `user = "qemu"` / `group = "qemu"` (Fedora/RHEL) or `libvirt-qemu` (Debian); the QEMU process drops privileges before executing guest code. Operators sometimes set `user = "root"` to work around device-permission issues — this defeats every privilege-separation primitive sVirt relies on, because a QEMU escape now runs with full host root. The right fix is to set the device file ownership/group, not to run QEMU as root. NIST SP 800-125A r1 §HY-BR-13 (process isolation).
- Grep: `^\s*user\s*=\s*["']root["']` in `qemu.conf` OR domain XML `<seclabel>` referencing a root-mapped label.
- File globs: `qemu.conf`, `/etc/libvirt/qemu.conf`
- Source: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/configuring_and_managing_virtualization/

### Legacy machine type `pc-i440fx-*` instead of `q35` — CWE-1037

- Why: The `i440fx` chipset emulates a 1996 desktop PC: legacy ISA bus, no IOMMU device tree, no SMM, no ACPI table-source-tracking, and missing IOMMU group isolation that the kernel uses to enforce DMA boundaries between PCI devices. `q35` (Intel ICH9, 2009) provides PCIe with IOMMU and SMM; it is required for properly isolating PCI passthrough devices. Modern guest operating systems (any Linux ≥ 5.x, Windows Server 2019+) target `q35`. CIS KVM Benchmark §2 mandates `q35` (or `microvm` for ephemeral compute) for new deployments.
- Grep: `<os>\s*<type[^>]*machine=['"]pc-i440fx`
- File globs: `**/*.xml`
- Source: https://www.qemu.org/docs/master/system/security.html

### `<filesystem type='mount' accessmode='passthrough'>` — uid passthrough — CWE-272

- Why: `<filesystem type='mount' accessmode='passthrough'>` (the legacy 9p `passthrough` mode) maps guest UIDs directly to host UIDs — guest UID 0 writes to the host filesystem as host UID 0 (or as the QEMU service account if sVirt is enabled, but unmapped). The hardened mode is `accessmode='mapped-xattr'` or `accessmode='mapped-file'`, which stores guest ownership in xattrs on the host file (the file itself remains owned by the QEMU service account). With `passthrough`, an in-guest root attacker who escapes the 9p path-rooting boundary can write arbitrary files as host root. Replace 9p with virtiofs (post-libvirt 6.2) for performance and the proper user-namespace mapping.
- Grep: `<filesystem[^>]*type=['"]mount['"][^>]*accessmode=['"]passthrough['"]`
- File globs: `**/*.xml`
- Source: https://libvirt.org/formatdomain.html

### `<hostdev>` PCI passthrough without `<rom file=''/>` and without IOMMU group isolation check — CWE-862

- Why: PCI passthrough hands a host device's MMIO and DMA capabilities to the guest. Without IOMMU isolation (Intel VT-d / AMD-Vi), a malicious guest can use the device's DMA engine to read arbitrary host memory. The host-side preconditions are `intel_iommu=on` (or `amd_iommu=on`) on the kernel command line, and the device must be in a clean IOMMU group (no other host-critical devices share the group). Domain XML cannot enforce these — they are host-config preconditions — but XML SHOULD pin the device to a specific PCI address (`<source><address domain='0x0000' bus='0x01' slot='0x00' function='0x0'/></source>`) and explicitly disable option-ROM execution (`<rom enabled='no'/>`). Missing both is a misconfiguration.
- Grep: `<hostdev[^>]*type=['"]pci['"]` blocks WITHOUT a child `<rom enabled=['"]no['"]/>` element.
- File globs: `**/*.xml`
- Source: https://csrc.nist.gov/publications/detail/sp/800-125a/rev-1/final

### Missing `<launchSecurity type='sev'>` on confidential-compute guests — CWE-922

- Why: For threat models where the host operator is not trusted (multi-tenant cloud, compliance-bound workloads), AMD SEV / SEV-ES / SEV-SNP encrypts guest memory with a key the host cannot read. libvirt declares this via `<launchSecurity type='sev'>` (or `type='s390-pv'` on s390x); without it, the host operator can `gdb`-attach to QEMU, dump guest memory, and read everything including disk encryption keys after the guest mounts encrypted volumes. The pattern is only relevant on hosts with SEV-capable CPUs; when the threat model excludes a malicious host, this is informational, not a defect.
- Grep: domain XML for production-tagged guests where the SEV pattern is absent — flag as MEDIUM (severity contingent on the threat model).
- File globs: `**/*.xml`
- Source: https://libvirt.org/formatdomain.html

### Network mode `<interface type='direct' mode='passthrough'>` without VLAN isolation — CWE-923

- Why: `mode='passthrough'` (macvtap-passthrough) hands the host NIC's MAC address and VLAN unfiltered to the guest. Without an upstream-switch VLAN ACL, a malicious guest can spoof MAC/VLAN tags and join broadcast domains the host operator did not intend. NIST SP 800-125B §5 requires VLAN segmentation and MAC ACLs at the upstream switch when passthrough is used. The safer in-host pattern is `mode='vepa'` (with an EVB-aware switch) or `mode='bridge'` plus an explicit `<filterref filter='clean-traffic'/>` reference.
- Grep: `<interface[^>]*type=['"]direct['"][^>]*>.*<source[^>]*mode=['"]passthrough['"]`
- File globs: `**/*.xml`
- Source: https://csrc.nist.gov/publications/detail/sp/800-125b/final

## Secure patterns

Hardened minimal domain XML for a Linux guest (Q35 + UEFI Secure Boot + virtio-blk + virtio-net + sVirt):

```xml
<domain type='kvm'>
  <name>app01</name>
  <memory unit='GiB'>4</memory>
  <vcpu placement='static'>2</vcpu>
  <os firmware='efi'>
    <type arch='x86_64' machine='q35'>hvm</type>
    <firmware>
      <feature enabled='yes' name='enrolled-keys'/>
      <feature enabled='yes' name='secure-boot'/>
    </firmware>
    <loader readonly='yes' secure='yes' type='pflash'>/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd</loader>
    <nvram template='/usr/share/edk2/ovmf/OVMF_VARS.secboot.fd'/>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/><apic/>
    <smm state='on'/>
  </features>
  <cpu mode='host-passthrough' check='none' migratable='off'/>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none' io='native' discard='unmap'/>
      <source file='/var/lib/libvirt/images/app01.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
      <filterref filter='clean-traffic'/>
    </interface>
    <tpm model='tpm-crb'>
      <backend type='emulator' version='2.0'/>
    </tpm>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
    <memballoon model='none'/>
    <serial type='pty'/><console type='pty'/>
  </devices>
  <seclabel type='dynamic' model='selinux' relabel='yes'/>
</domain>
```

Source: https://libvirt.org/formatdomain.html

virtiofs host-path mount with proper id mapping (replaces 9p passthrough):

```xml
<filesystem type='mount' accessmode='mapped-xattr'>
  <driver type='virtiofs'/>
  <source dir='/srv/guest-share'/>
  <target dir='guest-share'/>
  <readonly/>
</filesystem>
```

Source: https://libvirt.org/formatdomain.html

## Fix recipes

### Recipe: replace machine type `pc-i440fx` with `q35`+UEFI — addresses CWE-1037

**Before (dangerous):**

```xml
<os>
  <type arch='x86_64' machine='pc-i440fx-7.2'>hvm</type>
  <boot dev='hd'/>
</os>
```

**After (safe):**

```xml
<os firmware='efi'>
  <type arch='x86_64' machine='q35'>hvm</type>
  <firmware>
    <feature enabled='yes' name='secure-boot'/>
  </firmware>
  <loader readonly='yes' secure='yes' type='pflash'>/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd</loader>
  <boot dev='hd'/>
</os>
<features>
  <smm state='on'/>
</features>
```

Source: https://www.qemu.org/docs/master/system/security.html

### Recipe: re-enable sVirt — addresses CWE-693

**Before (dangerous):**

```xml
<seclabel type='none'/>
```

**After (safe):**

```xml
<seclabel type='dynamic' model='selinux' relabel='yes'/>
```

Source: https://libvirt.org/drvqemu.html

### Recipe: 9p passthrough → virtiofs mapped-xattr — addresses CWE-272

**Before (dangerous):**

```xml
<filesystem type='mount' accessmode='passthrough'>
  <source dir='/srv/share'/>
  <target dir='share'/>
</filesystem>
```

**After (safe):**

```xml
<filesystem type='mount' accessmode='mapped-xattr'>
  <driver type='virtiofs'/>
  <source dir='/srv/share'/>
  <target dir='share'/>
  <readonly/>
</filesystem>
```

Source: https://libvirt.org/formatdomain.html

## Version notes

- libvirt 6.2 (April 2020) introduced `<driver type='virtiofs'/>`; older libvirts must use 9p, in which case `accessmode='mapped-xattr'` is the only acceptable mode (not `passthrough`).
- `q35` machine type requires guest OS support for AHCI/NVMe and PCIe; Windows guests pre-2008 will not boot. For legacy guests, document the i440fx-finding as MEDIUM with a "legacy-guest" suppression note rather than HIGH.
- AMD SEV-SNP (`<launchSecurity type='sev-snp'>`) requires libvirt 9.4 (June 2023) and host CPU EPYC 3rd gen+; SEV (without -SNP) is available since libvirt 4.5.
- swtpm (the `<tpm><backend type='emulator'>` form) requires the `swtpm` and `swtpm-tools` packages on the host. Without them, libvirt silently falls back to a passthrough TPM (which only works if the host has a real TPM and is willing to share it — usually undesirable).

## Common false positives

- Domain XML in `tests/fixtures/` or `examples/` directories under target — documentation/test fixtures, not deployed; downgrade.
- `pc-i440fx` on a guest explicitly tagged `<title>legacy</title>` or with a comment indicating Windows XP / legacy support — flag as MEDIUM with the legacy-guest justification documented.
- `<seclabel type='none'/>` on a domain XML used only for `virsh dumpxml` import-export workflows that are post-processed before `define` — verify the deployment path before flagging HIGH.
