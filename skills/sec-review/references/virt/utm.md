# UTM — Bundle Configuration Hardening on macOS

## Source

- https://docs.getutm.app/ — UTM official documentation
- https://docs.getutm.app/settings-qemu/system/ — UTM QEMU system settings reference
- https://docs.getutm.app/advanced/sharing-files/ — host-directory sharing modes
- https://github.com/utmapp/UTM — UTM source (config schema lives in `Configuration/`)
- https://developer.apple.com/documentation/virtualization — Virtualization.framework (UTM's "Apple Virtualization" backend)
- https://developer.apple.com/documentation/hypervisor — Hypervisor.framework (UTM's QEMU-backed acceleration on Apple silicon and Intel)
- https://www.qemu.org/docs/master/system/security.html — QEMU security model (relevant when UTM uses the QEMU backend)
- https://csrc.nist.gov/publications/detail/sp/800-125a/rev-1/final — NIST SP 800-125A r1

## Scope

Covers UTM virtual-machine bundles on macOS: `*.utm` directories, the bundle's `config.plist` (the canonical settings store), backend selection (`Apple Virtualization` via Virtualization.framework vs `QEMU` accelerated by Hypervisor.framework), QEMU command-line arguments configured under `Arguments`, host-directory shares (virtfs/SPICE WebDAV/virtiofs), USB pass-through claims, and serial-console exposure. Out of scope: guest OS configuration (audited per-guest by the guest's lane — Linux/Windows/macOS-as-guest), iOS UTM SE (a separate restricted-mode build with no JIT), GUI-only "Recent VMs" history.

## Dangerous patterns (regex/AST hints)

### `Backend = QEMU` with `EnableHypervisor = false` (TCG-only) on production VM — CWE-1037

- Why: `EnableHypervisor = false` forces UTM into pure software emulation (QEMU TCG); the guest runs without Hypervisor.framework acceleration. TCG mode lacks the hardware-virtualization isolation guarantees that Hypervisor.framework provides via the host CPU's VMX/SVM extensions: there is no IOMMU enforcement, no nested-page-table isolation between guest physical and host physical memory, and significantly more attack surface in the QEMU emulator itself (every device model is software-rendered). TCG-only is acceptable for development against legacy CPU architectures (e.g. PowerPC, SPARC guests on Apple silicon) where no hardware-virt path exists. Production-tagged VMs should use Hypervisor.framework or the Apple Virtualization backend.
- Grep: `<key>EnableHypervisor</key>\s*<false/>` in `config.plist`; `<key>Backend</key>\s*<string>QEMU</string>` paired with `EnableHypervisor=false`.
- File globs: `*.utm/config.plist`
- Source: https://www.qemu.org/docs/master/system/security.html

### Host-directory share with `Mode = SPICE WebDAV` writeable — CWE-732

- Why: UTM exposes host directories to the guest via three modes: SPICE WebDAV (over the SPICE channel), virtfs (9p — covered by the libvirt-qemu pack's same CWE-272), and virtiofs (Apple Virtualization backend only). SPICE WebDAV grants HTTP-WebDAV access to the host directory from inside the guest with the host user's permissions; a writeable share over `$HOME` or any developer-tooling directory becomes a guest-to-host write primitive. Restrict shares to a dedicated host directory (`~/UTM-Shared/<vm-name>/`) and use read-only mode by default.
- Grep: `<key>SharedDirectoryReadOnly</key>\s*<false/>` AND a `<key>SharedDirectoryURL</key>` referencing a path under `$HOME` that is not a UTM-dedicated subdir.
- File globs: `*.utm/config.plist`
- Source: https://docs.getutm.app/advanced/sharing-files/

### USB device claim on host-critical device — CWE-921

- Why: UTM's `UsbForwarding` claim grabs a USB device from the host and exposes it to the guest. Claiming a host-critical device — a hardware security key (YubiKey), a smartcard reader the host uses for login, or the host's keyboard/mouse — locks the device out of host use and exposes it to in-guest exploitation (key extraction over USB protocol abuse). The legitimate use is dedicated-VM workflows (e.g. a Windows VM with a vendor-specific USB dongle); flag claims of vendor-IDs that match common security-key manufacturers.
- Grep: `<key>UsbDevices</key>` blocks containing `<key>VendorId</key>` matching `1050` (Yubico), `096E` (Feitian), `1209` (PID-codes-org generic security tokens), or `05AC` (Apple — host keyboard/mouse).
- File globs: `*.utm/config.plist`
- Source: https://docs.getutm.app/settings-qemu/system/

### Serial port over UNIX socket exposed in user-shared path — CWE-668

- Why: UTM can expose the guest's serial console over a UNIX domain socket. If the socket lives in a path accessible to other macOS users (e.g. `/tmp/`, `/var/folders/.../shared/`) and the guest is configured for a getty on serial, any host user can connect to the guest's login prompt. Restrict the socket to the user's own `~/Library/Containers/com.utmapp.UTM/Data/` or a similarly access-controlled path.
- Grep: `<key>SerialMode</key>\s*<string>UnixSocket</string>` paired with `<key>SerialURL</key>` referencing `/tmp/` or any path with mode 0777.
- File globs: `*.utm/config.plist`
- Source: https://docs.getutm.app/settings-qemu/system/

### Custom `Arguments` block bypasses UTM safety defaults — CWE-693

- Why: UTM's "Custom QEMU Arguments" `Arguments` array is concatenated into the QEMU command line after UTM's own arguments. Operators sometimes add `-monitor stdio`, `-gdb tcp::1234`, `-S` (start frozen), `-snapshot off`, or device flags that disable UTM's defaults (e.g. `-device pcnet` instead of the safer `virtio-net`). Each addition has its own risk envelope; the pattern of "unrestricted custom arguments" deserves a structural review. NIST SP 800-125A r1 §HY-BR-08 (audit hypervisor configuration) maps to this.
- Grep: `<key>Arguments</key>` array containing any of `-monitor`, `-gdb`, `-S\b`, `-snapshot off`, `-display sdl,gl=on`, `-device pcnet`, or unknown `-device` strings beyond UTM's emitted set.
- File globs: `*.utm/config.plist`
- Source: https://www.qemu.org/docs/master/system/security.html

### Boot from unsigned kernel/initrd in `Apple Virtualization` mode — CWE-345

- Why: UTM's Apple Virtualization backend supports direct kernel boot (passing `<key>VZBootLoader</key>` with `<key>LinuxBootLoader</key>` referencing host-side `kernel`/`initialRamdisk`/`commandLine`). Without verifying the kernel's signature out-of-band, a tampered host kernel image is silently booted by every VM start. The recommended pattern is GPT-bootable disk images with shim+grub or systemd-boot's signed-boot path so the chain-of-trust is rooted in firmware — not direct kernel boot from a host file.
- Grep: `<key>LinuxBootLoader</key>` block in `config.plist` referencing host-side kernel paths without an associated signature-verification step in the surrounding deployment scripts.
- File globs: `*.utm/config.plist`, deployment shell scripts
- Source: https://developer.apple.com/documentation/virtualization

## Secure patterns

Hardened `config.plist` skeleton (Apple Virtualization backend, Linux guest):

```xml
<dict>
  <key>Backend</key>
  <string>Apple</string>            <!-- Apple Virtualization, not QEMU TCG -->
  <key>VirtualizationConfig</key>
  <dict>
    <key>EnableHypervisor</key>
    <true/>
    <key>EnableSecureBoot</key>
    <true/>                         <!-- generic UEFI Secure Boot when supported by guest -->
    <key>EnableTPM</key>
    <true/>
  </dict>
  <key>SharedDirectory</key>
  <dict>
    <key>SharedDirectoryURL</key>
    <string>file:///Users/dev/UTM-Shared/devvm/</string>
    <key>SharedDirectoryReadOnly</key>
    <true/>                         <!-- read-only by default -->
  </dict>
  <key>SerialMode</key>
  <string>None</string>             <!-- no serial console exposed by default -->
  <key>UsbDevices</key>
  <array/>                          <!-- explicit empty: no USB pass-through -->
  <key>Arguments</key>
  <array/>                          <!-- explicit empty: no custom QEMU args -->
</dict>
```

Source: https://docs.getutm.app/

QEMU-backend mode hardened (when QEMU is required for non-Linux/non-macOS guest architectures):

```xml
<dict>
  <key>Backend</key>
  <string>QEMU</string>
  <key>EnableHypervisor</key>
  <true/>                           <!-- mandatory: HVF, not TCG -->
  <key>EnableUefiBoot</key>
  <true/>
  <key>QEMUConfiguration</key>
  <dict>
    <key>Machine</key>
    <string>q35</string>            <!-- modern chipset; same rationale as virt/libvirt-qemu.md -->
    <key>EnableSerial</key>
    <false/>
  </dict>
</dict>
```

Source: https://www.qemu.org/docs/master/system/security.html

## Fix recipes

### Recipe: switch from TCG-only to Hypervisor.framework — addresses CWE-1037

**Before (dangerous):**

```xml
<key>Backend</key><string>QEMU</string>
<key>EnableHypervisor</key><false/>
```

**After (safe):**

```xml
<key>Backend</key><string>QEMU</string>
<key>EnableHypervisor</key><true/>
```

Source: https://developer.apple.com/documentation/hypervisor

### Recipe: lock down host-directory share to scoped read-only — addresses CWE-732

**Before (dangerous):**

```xml
<key>SharedDirectoryURL</key><string>file:///Users/dev/</string>
<key>SharedDirectoryReadOnly</key><false/>
```

**After (safe):**

```xml
<key>SharedDirectoryURL</key><string>file:///Users/dev/UTM-Shared/devvm/</string>
<key>SharedDirectoryReadOnly</key><true/>
```

Source: https://docs.getutm.app/advanced/sharing-files/

### Recipe: drop USB claim on host-critical device — addresses CWE-921

**Before (dangerous):**

```xml
<key>UsbDevices</key>
<array>
  <dict>
    <key>VendorId</key><integer>4176</integer>   <!-- 0x1050 = Yubico -->
    <key>ProductId</key><integer>1031</integer>
  </dict>
</array>
```

**After (safe):**

```xml
<key>UsbDevices</key>
<array/>                            <!-- explicit empty: no USB pass-through -->
```

Source: https://docs.getutm.app/settings-qemu/system/

## Version notes

- UTM 4.x introduced the Apple Virtualization backend on macOS 13+; on Apple silicon it is the recommended backend for Linux guests because virtiofs delivers better performance than 9p with proper id-mapping.
- UTM SE (App Store / iPad version) is a JIT-less build; its threat model differs (no Hypervisor.framework or HVF — pure TCG) and its config is similar but lacks the backend toggle.
- The `*.utm` bundle is a directory on macOS, not a file; it contains `config.plist` plus disk images. Reviewing requires reading inside the directory — `defaults read /path/to/vm.utm/config.plist` returns the plist as JSON.

## Common false positives

- `Backend = QEMU` + `EnableHypervisor = false` on a guest architecture with no host-virt path (PowerPC, MIPS, SPARC) — this is the only way to run those guests on Apple silicon; flag as INFO not HIGH.
- A host-directory share rooted at a UTM-dedicated subpath (`~/UTM-Shared/<vm>/`) that the user has explicitly carved out — flag only when the share root is broader (e.g. `~`, `/Volumes/`, `/`).
- USB claims on vendor-IDs that match developer hardware (e.g. an Espressif ESP32 dev board, vendor 303A) — these are workflow-required and not host-critical; downgrade.
- Custom `Arguments` arrays in QEMU-backend mode that are required for legacy guest architectures (PCI quirks, custom firmware blobs) — flag as INFO with a "review individual arguments" recommendation rather than HIGH.
