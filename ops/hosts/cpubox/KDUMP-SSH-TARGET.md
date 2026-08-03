# authoritative-node kdump — SSH dump target on the fallback host

**Status: ACTIVE since 2026-07-18.** `kdump.service` is active and enabled,
`kexec_crash_loaded=1`, `kdumpctl status` reports "Kdump is operational". Activation required NO
reboot and did not disturb the box (uptime continuous, 15 containers, 0 failed units).

## Why SSH instead of a local dump

Every filesystem on the authoritative node is LUKS-encrypted (`/`, `/var`, `/var/log`, `/home` are LVM inside
`luks-61b5045d-<uuid>`; `/data` is a separate `data_crypt`). `kdump.service` failed with:

    kdump: Error: Could not unlock the LUKS device.
    kdump: Failed to get logon key kdump-cryptsetup:vk-61b5045d-<luks-uuid>
    kdump: kexec: failed to prepare for a LUKS target

The crash kernel has no key, so it cannot write to any local target. "Point it at an unencrypted
filesystem" is not available here — there isn't one. Dumping over SSH sidesteps the key problem
entirely: the crash kernel needs only a network driver.

The kernel DOES support the alternative (LUKS volume-key reuse: `CONFIG_CRASH_DM_CRYPT=y`,
`/sys/kernel/config/crash_dm_crypt_keys` present, systemd 257, 1024M reserved vs 512M
recommended). That route needs a `crypttab` volume-key-link option and a REBOOT to take effect,
and it touches the boot unlock path on a headless LUKS-root box. SSH was chosen because it
touches neither.

## What is set up

Receiver — the fallback host (56G free):
  - user `kdumpdrop` (home `/var/crash-remote`, mode 700); dump dir `/srv/crash-remote/the authoritative node`
    on **vg1-srv, 1.4T XFS with 1.3T free** — NOT the 56G root volume. `df -h / /data` on this
    host prints `/` twice because `/data` does not exist, which is how the big drive was missed
    on the first pass.
  - `authorized_keys` entry restricted: `no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding`

Sender — the authoritative node:
  - dedicated key `/root/.ssh/kdump_id_rsa` (mode 600, no passphrase — kdump runs unattended)
  - **RSA-4096, not ed25519**: `/proc/sys/crypto/fips_enabled` reads 0, but
    `update-crypto-policies --show` returns **FIPS**, which bars ed25519. ssh-keygen fails with
    "ED25519 keys are not allowed in FIPS mode". Check the crypto-policy, not just the sysctl.
  - `/etc/kdump.conf`: local `path /var/crash` commented out; `ssh` / `sshkey` /
    `path /srv/crash-remote/the authoritative node` added. Backup at `/etc/kdump.conf.bak-*`.

## Verified

    auth:      "AUTH OK as kdumpdrop@the fallback host; writable: yes"
    transport: 20MB piped over the kdump key -> received exactly 20971520 bytes
               (byte-exact confirms the tsrecorder session banner does not pollute the stream)
    config:    kdumpctl parses it; "Reserved 1024MB memory for crash kernel"

## Activation (needs a maintenance window)

    sudo kdumpctl restart && sudo kdumpctl status     # expect "Kdump is operational"

`kdumpctl restart` rebuilds the kdump initramfs via dracut. That is the same operation that ran
at 18:30 on 2026-07-18, roughly four minutes before the authoritative node went down uncleanly — journal
truncated, no clean shutdown sequence, no hardware error logged, and no dump to explain it
because kdump was broken. Causation was never established, but that is exactly why this last
step waits for a window rather than running unattended.

To prove a dump end to end you must deliberately crash the box:

    echo c | sudo tee /proc/sysrq-trigger

Never unattended. the authoritative node does auto-unlock LUKS via clevis (token 0, keyslot 2), so it recovers
without console access — but the asg-crm container stack does NOT come back on its own unless
`podman-restart.service` is enabled (it now is).


## Activation notes (learned the hard way)

Two things only surfaced when actually activating:

1. **`makedumpfile -F` is mandatory for SSH targets.** They stream over a pipe, so the collector
   must emit flattened format. Without it: "The specified dump target needs makedumpfile -F
   option" and `mkdumprd: failed to make kdump initrd`.
2. **dracut logs TPM2 errors** (`systemd-cryptenroll`, `libtss2-*`) while building the kdump
   initramfs. They are non-fatal — the image builds and the crash kernel loads — but they would
   matter if the LUKS volume-key route is pursued later.

Also: after a failed start, `kdumpctl restart` can load the crash kernel while systemd still
shows the unit failed. `systemctl reset-failed kdump.service && systemctl restart kdump.service`
reconciles the two views.

Still true: **"No vmcore creation test performed"** — kdump is armed but has never produced a
dump. Proving it end to end requires `echo c | sudo tee /proc/sysrq-trigger`, a deliberate crash.
Never unattended.
