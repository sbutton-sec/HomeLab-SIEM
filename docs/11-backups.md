# 11 Backups

## What I found

Before patching the Proxmox host I checked its disk, which was **93% full** (6.9 GB free of 96 GB). 77 GB of it was VM backups in `/var/lib/vz/dump`, and looking at them showed a bigger problem than the space:

| VM | Backups found |
|---|---|
| 100 SIEM | **None, ever** |
| 101 OPNsense | Three, the newest from May 2025 |
| 102 Pi-hole | One, from December 2024 |
| 105 and 106 | 67.5 GB of backups of two VMs I'd retired |

There was also **no scheduled backup job at all**. The snapshots I'd been taking help, but a snapshot lives on the VM's own disk and doesn't survive that disk failing or the VM being deleted.

## What I changed

1. **Freed space.** I deleted the backups of the two retired VMs, after reading their notes to make sure nothing in them was worth keeping. The disk went from 93% to 44%.
2. **Fresh backups of everything,** with the VMs running (snapshot mode), including the SIEM's first ever backup: SIEM 9.7 GB, OPNsense 3.9 GB, Pi-hole 14 GB.
3. **A weekly job** (see [`configs/proxmox/jobs.cfg`](../configs/proxmox/jobs.cfg)):
   ```bash
   pvesh create /cluster/backup --schedule 'sun 02:30' --vmid 100,101,102 --storage local \
     --mode snapshot --compress zstd --prune-backups 'keep-last=2' --enabled 1
   ```
   Two weeks of backups is about 55 GB, so the disk peaks at about 62% and can't fill up again. `backup-info/not-backed-up` now lists only the retired VM.
4. **Start order** so the network comes up first after a host reboot: OPNsense, then the Pi-hole, then the SIEM.

## What's still missing

The backups sit on the same disk as the VMs, so they protect against mistakes but not against that disk dying. An off-host copy (USB drive or NAS) is on the [roadmap](roadmap.md).

The Pi-hole backup is much bigger than the VM's real data, probably because space freed inside the VM is never released by the virtual disk. Enabling discard and running `fstrim` should shrink it.
