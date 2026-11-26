# Roadmap

| Priority | Item | Why |
|---|---|---|
| High | Upgrade Proxmox VE 8 to 9 | VE 8 reached end of life on 31 August 2026, so the hypervisor, its kernel and QEMU get no more fixes. Backups are in place, and the next step is Proxmox's `pve8to9` checker. |
| High | Off-host copy of the VM backups | The backups sit on the same disk as the VMs |
| Medium | Confirm the out-of-hours rules (100503, 100510) and the DNS config rule (100602) with real events | They haven't fired for real yet |
| Medium | Disk space alert below 100% | Wazuh's built-in disk rule only fires at 100%, and 4.14.11 removed `df -P` from the default config. My Proxmox disk reached 93% unnoticed. |
| Medium | Tune vulnerability alerts (rule 23505) for Telegram | Patching Proxmox produced 13 level-10 messages at once for CVEs with no fix yet |
| Medium | Free abuse.ch account for the official ThreatFox feed in Pi-hole | The account key would have to stay out of this repo |
| Medium | auditd on the Proxmox host | About 25 more CIS checks, and better command-level visibility |
| Low | Indexer memory | The heap is 1 GB on an 8 GB VM |
| Low | Pi-hole disk discard and `fstrim` | Its backup is 14 GB for a small VM |
| Low | Delete the retired Docker VM (105) | Frees a 200 GB disk |
| Low | Rules for more OPNsense apps (gateways, WireGuard, pkg) | Needs real log samples first |
| Low | Named admin account in OPNsense | GUI logins currently use `root` |
| Low | Find the LAN device behind the regular `.biz` lookups | Tuned down to level 3, but still unexplained |
| Low | Pi-hole update (Core 6.6, FTL 6.9) | Small updates waiting |
