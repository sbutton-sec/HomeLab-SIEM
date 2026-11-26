# Configs

Real files from the lab, collected with `scripts/collect-docs.py` and redacted (Telegram token and chat ID, passwords, keys and public IP addresses replaced).

| File | Location on the system |
|---|---|
| `server/ossec.conf` | `/var/ossec/etc/ossec.conf` on the SIEM server |
| `server/local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` (27 custom rules) |
| `server/0290-solaris_decoders.xml` | `/var/ossec/etc/decoders/` (built-in file plus the OPNsense decoders) |
| `server/decoder-override.diff` | Difference between that file and the built-in one |
| `server/shared-agent.conf` | `/var/ossec/etc/shared/default/agent.conf` (FIM for the `default` group) |
| `server/cron.d-wazuh-daily-summary` | `/etc/cron.d/wazuh-daily-summary` |
| `pihole/agent-ossec.conf`, `proxmox/agent-ossec.conf` | `/var/ossec/etc/ossec.conf` on each agent |
| `pihole/10-cis-hardening.conf`, `proxmox/10-cis-hardening.conf` | `/etc/ssh/sshd_config.d/` |
| `pihole/60-cis-hardening.conf` | `/etc/sysctl.d/` |
| `pihole/60-cis-net-modules.conf` | `/etc/modprobe.d/` |
| `pihole/60-cis-core.conf` | `/etc/security/limits.d/` |
| `pihole/60-cis-timeout.sh` | `/etc/profile.d/` |
| `pihole/journald-60-cis.conf` | `/etc/systemd/journald.conf.d/60-cis.conf` |
| `pihole/issue.net`, `proxmox/issue.net` | `/etc/issue.net` |
| `pihole/checks.txt`, `proxmox/checks.txt` | Live values after hardening (`sshd -T` and others) |
| `pihole/firewall-ufw.txt` | `ufw status verbose` |
| `pihole/deny-list-defanged.txt` | Pi-hole exact deny list, defanged |
| `proxmox/cluster.fw`, `proxmox/102.fw`, `proxmox/host.fw` | `/etc/pve/firewall/` and `/etc/pve/nodes/pve/host.fw` |
| `proxmox/jobs.cfg` | `/etc/pve/jobs.cfg` (weekly backup job) |
| `proxmox/chrony-60-cis.conf` | `/etc/chrony/conf.d/60-cis.conf` |

The SIEM server's `ossec.conf` in this repo is redacted, so it won't run as it is: the Telegram block needs a real token and chat ID.
