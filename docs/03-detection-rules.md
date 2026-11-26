# 03 Detection rules

All custom content is in [`configs/server/local_rules.xml`](../configs/server/local_rules.xml) and one decoder file. There are 27 rules in four batches. I tested the log-based rules with `wazuh-logtest` using real log lines before restarting the manager, and then again with real activity (logins, failed passwords, new users). `wazuh-logtest` can't replay file integrity events, so I tested the FIM rules by creating and deleting real files.

## The OPNsense decoder fix

OPNsense writes its web GUI log under the program name `audit`, which is the same name Solaris BSM uses, so Wazuh's built-in `solaris_bsm` decoder grabbed these lines and pulled out no useful fields. Wazuh doesn't let you put a custom decoder in front of a built-in one by order alone, so I:

1. excluded the built-in file in `ossec.conf` (`<decoder_exclude>ruleset/decoders/0290-solaris_decoders.xml</decoder_exclude>`),
2. copied it to `/var/ossec/etc/decoders/` and
3. added four OPNsense decoders **above** `solaris_bsm` in that copy.

The decoders pull out the user name, the source IP and the PHP page. [`decoder-override.diff`](../configs/server/decoder-override.diff) shows that my copy differs from the built-in file only by those added lines, which I checked again after the 4.14.11 upgrade.

## The rules

| ID | Level | Parent and condition | What it means | MITRE |
|---|---|---|---|---|
| **Suricata (OPNsense IDS)** |||||
| 100100 | 0 | 86601 + signature starts "ET INFO … (STUN" | STUN from voice and video calls, ignored | |
| 100101 | 10 | 86601 + severity 1 | Suricata high severity | |
| 100102 | 7 | 86601 + severity 2 | Suricata medium severity | |
| 100103 | 3 | 100102 + ".biz TLD" signature | Lookups of .biz domains, informational (batch 4) | |
| **OPNsense web GUI** |||||
| 100200 | 0 | decoded as `opnsense-audit` | Grouping rule | |
| 100201 | 3 | 100200 + "Successful login for user" | GUI login from the LAN | |
| 100204 | 12 | 100201 + source **not** in the LAN | GUI login from outside my networks | T1078 |
| 100203 | 7 | 100204 + source in WireGuard | GUI login over the VPN | |
| 100205 | 3 | 100200 + "User logged out" | GUI logout | |
| 100206 | 5 | 100200 + "Web GUI authentication error" | One failed GUI login | |
| 100207 | 10 | 5 × 100206 in 120 s from the same IP, then quiet for 300 s | GUI brute force | T1110.001 |
| **Firewall blocks** |||||
| 100300 | 10 | 87702 + source in the LAN | A LAN device is repeatedly being blocked | |
| 100302 | 3 | 87702 + source **not** in the LAN | Internet background noise (was level 10) | |
| 100301 | 10 | 100302 + source in WireGuard | A VPN device is repeatedly being blocked | |
| **SSH and sudo (all Linux agents)** |||||
| 100500 | 12 | 5715 + source **not** in the LAN | SSH login from outside my networks | T1078 |
| 100501 | 7 | 100500 + source in WireGuard | SSH login over the VPN | |
| 100502 | 10 | 5715 + LAN source + user `root` | Direct root SSH login | T1078.003 |
| 100504 | 3 | 100502 + host `pve` + source 10.66.66.66 | Expected root login to Proxmox from my PC (batch 4) | |
| 100503 | 8 | 5715 + LAN + not root + 22:00 to 06:00 | Out-of-hours SSH login | |
| 100510 | 8 | 5402 + 22:00 to 06:00 | Out-of-hours sudo to root | T1548.003 |
| 100520 | 10 | 5902 | New local user account (built-in level is 8) | T1136.001 |
| **Proxmox web GUI** |||||
| 100400 | 12 | 87201 + `rhost` **not** LAN or VPN | Failed Proxmox login from outside my networks | T1110 |
| 100401 | 10 | 87203 + user `root` | Proxmox GUI login as root (I normally use a named admin account) | T1078.003 |
| **File integrity (children of built-in 550, 553, 554)** |||||
| 100600 | 12 | path in `/etc/ssh`, `/etc/sudoers*`, `/root/.ssh`, `/home/*/.ssh` | Change to a critical access file | T1098 |
| 100601 | 10 | path in `/etc/cron*`, `/etc/systemd/system` | Possible persistence | T1053 |
| 100602 | 10 | `pihole.toml` or `/etc/unbound` | DNS server configuration changed | |
| 100603 | 10 | path in `/etc/pve` | Proxmox configuration changed | |

Built-in rules I rely on and left alone: 87202 (Proxmox login brute force), 5712 and 5763 (SSH brute force, used by [active response](09-active-response.md)), 23505 (vulnerability found) and the SCA rule 19007.

## How I structured them

- **One condition per child rule.** My first version had a "catch-all" sibling rule with no condition next to more specific siblings, and the catch-all won. Wazuh doesn't promise an order between siblings, so each child now adds exactly one condition to its parent (for example 100201, then 100204 for "outside the LAN", then 100203 for "but inside the VPN").
- **Negation uses `negate="yes"`.** Writing `<srcip>!10.66.66.0/24</srcip>` gave inverted results. The Wazuh mailing list confirmed the `!` prefix doesn't work for this field.
- **Count attempts, not log lines.** One wrong OPNsense password writes three audit lines, so a brute-force rule built on all three fired after only two attempts. Rule 100207 counts only the "Web GUI authentication error" line, and `ignore="300"` stops it repeating every few seconds during an attack.
- **Check what's already there.** Proxmox already had a decoder and a brute-force rule (87201 to 87203), so I only added the "outside my networks" and "root" cases.
- **Odd field formats.** Proxmox logs source addresses as `::ffff:10.66.66.66`, so 100400 matches the log text with PCRE2 instead of using `<srcip>`.
- **Only decoded fields expand in descriptions.** `$(agent.name)` came out blank even in live alerts, so I removed it. `$(file)` in the FIM rules does expand.

## Tuning from real data (batch 4)

Before publishing I collected a week of alerts and looked at what was actually reaching my phone:

- **100502** fired five times in a day for my own root logins to Proxmox. Proxmox has no sudo, so root over SSH from my PC is normal there. Rule 100504 lowers exactly that case (host `pve` and source 10.66.66.66) to level 3, and a root login anywhere else still alerts at level 10.
- **100102** (Suricata medium) was firing about 55 times a day for `.biz` lookups from a LAN device. Rule 100103 lowers that one signature to level 3.
- **Most of the jump in level 7 to 9 alerts** on 26 November was my own work (321 package events from patching and about 150 CIS results from rescans), so I left those rules alone.

All three cases were checked with `wazuh-logtest` before the restart: the Proxmox line ended at 100504 (level 3), the same line from the Pi-hole still ended at 100502 (level 10), and a real `.biz` alert ended at 100103 (level 3).

## Example alerts

[`samples/alerts/`](../samples/alerts/) holds one real alert for each rule that fired during the project. The log-based rules without a sample (logins from outside, VPN logins, Proxmox failures from outside) haven't happened for real, and I tested them with `wazuh-logtest`. The out-of-hours rules (100503, 100510) use the server's clock, so they still need a real night-time login to confirm them, and rule 100602 (DNS config changes) hasn't fired yet. Both are on my test list.
