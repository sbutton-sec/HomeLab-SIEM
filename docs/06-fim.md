# 06 File integrity monitoring

## Design

The agents already ran a scheduled integrity scan every 12 hours over `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` and `/boot`. That catches changes eventually, but an attacker who adds an SSH key or a cron job wants to be found as late as possible, so I added **real-time** monitoring for the places used for persistence and access.

Real-time monitoring (inotify) works on directories, not single files, so I watch the folders, and single files like `/etc/passwd` and `/etc/shadow` stay on the scheduled scan. Account changes are caught immediately anyway by the log rules (a new user raises rule 100520).

The config lives in the shared file for the `default` group ([`configs/server/shared-agent.conf`](../configs/server/shared-agent.conf)), so the manager pushes it to every agent:

| Scope | Real-time paths | Notes |
|---|---|---|
| All Linux agents | `/etc/ssh`, `/etc/sudoers.d`, `/etc/cron.d`, `/etc/cron.hourly` … `/etc/cron.monthly`, `/etc/systemd/system`, `/root/.ssh`, `/home` (only `authorized_keys`) | `report_changes` on text configs so the alert shows the diff |
| Pi-hole | `/etc/pihole` (only `pihole.toml`), `/etc/unbound` | No diff for `pihole.toml` because it holds the web password hash |
| Proxmox | `/etc/pve` (scheduled, not real time) | It's a cluster filesystem (FUSE); dot-files, `priv/` and `lrm_status` are ignored |

**Keeping secrets out of alerts.** `report_changes` puts file diffs into alerts, so a `nodiff` rule excludes host keys (`_key$`) and private user keys (`id_rsa`, `id_ed25519` and the others).

## A mistake I found in my own patterns

Wazuh's `sregex` pattern type only understands `^`, `$` and `|`, and treats everything else literally. My first version used `\.` and `[a-z0-9]+`, which looked fine but never matched:

- the Proxmox dot-files I meant to ignore (`.rrd`, `.version`, `.clusterlog`) kept raising alerts, which is how I spotted it, and
- the `nodiff` for private keys (`/id_[a-z0-9]+$`) didn't cover `/root/.ssh/id_*`. Host keys were covered, and no private key had changed, so nothing leaked.

I replaced both with plain literal alternatives and ran `verify-agent-conf` before the agents picked them up.

## Alert rules

Four custom rules sit on top of the built-in FIM rules (550 modified, 553 deleted, 554 added): 100600 (level 12, access files), 100601 (level 10, cron and systemd), 100602 (DNS config) and 100603 (Proxmox config). See [03 Detection rules](03-detection-rules.md).

## Tests

| Test | Result |
|---|---|
| `touch` then `rm` of `/etc/cron.d/wazuh-fim-test` on the Pi-hole | Two rule 100601 alerts, both delivered to Telegram within seconds |
| Adding my SSH hardening file on the Pi-hole and changing permissions on `sshd_config` | Three 🔴 level-12 alerts (100600): one `added`, two `modified` |
| The same on Proxmox | 100600 at level 12 ([sample](../samples/alerts/rule-100600.json)) |
| After the Wazuh upgrade | Repeated the cron test: `Change: added` reached Telegram within seconds |

The first test showed that `added` and `deleted` messages looked identical, which led to the `Change:` line in the Telegram script.
