# 02 Deployment

The Wazuh all-in-one server was already installed when I started, with the server itself and OPNsense reporting. This covers what I did from there.

## Baseline and hardening of the SIEM server

- Took a Proxmox snapshot (`before-config`) and a copy of `ossec.conf` before changing anything.
- Checked DNS (the server resolves through the Pi-hole) and that the vulnerability feed (`cti.wazuh.com`) is reachable, and gave the server a fixed address through an OPNsense static DHCP mapping.
- **Agent enrollment needs a password.** I set `use_password` to `yes` in the `<auth>` block and put the password in `/var/ossec/etc/authd.pass` (owner root, group wazuh, mode 640), so that a random machine on the network can't register itself as an agent.
- Changed the dashboard `admin` password.
- **Held the Wazuh packages** (`apt-mark hold`) so that an `apt upgrade` can't move the server to a new version by accident. Agents must never be newer than the manager, so I hold them as well.
- **UFW** allows 22 (SSH), 443 (dashboard), 1514 (agents) and 1515 (enrollment) from the LAN only.

## Agents

| Agent | How | Notes |
|---|---|---|
| 001 OPNsense | os-wazuh-agent plugin | Collects audit, filter, gateways, hostwatch, pkg, ppps and wireguard. I unticked remote commands in the logcollector settings. |
| 002 Proxmox host | Wazuh apt repo, enrolled with the password | journald is collected by default, which includes the Proxmox web login log |
| 003 Pi-hole | Wazuh apt repo, enrolled with the password | I set the timezone to Africa/Johannesburg first, so that log times match the server |

All three are in the `default` group, which carries the shared FIM configuration (`configs/server/shared-agent.conf`).

## Moving OPNsense from syslog to the agent

OPNsense was sending its logs twice: as plain UDP syslog to port 514 and through the agent. I disabled the remote syslog destination in OPNsense, commented out the syslog `<remote>` block in the manager's `ossec.conf` and deleted the UFW rule for 514/udp. OPNsense logs now only arrive over the agent's encrypted channel.

Before switching I turned on the archive log for a short test and checked how each OPNsense log was decoded. 186 firewall lines decoded correctly as `pf`, but the 4 web GUI audit lines were picked up by the built-in **Solaris BSM** decoder, because OPNsense uses the same program name (`audit`). That is fixed in [03 Detection rules](03-detection-rules.md).

## Suricata noise

Suricata on OPNsense had the **OPNsense-App-detect** rulesets enabled. These fire on normal use of WhatsApp, Teams, YouTube and so on, and made up the whole top 10 of my alerts (WhatsApp alone was 3,772 in a week). They are app inventory, not threats, so I disabled the six App-detect rulesets and kept the ET Open and abuse.ch rulesets.
