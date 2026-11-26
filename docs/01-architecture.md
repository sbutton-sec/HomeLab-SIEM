# 01 Architecture

## Machines

| Role | Host | IP | OS | Wazuh |
|---|---|---|---|---|
| Hypervisor | pve | 10.66.66.22 | Proxmox VE 8.4.21 (Debian 12), i7-6700K, 15.5 GB RAM | Agent 002 `proxmox`, 4.14.11 |
| SIEM server (VM 100) | siem | 10.66.66.218 | Ubuntu 24.04.5 LTS, 4 vCPU, 7.8 GB RAM, 77 GB disk | All-in-one 4.14.11 (manager, indexer, dashboard, Filebeat) |
| Router and IDS (VM 101) | OPNsenseRouter.localdomain | 10.66.66.1 (WAN over PPPoE) | OPNsense 26.7 (FreeBSD 15.1), Suricata IDS | Agent 001 via the os-wazuh-agent plugin, 4.14.9 |
| DNS (VM 102) | ubuntu | 10.66.66.50 | Ubuntu 24.04.5 LTS, Pi-hole 6 + Unbound, 1 vCPU, 1 GB RAM | Agent 003 `pihole`, 4.14.11 |
| Admin PC | - | 10.66.66.66 | Windows | Not an agent, used for the dashboard and SSH |

Networks used in the rules: LAN `10.66.66.0/24` and the WireGuard VPN `10.10.10.0/24`. There are no VLANs or guest networks.

## How the logs flow

1. Each machine runs a Wazuh agent that reads its logs (journald, auth logs, package logs) and runs file integrity, inventory and CIS scans.
2. OPNsense sends its firewall log, its web GUI audit log and the Suricata EVE alerts through its agent. I switched off the old UDP syslog path so that every log arrives over the agent's encrypted channel (TCP 1514).
3. The manager decodes each event, runs it through the built-in rules and my 27 custom rules, and writes alerts.
4. Filebeat ships the alerts to the indexer, where the dashboard, the weekly PDF and the 90-day retention policy work on them.
5. Any alert at level 10 or above goes to Telegram through my integration script, and a cron job sends a summary of the previous day every morning at 09:00.

## Two firewall layers

While testing active response I found that the Pi-hole sits behind two firewalls with the same rules:

- **Proxmox firewall** on the VM's network card (`configs/proxmox/102.fw`), with a datacenter default of drop (`cluster.fw`).
- **UFW** inside the VM (`configs/pihole/firewall-ufw.txt`).

Both allow DNS and the web UI from the LAN and WireGuard, and SSH only from my admin PC and WireGuard. A test packet has to get through both, which is why my first brute-force test from the Proxmox host never reached SSH (see [09 Active response](09-active-response.md)). The Proxmox host itself only accepts SSH and its web UI from the admin PC (`host.fw`).

The SIEM server has UFW allowing 22, 443, 1514 and 1515 from the LAN only.

## Start order

After a host reboot the VMs start in this order, so that the network is up before anything that needs it: OPNsense first (then a 30 second wait), Pi-hole second (15 second wait), then the SIEM.
