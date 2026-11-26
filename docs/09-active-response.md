# 09 Active response

## Design

Active response lets the manager tell an agent to run a command when a rule fires. I used the built-in `firewall-drop`, which adds a drop rule for the attacker's IP at the top of the firewall and removes it again after a timeout.

```xml
<active-response>
  <command>firewall-drop</command>
  <location>defined-agent</location>
  <agent_id>003</agent_id>
  <rules_id>5712,5763</rules_id>
  <timeout>600</timeout>
</active-response>
```

- **Triggers:** built-in rules 5712 (8 attempts with a non-existent user in 2 minutes) and 5763 (8 failed passwords in 2 minutes), both level 10 and grouped per source IP.
- **Where:** only on the Pi-hole (agent 003). I kept it off the Proxmox host, because `firewall-drop` also drops forwarded traffic, and the host bridges every VM's traffic, including the router's. A block there could cut a device off the whole network. OPNsense manages its own firewall rules, so I left it out too.
- **Timeout:** 10 minutes, so that a mistake fixes itself.
- **Allow-list:** my admin PC (10.66.66.66), the router (10.66.66.1) and the SIEM (10.66.66.218) were added to the manager's `<white_list>`, so they can never be blocked.

I checked the config with an XML parse and `wazuh-analysisd -t` before restarting the manager.

## Finding the second firewall

The Pi-hole's UFW only allows SSH from my PC and the VPN, so for the test I added a temporary rule letting the Proxmox host (10.66.66.22) in. It still timed out. Ping failed too, but TCP 53 worked, and UFW logged nothing, so the packets were being dropped **before** the VM. The Proxmox firewall turned out to have a rule set on the Pi-hole's network card that mirrors UFW exactly. I added a temporary rule there as well:

```bash
pvesh create /nodes/pve/qemu/102/firewall/rules --type in --action ACCEPT \
  --source 10.66.66.22 --proto tcp --dport 22 --enable 1 --pos 0 --comment "TEMP active-response test"
```

## The test

From the Proxmox host I connected repeatedly as a user that doesn't exist:

```bash
for i in $(seq 1 10); do ssh -o BatchMode=yes -o ConnectTimeout=5 attacker@10.66.66.50 true; sleep 1; done
```

| Time | What happened |
|---|---|
| 14:30:34 to 14:30:49 | 8 "Invalid user attacker from 10.66.66.22" lines on the Pi-hole |
| 14:30:50 | Rule 5712 fired, the manager sent `firewall-drop add` to the Pi-hole, and Telegram got the alert |
| Attempt 8 onwards | `Connection timed out` |
| 14:40:51 | `firewall-drop delete`, and the rule was gone |

```
🟠 Wazuh level 10 - pihole
sshd: brute force trying to get access to the system. Non existent user.
Rule 5712 | 2026-11-26 14:30:50
Source IP: 10.66.66.22
User: attacker
MITRE: T1110
```

On the Pi-hole the block sat above UFW's chains:

```
-P INPUT DROP
-A INPUT -s 10.66.66.22/32 -j DROP
-A INPUT -j ufw-before-logging-input
```

Detection, response and notification happened in the same second, and the block cleaned itself up 10 minutes later. Afterwards I removed both temporary allow rules and checked that both firewalls were back to their original rules.

## A side effect worth knowing

The block cuts the source off from the Pi-hole completely, not just from SSH. I think the Proxmox host resolves names through the Pi-hole, which would explain why chrony showed no time source when I restarted it during the block. A response action can hit your own infrastructure, which is why the allow-list matters, and why infrastructure hosts belong on it anywhere they could trigger a block.
