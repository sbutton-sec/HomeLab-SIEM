# 04 Alerting

## Telegram for level 10 and above

I picked Telegram because it's free, it reaches my phone instantly and its bot API is one HTTPS call. Wazuh has no built-in Telegram integration, so I wrote one: [`scripts/custom-telegram`](../scripts/custom-telegram) (the launcher) and [`scripts/custom-telegram.py`](../scripts/custom-telegram.py).

The integration block in `ossec.conf` (token and chat ID redacted):

```xml
<integration>
  <name>custom-telegram</name>
  <hook_url>https://api.telegram.org/bot<TELEGRAM-TOKEN>/sendMessage</hook_url>
  <api_key><TELEGRAM-CHAT-ID></api_key>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

How it works:

- Wazuh only runs integrations whose name starts with `custom-`, and runs the launcher, which starts the Python file with Wazuh's own Python. Both files are owned by root, group wazuh, mode 750.
- The script builds a short message: an icon by level (🟡 7 to 9, 🟠 10 to 11, 🔴 12+), the agent, the rule description, the rule ID and time, and then whatever applies: source IP, user, the file change type, the network flow and domain for Suricata alerts, and the MITRE technique.
- **Malicious domains are defanged** (`verificator[.]cc`), so that Telegram can't turn them into a link someone might tap.
- It uses only the Python standard library and logs each send to `/var/ossec/logs/integrations.log`.

A real message from the incident on 26 November:

```
🟠 Wazuh level 10 - OPNsenseRouter.localdomain
Suricata HIGH severity: ThreatFox payload delivery (domain - confidence level: 100%)
Rule 100101 | 2026-11-26 16:06:38
Flow: 10.66.66.50 -> <PUBLIC-IP>:53
Domain: verificator[.]cc
```

### Problems I hit and how I fixed them

- **`CERTIFICATE_VERIFY_FAILED`.** Wazuh's bundled Python doesn't use Ubuntu's certificate store. I didn't turn verification off. Instead the script loads `/etc/ssl/certs/ca-certificates.crt` with `ssl.create_default_context(cafile=...)`.
- **The config change silently did nothing.** My first attempt to append the block with `printf ... | sudo tee -a` left `ossec.conf` unchanged, and the integrator log said "Remote integrations not configured". I now write such blocks to a private temp file with placeholders, fill the secrets in with `sed` from a hidden `read -s` prompt, append with `sudo sh -c 'cat ... >> ...'` and shred the temp file. I also check the file's size and time after every change.
- **Identical messages.** A FIM "added" and "deleted" alert looked exactly the same, so I added a `Change:` line from `syscheck.event`.
- **Missing details for Suricata.** Suricata names its field `src_ip`, not `srcip`, so the first ThreatFox alert reached my phone without a source. The script now adds `Flow:` and `Domain:` for those alerts.

## Daily summary at 09:00

[`scripts/wazuh-daily-summary.py`](../scripts/wazuh-daily-summary.py) runs from cron every morning at 09:00 ([`cron.d-wazuh-daily-summary`](../configs/server/cron.d-wazuh-daily-summary)). It reads the previous day's compressed alert file, takes the Telegram settings from the same `ossec.conf` block, and sends the total, the count per level band, the count per machine, the top 5 rules and the top 5 level-10+ rules.

The first scheduled run (covering 25 November):

```
📊 Wazuh daily summary - Wed 25 Nov 2026
Total alerts: 8332
By level: 12+: 0 | 10-11: 21 | 7-9: 439 | 3-6: 7872
By machine: OPNsenseRouter.localdomain: 7004 | siem: 566 | pihole: 534 | proxmox: 228
```

Most of that day's noise came from before the tuning I did that afternoon, and the next day's alerts confirmed the tuning held: no STUN, no app detection and no level-10 firewall alerts.
