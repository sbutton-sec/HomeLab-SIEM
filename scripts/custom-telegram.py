#!/usr/bin/env python3
# Wazuh -> Telegram integration (homelab, 2026-11-25)
# Called by wazuh-integratord: argv[1]=alert file, argv[2]=api_key (chat ID), argv[3]=hook_url
# hook_url = https://api.telegram.org/bot<TOKEN>/sendMessage
# Standard library only.
import json, ssl, sys, urllib.request, urllib.parse
from datetime import datetime

LOG = "/var/ossec/logs/integrations.log"
CA_FILE = "/etc/ssl/certs/ca-certificates.crt"  # Ubuntu system CA bundle

def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write(f"{datetime.now():%Y/%m/%d %H:%M:%S} custom-telegram: {msg}\n")
    except OSError:
        pass

def icon(level):
    return "\U0001F534" if level >= 12 else "\U0001F7E0" if level >= 10 else "\U0001F7E1"

def build(alert):
    rule, agent, data = alert.get("rule", {}), alert.get("agent", {}), alert.get("data", {})
    level = int(rule.get("level", 0))
    lines = [
        f"{icon(level)} Wazuh level {level} - {agent.get('name', '?')}",
        rule.get("description", "Wazuh alert"),
        f"Rule {rule.get('id', '?')} | {alert.get('timestamp', '')[:19].replace('T', ' ')}",
    ]
    if data.get("srcip"):
        lines.append(f"Source IP: {data['srcip']}")
    elif data.get("src_ip"):
        lines.append(f"Flow: {data['src_ip']} -> {data.get('dest_ip', '?')}:{data.get('dest_port', '?')}")
    dns = data.get("dns") or {}
    host = ((dns.get("queries") or [{}])[0].get("rrname") or dns.get("rrname")
            or (data.get("tls") or {}).get("sni") or (data.get("http") or {}).get("hostname"))
    if host:
        lines.append(f"Domain: {host.replace('.', '[.]')}")
    user = data.get("dstuser") or data.get("srcuser")
    if user:
        lines.append(f"User: {user}")
    event = alert.get("syscheck", {}).get("event")
    if event:
        lines.append(f"Change: {event}")
    mitre = rule.get("mitre", {}).get("id")
    if mitre:
        lines.append(f"MITRE: {', '.join(mitre)}")
    return "\n".join(lines)[:4000]

def main():
    if len(sys.argv) < 4:
        log("missing arguments"); sys.exit(1)
    alert_file, chat_id, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(alert_file) as f:
        alert = json.load(f)
    body = urllib.parse.urlencode({"chat_id": chat_id, "text": build(alert)}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(hook_url, data=body), timeout=10, context=ssl.create_default_context(cafile=CA_FILE)) as r:
            log(f"rule {alert.get('rule', {}).get('id')} sent, HTTP {r.status}")
    except Exception as e:
        log(f"send failed: {e}"); sys.exit(1)

if __name__ == "__main__":
    main()
