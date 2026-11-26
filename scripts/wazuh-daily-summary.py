#!/usr/bin/env python3
# Daily Wazuh summary to Telegram (homelab, 2026-11-25)
# Reads one day of alerts from the manager's alert log and sends a short digest.
# Token and chat ID are read from the custom-telegram block in ossec.conf (no second copy).
# Usage: wazuh-daily-summary.py [yesterday|today]   (default: yesterday)
import gzip, json, re, ssl, sys, urllib.parse, urllib.request
from collections import Counter
from datetime import date, timedelta

OSSEC_CONF = "/var/ossec/etc/ossec.conf"
ALERTS_DIR = "/var/ossec/logs/alerts"
CA_FILE = "/etc/ssl/certs/ca-certificates.crt"

def telegram_settings():
    conf = open(OSSEC_CONF).read()
    block = re.search(r"<name>custom-telegram</name>.*?</integration>", conf, re.S).group(0)
    hook = re.search(r"<hook_url>(.*?)</hook_url>", block).group(1).strip()
    chat = re.search(r"<api_key><TELEGRAM-CHAT-ID></api_key>", block).group(1).strip()
    return hook, chat

def alert_lines(day):
    if day == date.today():
        path, opener = f"{ALERTS_DIR}/alerts.json", open
    else:
        path, opener = f"{ALERTS_DIR}/{day:%Y}/{day:%b}/ossec-alerts-{day:%d}.json.gz", gzip.open
    with opener(path, "rt", errors="replace") as f:
        for line in f:
            try:
                yield json.loads(line)
            except ValueError:
                continue

def band(level):
    return "12+" if level >= 12 else "10-11" if level >= 10 else "7-9" if level >= 7 else "3-6"

def build(day):
    total, bands, agents, rules, high = 0, Counter(), Counter(), Counter(), Counter()
    for a in alert_lines(day):
        r = a.get("rule", {})
        lvl = int(r.get("level", 0))
        key = f"{r.get('id', '?')} {r.get('description', '')[:60]}"
        total += 1
        bands[band(lvl)] += 1
        agents[a.get("agent", {}).get("name", "?")] += 1
        rules[key] += 1
        if lvl >= 10:
            high[key] += 1
    out = [f"\U0001F4CA Wazuh daily summary - {day:%a %d %b %Y}", f"Total alerts: {total}", ""]
    out.append("By level: " + " | ".join(f"{b}: {bands[b]}" for b in ("12+", "10-11", "7-9", "3-6")))
    out.append("By machine: " + " | ".join(f"{n}: {c}" for n, c in agents.most_common()))
    out += ["", "Top 5 rules:"] + [f"  {c} x {k}" for k, c in rules.most_common(5)]
    out += ["", "Level 10+ alerts:"] + ([f"  {c} x {k}" for k, c in high.most_common(5)] or ["  none \u2705"])
    return "\n".join(out)[:4000]

def send(text):
    hook, chat = telegram_settings()
    body = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    ctx = ssl.create_default_context(cafile=CA_FILE)
    with urllib.request.urlopen(urllib.request.Request(hook, data=body), timeout=15, context=ctx) as r:
        return r.status

if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "yesterday"
    day = date.today() if which == "today" else date.today() - timedelta(days=1)
    try:
        text = build(day)
    except FileNotFoundError as e:
        text = f"\u26A0\uFE0F Wazuh daily summary: alert file not found ({e.filename})"
    print(text)
    print("Telegram HTTP", send(text))
