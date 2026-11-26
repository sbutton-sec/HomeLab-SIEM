#!/usr/bin/env python3
"""
Homelab Wazuh SIEM - documentation collector (read-only).

Run as root on each machine:  sudo python3 /tmp/collect-docs.py
It works out which machine it is on (Wazuh server, Pi-hole or Proxmox host),
copies the relevant configs and command outputs, REDACTS secrets and public
IP addresses, and packs everything into /tmp/homelab-docs-<hostname>.tar.gz.

It changes nothing on the system. Standard library only.
"""
import datetime
import glob
import gzip
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tarfile

HOST = socket.gethostname()
OUT = f"/tmp/homelab-docs-{HOST}"
TARBALL = OUT + ".tar.gz"

# ---------------------------------------------------------------- redaction
SECRETS = [
    (re.compile(r"bot\d+:[A-Za-z0-9_-]{20,}"), "bot<TELEGRAM-TOKEN>"),
    (re.compile(r"(<api_key>)[^<]*(</api_key>)"), r"\1<TELEGRAM-CHAT-ID>\2"),
    (re.compile(r"(<password>)[^<]*(</password>)"), r"\1<REDACTED>\2"),
    (re.compile(r"(<key>)[^<]*(</key>)"), r"\1<REDACTED>\2"),
    (re.compile(r"(?im)^(\s*[\w.-]*(password|passwd|secret|token)[\w.-]*\s*[:=]\s*).+$"), r"\1<REDACTED>"),
]
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _mask_ip(m):
    text = m.group(0)
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return text
    if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        return text
    return "<PUBLIC-IP>"


def redact(text):
    for pattern, repl in SECRETS:
        text = pattern.sub(repl, text)
    return IPV4.sub(_mask_ip, text)


# ---------------------------------------------------------------- helpers
def save(name, content):
    path = os.path.join(OUT, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(redact(content))


def copy(src, name=None):
    if os.path.isfile(src):
        with open(src, errors="replace") as f:
            save(name or os.path.basename(src), f.read())
    else:
        save((name or os.path.basename(src)) + ".MISSING", f"not found: {src}\n")


def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
        return f"$ {cmd}\n{r.stdout}{r.stderr}\n"
    except Exception as e:  # noqa: BLE001 - report and continue
        return f"$ {cmd}\nERROR: {e}\n"


def runs(name, *cmds):
    save(name, "".join(run(c) for c in cmds))


# ---------------------------------------------------------------- common
def common():
    runs("system.txt",
         "hostname", "grep PRETTY_NAME /etc/os-release", "uname -r", "uptime",
         "/var/ossec/bin/wazuh-control info",
         "dpkg -l 'wazuh-*' filebeat 2>/dev/null | awk '/^.i/{print $1, $2, $3}'",
         "apt-mark showhold", "df -h /")


# ---------------------------------------------------------------- Wazuh server
def alert_files(days=8):
    today = datetime.date.today()
    files = ["/var/ossec/logs/alerts/alerts.json"]
    for d in range(1, days):
        day = today - datetime.timedelta(days=d)
        files.append(day.strftime("/var/ossec/logs/alerts/%Y/%b/ossec-alerts-%d.json.gz"))
    return files


def read_alerts(path):
    if not os.path.isfile(path):
        return
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", errors="replace") as f:
        for line in f:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def manager():
    copy("/var/ossec/etc/ossec.conf", "server/ossec.conf")
    copy("/var/ossec/etc/rules/local_rules.xml", "server/local_rules.xml")
    copy("/var/ossec/etc/decoders/0290-solaris_decoders.xml", "server/0290-solaris_decoders.xml")
    copy("/var/ossec/etc/shared/default/agent.conf", "server/shared-default-agent.conf")
    copy("/var/ossec/integrations/custom-telegram", "server/custom-telegram")
    copy("/var/ossec/integrations/custom-telegram.py", "server/custom-telegram.py")
    copy("/usr/local/sbin/wazuh-daily-summary.py", "server/wazuh-daily-summary.py")
    copy("/etc/cron.d/wazuh-daily-summary", "server/cron-wazuh-daily-summary")
    runs("server/decoder-override.diff",
         "diff -u /var/ossec/ruleset/decoders/0290-solaris_decoders.xml "
         "/var/ossec/etc/decoders/0290-solaris_decoders.xml")
    runs("server/agents.txt", "/var/ossec/bin/agent_control -l",
         *[f"/var/ossec/bin/agent_control -i {i} | grep -E 'Agent name|Status|Client version|Operating'"
           for i in ("001", "002", "003")])
    runs("server/firewall-ufw.txt", "ufw status verbose")
    runs("server/ruleset-test.txt", "/var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -3")

    certs = "/etc/wazuh-indexer/certs"
    if os.path.isfile(f"{certs}/admin.pem"):
        c = (f"--cacert {certs}/root-ca.pem --cert {certs}/admin.pem "
             f"--key {certs}/admin-key.pem")
        runs("server/indexer.txt",
             f"curl -s {c} https://127.0.0.1:9200/_cluster/health?pretty",
             f"curl -s {c} https://127.0.0.1:9200/_plugins/_ism/policies/wazuh-alerts-retention?pretty")

    # one example alert per custom rule (+ a few built-ins used in the write-up)
    wanted = re.compile(r"^(100\d{3}|5712|5763|23505)$")
    samples, stats = {}, {}
    for path in alert_files():
        for a in read_alerts(path):
            rule = a.get("rule", {})
            day = a.get("timestamp", "")[:10]
            lvl = int(rule.get("level", 0))
            s = stats.setdefault(day, {"total": 0, "lvl12": 0, "lvl10": 0, "lvl7": 0})
            s["total"] += 1
            if lvl >= 12:
                s["lvl12"] += 1
            elif lvl >= 10:
                s["lvl10"] += 1
            elif lvl >= 7:
                s["lvl7"] += 1
            rid = str(rule.get("id", ""))
            if wanted.match(rid) and (rid not in samples or a["timestamp"] > samples[rid]["timestamp"]):
                samples[rid] = a
    for rid, a in samples.items():
        save(f"server/alert-samples/rule-{rid}.json", json.dumps(a, indent=2, ensure_ascii=False))
    lines = ["date,total,level_12_plus,level_10_11,level_7_9"]
    lines += [f"{d},{v['total']},{v['lvl12']},{v['lvl10']},{v['lvl7']}" for d, v in sorted(stats.items())]
    save("server/alert-stats-by-day.csv", "\n".join(lines) + "\n")


# ---------------------------------------------------------------- Pi-hole
def pihole():
    copy("/var/ossec/etc/ossec.conf", "pihole/agent-ossec.conf")
    for f in ("/etc/ssh/sshd_config.d/10-cis-hardening.conf", "/etc/sysctl.d/60-cis-hardening.conf",
              "/etc/modprobe.d/60-cis-net-modules.conf", "/etc/security/limits.d/60-cis-core.conf",
              "/etc/profile.d/60-cis-timeout.sh", "/etc/systemd/journald.conf.d/60-cis.conf",
              "/etc/issue.net"):
        copy(f, "pihole/hardening/" + os.path.basename(f))
    runs("pihole/hardening/checks.txt",
         "sshd -T | grep -Ei '^(banner|clientalive|disableforwarding|logingracetime|macs|maxauthtries|maxstartups|permitrootlogin)'",
         "grep -E '^(NTP|System|Runtime|MaxFile)' /etc/systemd/timesyncd.conf /etc/systemd/journald.conf",
         "stat -c '%a %U:%G %n' /etc/crontab /etc/cron.d /etc/cron.daily /etc/ssh/sshd_config")
    runs("pihole/firewall-ufw.txt", "ufw status verbose")
    runs("pihole/active-response.txt",
         "grep -E '\"command\":\"(add|delete)\"' /var/ossec/logs/active-responses.log | tail -6 | cut -c1-200")
    runs("pihole/pihole.txt", "pihole -v",
         "pihole-FTL sqlite3 -header -column /etc/pihole/gravity.db "
         "\"SELECT id, enabled, number, comment, address FROM adlist;\"")
    # deny list: defang so the published file holds no live malicious domains
    deny = run("pihole deny -l").replace(".", "[.]")
    save("pihole/deny-list-defanged.txt", deny)


# ---------------------------------------------------------------- Proxmox host
def proxmox():
    copy("/var/ossec/etc/ossec.conf", "proxmox/agent-ossec.conf")
    copy("/etc/ssh/sshd_config.d/10-cis-hardening.conf", "proxmox/hardening/10-cis-hardening.conf")
    copy("/etc/chrony/conf.d/60-cis.conf", "proxmox/hardening/chrony-60-cis.conf")
    copy("/etc/issue.net", "proxmox/hardening/issue.net")
    runs("proxmox/hardening/checks.txt",
         "sshd -T | grep -Ei '^(banner|allowusers|clientalive|disableforwarding|logingracetime|macs|maxauthtries|maxstartups|permitrootlogin)'",
         "grep -n pam_wheel /etc/pam.d/su", "ps -o user= -C chronyd", "chronyc sources | head -6")
    for f in ("/etc/pve/firewall/cluster.fw", "/etc/pve/firewall/102.fw", "/etc/pve/nodes/pve/host.fw",
              "/etc/pve/jobs.cfg"):
        copy(f, "proxmox/" + os.path.basename(f))
    runs("proxmox/proxmox.txt", "pveversion", "qm list",
         "grep -H -E '^(name|onboot|startup)' /etc/pve/qemu-server/10[0-2].conf | sort -u",
         "pvesm status", "grep -rh '^[^#]' /etc/apt/sources.list /etc/apt/sources.list.d/",
         "ls -lh /var/lib/vz/dump/ | grep -E 'vma|zst'")


# ---------------------------------------------------------------- main
def main():
    if os.geteuid() != 0:
        raise SystemExit("Run as root: sudo python3 /tmp/collect-docs.py")
    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(OUT)
    common()
    roles = []
    if os.path.exists("/var/ossec/bin/wazuh-analysisd"):
        roles.append("wazuh-server")
        manager()
    if shutil.which("pihole"):
        roles.append("pihole")
        pihole()
    if shutil.which("pveversion"):
        roles.append("proxmox")
        proxmox()
    save("README.txt", f"Collected on {HOST} at {datetime.datetime.now():%Y-%m-%d %H:%M}; roles: {', '.join(roles)}\n"
                       "Secrets and public IPs redacted by collect-docs.py.\n")

    # safety net: refuse to package anything that still looks like a token
    leaks = []
    for root, _, files in os.walk(OUT):
        for fn in files:
            with open(os.path.join(root, fn), errors="replace") as f:
                if re.search(r"bot\d+:[A-Za-z0-9_-]{20,}", f.read()):
                    leaks.append(fn)
    if leaks:
        raise SystemExit(f"STOPPED: possible Telegram token left in {leaks} - nothing packaged.")

    with tarfile.open(TARBALL, "w:gz") as tar:
        tar.add(OUT, arcname=os.path.basename(OUT))
    os.chmod(TARBALL, 0o644)
    count = sum(len(f) for _, _, f in os.walk(OUT))
    print(f"Roles: {', '.join(roles)}  |  {count} files  |  {TARBALL} ({os.path.getsize(TARBALL) // 1024} KB)")


if __name__ == "__main__":
    main()
