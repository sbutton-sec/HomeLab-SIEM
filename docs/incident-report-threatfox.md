# Incident report: ThreatFox domain lookup from a household device

| | |
|---|---|
| **Date** | 26 November 2026, 16:06 SAST |
| **Detected by** | Suricata on OPNsense (ThreatFox rule) → Wazuh rule 100101 (level 10) → Telegram |
| **Severity** | Medium. Contact with a known-malicious domain, low likelihood of compromise |
| **Status** | Contained. Domains blocked, detection improved |

Malicious domains in this report are defanged (`.` written as `[.]`). Device details are left out on purpose.

## Summary

A mobile device on my LAN looked up `verificator[.]cc`, a domain that ThreatFox lists as a malware payload delivery domain with 100% confidence. The lookup happened in the same second that the device opened `www[.]flybluecrane[.]com`, the old website of a South African airline that stopped flying in February 2017. The same pattern had happened once before, on 8 October, without anyone noticing. I blocked both domains in Pi-hole and improved the alert and the DNS blocklists. The device is a phone, which makes compromise unlikely. The one open question is whether the page asked the person using it to enter anything.

## Timeline

| Time | Event |
|---|---|
| 16:06:26 | The device makes Safari search lookups, then loads several unrelated websites |
| **16:06:37** | The device asks the Pi-hole for `www[.]flybluecrane[.]com` **and** `verificator[.]cc` in the same second |
| 16:06:38 | Unbound on the Pi-hole resolves `verificator[.]cc` by asking the `.cc` registry's nameservers, Suricata on OPNsense matches the ThreatFox signature and Wazuh raises rule 100101 (two alerts) |
| 16:06:38 | Telegram alert on my phone |
| 16:07:02 | The device moves on to another airline's website |
| 16:13 | I start the triage |
| 16:17 | `verificator[.]cc` blocked in Pi-hole |
| 16:21 | `flybluecrane[.]com` and `www[.]flybluecrane[.]com` blocked, and both checked to return `0.0.0.0` |
| 16:23 to 16:27 | Telegram alert improved and two threat-intel blocklists added (see below) |

## Investigation

**1. What did the alert say?** The first Telegram message showed the rule but no source, because Suricata names the field `src_ip` and my script only looked for `srcip`. I pulled the full alert from `alerts.json` on the manager:

```
10.66.66.50 -> <PUBLIC-IP> port 53 UDP dns   (a .cc registry nameserver)
signature: ThreatFox payload delivery (domain - confidence level: 100%)
dns query: verificator[.]cc  (type A)
```

The source was the **Pi-hole itself**, and the destination was a `.cc` registry nameserver. So the Pi-hole wasn't the culprit. Its Unbound resolver was looking the domain up on behalf of another device.

**2. Which device asked?** Pi-hole keeps a query log, so I searched it for the domain:

```
2026-11-26 16:06:37  10.66.66.200  verificator[.]cc
2026-10-08 15:23:11  10.66.66.200  verificator[.]cc
```

The same device had made the same lookup seven weeks earlier. Pi-hole's network table and the OPNsense DHCP lease identified it as a phone.

**3. What was it doing?** I listed every lookup from that device two minutes either side of each event. Both times, `verificator[.]cc` was requested in the same second as `www[.]flybluecrane[.]com`, straight after a Safari search, and both times the person moved on to another airline's website within about 25 seconds. That's someone searching for flights, tapping an old result and leaving.

**4. What is the domain?** The Suricata rule's metadata says ThreatFox first listed the domain on 18 October 2026, ten days *after* the device's first lookup on 8 October, so the earlier visit couldn't have been caught by this rule even if I'd been watching. I couldn't find the exact public ThreatFox entry in a quick search. Similar "verify" domains on ThreatFox are mostly fake "verify you're human" pages from the ClickFix and ClearFake families, which try to get a person to paste a command into a Windows or Mac computer. That's an assumption based on the name, not something I confirmed. Fly Blue Crane stopped operating in February 2017 and its website went offline, so its address being alive and loading a script from a malicious domain fits a common pattern: an abandoned or hijacked website serving malicious code.

## Assessment

- **True positive:** the device really did contact a known-malicious domain.
- **Compromise unlikely:** the device is a phone, and the usual payload from lures like this needs a desktop command line. The more realistic risk is a phishing page asking for card or login details.
- **Open question:** whether the page asked the person to enter or "verify" anything. If it did, those details should be treated as exposed.

## Containment and improvements

| Action | Why |
|---|---|
| Blocked `verificator[.]cc`, `flybluecrane[.]com` and `www[.]flybluecrane[.]com` in Pi-hole | No device on the network can reach them again |
| Telegram alert now shows `Flow:` and a defanged `Domain:` for Suricata alerts | The next alert of this kind has the answer to "who and what" in the message, without making the domain clickable |
| Added two malware and phishing blocklists to Pi-hole (599 and 16,250 domains) | Broader protection for the same kind of risk |

I tried abuse.ch's own ThreatFox and URLhaus host files first, and both returned **HTTP 410**: since 21 October 2026 abuse.ch exports need a free account key. The community lists I added instead work, but neither contains `verificator[.]cc`. **Suricata's ThreatFox rules caught what the DNS lists would have missed**, which is a good argument for running both layers. Getting a key for the official ThreatFox feed is on the [roadmap](roadmap.md).

## What went well and what didn't

- **Went well:** the alert reached my phone within a second, and the SIEM alert plus the Pi-hole query log answered "which device, which website, has it happened before" in about ten minutes.
- **Didn't:** the first alert lacked the source and the domain.
- **Worth remembering:** the 8 October lookup wasn't flagged at all, because ThreatFox only listed the domain ten days later. Searching back through the DNS logs after a new detection found it, which is a good reason to keep those logs.
