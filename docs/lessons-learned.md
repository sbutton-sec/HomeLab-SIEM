# Lessons learned

These are the things I'd tell myself before starting, grouped by topic. Each one comes from something that went wrong or nearly went wrong during the project.

## Working safely on live systems

1. Long pastes into a terminal can look garbled even when the file is fine, and sometimes really are broken, so I paste long files in chunks and check them on the server (line count, checksum, XML or Python parse) before installing.
2. After every config change I check that the file actually changed (time and size) and that the service log confirms it loaded. One `tee -a` append silently did nothing.
3. I read the shell prompt before pasting. The manager and the agents have different file layouts, and I once pasted server commands on the Proxmox host.
4. A shell glob inside `sudo` (`sudo ls /var/ossec/x/*`) fails, because my own shell expands the `*` before sudo runs. `sudo grep -r` or `sudo ls dir | grep` avoids it.
5. SSH changes get `sshd -t`, a reload, and a new login from a second window before I close the first.
6. Backups don't belong in a Wazuh group's shared folder, because everything in that folder is pushed to the agents.
7. Removing a small package can take a metapackage with it (telnet took `ubuntu-standard`), so I check `apt-get -s autoremove` afterwards.

## Writing rules and decoders

8. I don't rely on the order of sibling rules. Each child rule adds one condition to its parent.
9. `<srcip>!x</srcip>` doesn't negate in current Wazuh. `negate="yes"` does.
10. I count events per attempt, not per log line, and give frequency rules an `ignore` period.
11. I check for built-in rules before writing my own. Proxmox already had a decoder and a brute-force rule.
12. Unusual field formats (`::ffff:10.66.66.66`) are easier to match in the log text with PCRE2.
13. Only decoded fields expand in rule descriptions. `$(agent.name)` came out blank, `$(file)` works.
14. Wazuh's `sregex` isn't a regex. It only understands `^`, `$` and `|`, so my `\.` and `[a-z0-9]+` never matched, and one of them was a privacy setting.
15. Before publishing I reviewed a week of my own alerts, which exposed noise and that broken setting.

## Alerting and response

16. I don't turn off TLS verification to fix a certificate error. Wazuh's Python needed pointing at the system CA bundle.
17. Two alerts that look identical hide what happened, so FIM messages now say whether a file was added, changed or deleted.
18. A malicious domain should never be clickable in a notification, so I defang it.
19. Before testing anything on the network I map every firewall layer. The Pi-hole had one on its Proxmox network card and one inside the VM.
20. A response action can hit your own infrastructure. Blocking the Proxmox host on the Pi-hole cut it off from the Pi-hole completely, DNS included, which is why the allow-list matters.

## Investigating

21. A DNS-based IDS alert shows the resolver as the source. The resolver's query log names the real device and what led to the lookup.
22. Threat-feed URLs need testing before I rely on them. abuse.ch moved its exports behind an account key in October 2026.
23. DNS blocklists and IDS threat intelligence cover different sets of domains, so I run both.

## Patching, hardening and maintenance

24. An installed but unbooted kernel still counts as vulnerable software, so I reboot after kernel updates and remove old kernels.
25. When a vendor repository stops offering any updates, I check whether the product has reached end of life. Proxmox VE 8 had.
26. I trust the CIS scan but read the rule. Three checks in Wazuh's Debian 12 policy can't pass on any system.
27. I check that backups exist and are recent before trusting them. The SIEM VM had never been backed up.
28. For upgrades I back up the configs and the indexer security config, keep my own config files, check every custom rule and integration afterwards, and do one live end-to-end test.
