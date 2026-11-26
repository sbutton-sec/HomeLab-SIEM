# 10 Upgrade runbook: Wazuh 4.14.9 to 4.14.11

Wazuh 4.14.11 came out on 25 November 2026. It's a cumulative bug-fix release (it includes 4.14.10) with hardening fixes and no breaking changes for this setup. One change matters to anyone relying on defaults: the `df -P` disk check was removed from the default `ossec.conf`. My config file isn't replaced on upgrade, so nothing changed for me.

I followed Wazuh's official order (indexer, manager, Filebeat template, dashboard, then agents) with three changes for my setup:

- **Indexer API calls in Dev Tools**, because `curl -u admin` returned "Unauthorized" for me.
- **Keep my config files.** The guide says to take the new version of each config file and re-apply your settings. For a patch release I answered `N` to keep mine instead, so that the certificate paths and memory settings couldn't be lost. None of the files I'd changed were touched.
- **Holds.** For each package: unhold, install the exact version, hold again.

## Before

1. Proxmox snapshot of the SIEM VM (`before_wazuh_4_14_11`), on top of that afternoon's full backup.
2. A tar of every config I'd changed: `/var/ossec/etc`, the integrations, `/etc/wazuh-indexer`, `/etc/wazuh-dashboard`, `/etc/filebeat`, and the daily-summary script and cron file.
3. A copy of the indexer security folder, then Wazuh's security backup:
   ```bash
   sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh --options "-backup /etc/wazuh-indexer/opensearch-security -icl -nhnv"
   ```
   This exports the **live** users and roles, including my changed admin password, so the upgrade can't reset them.
4. Health check (`GET _cluster/health`), then in Dev Tools:
   ```
   PUT _cluster/settings
   { "persistent": { "cluster.routing.allocation.enable": "primaries" } }

   POST _flush
   ```

## Upgrade

```bash
# stop everything, indexer last
sudo systemctl stop filebeat wazuh-dashboard wazuh-manager
sudo systemctl stop wazuh-indexer

# indexer
sudo apt-mark unhold wazuh-indexer
sudo apt-get install wazuh-indexer=4.14.11-1
sudo apt-mark hold wazuh-indexer
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-indexer
sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh      # "Done with success"

# manager
sudo apt-mark unhold wazuh-manager
sudo apt-get install wazuh-manager=4.14.11-1
sudo apt-mark hold wazuh-manager
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-manager

# Filebeat: new alert template, same Filebeat version (7.10.2)
sudo curl -so /etc/filebeat/wazuh-template.json \
  https://raw.githubusercontent.com/wazuh/wazuh/v4.14.11/extensions/elasticsearch/7.x/wazuh-template.json
sudo chmod go+r /etc/filebeat/wazuh-template.json
sudo systemctl start filebeat
sudo filebeat setup --pipelines
sudo filebeat setup --index-management -E output.logstash.enabled=false
sudo filebeat test output                                       # "talk to server... OK"

# dashboard
sudo apt-mark unhold wazuh-dashboard
sudo apt-get install wazuh-dashboard=4.14.11-1
sudo apt-mark hold wazuh-dashboard
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-dashboard
```

Then in Dev Tools: allocation back to `all`.

Held packages show as `hi` rather than `ii` in `dpkg -l`, so check versions with `awk '/^.i/'`.

## Checks afterwards

| Check | Result |
|---|---|
| Versions | Indexer, manager and dashboard 4.14.11-1, all held |
| Custom rules | 27 rules, `wazuh-analysisd -t` OK |
| Telegram, active response and allow-list in `ossec.conf` | All present, integration files intact |
| Decoder override | Only my added lines differ from the new built-in file |
| Alerts reaching the indexer | Newest alert 16:58:01, after the restart |
| End to end | FIM test on the Pi-hole reached Telegram on the new version |
| Cluster | Green after fixing the ISM replica settings (see [05 Reporting](05-reporting.md)) |

## Agents

```bash
sudo apt-mark unhold wazuh-agent
sudo apt-get install wazuh-agent=4.14.11-1
sudo apt-mark hold wazuh-agent
sudo systemctl restart wazuh-agent
```

The Pi-hole and Proxmox agents are on 4.14.11. OPNsense's agent is managed by its plugin and stays on 4.14.9, which is supported because it's older than the manager, not newer.

One odd detail: the manager reports `WAZUH_REVISION="rc2"`, which is unusual for a release package. It doesn't affect anything, but I've noted it.
