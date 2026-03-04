# Logstory Orchestrator

Build attack flows from Google Threat Intelligence actor profiles and replay them into Google SecOps via [chronicle/logstory](https://github.com/chronicle/logstory).

**Live app:** https://keith-manville.github.io/logstory-orchestrator/

---

## What it does

1. **Threat Intel** — Search GTI/VirusTotal Enterprise for a threat actor or campaign. Extract MITRE TTPs, check `splunk/attack_data` coverage for each technique, and build an ordered attack flow in one click.
2. **Attack Flow** — Review and reorder the generated chain. Swap log variants per step (e.g. swap Sysmon for CrowdStrike on T1003.001).
3. **Datasets** — Browse all technique folders in `splunk/attack_data` live via GitHub API. Add individual datasets manually.
4. **Tenants** — Configure one or more Google SecOps tenants (customer ID + region + service account credentials).
5. **Schedule** — Set cron schedule and logstory timestamp delta.
6. **Generate** — Export a GitHub Actions workflow YAML, Python replay script, and `gh secret set` commands ready to commit to your replay repo.

## Setup

### Prerequisites

- VT Enterprise / GTI subscription (for Threat Intel tab)
- Google SecOps tenant + service account JSON credentials
- GitHub repo for the generated replay workflows

### Run locally

```bash
npm install
npm run dev
# → http://localhost:5173/logstory-orchestrator/
```

### Deploy to GitHub Pages

Push to `main` — the [deploy workflow](.github/workflows/deploy.yml) builds and publishes automatically.

Enable Pages in your repo:
> Settings → Pages → Source: **Deploy from a branch** → Branch: **gh-pages** → `/ (root)`

The app will be live at `https://keith-manville.github.io/logstory-orchestrator/` within ~60 seconds of the first push.

## API keys

API keys are entered in the app UI and held **only in browser memory** — they are never sent anywhere except the respective APIs (GTI / GitHub), and are cleared on page refresh. Nothing is persisted to any server.

| Key | Where to get it | Used for |
|-----|----------------|---------|
| GTI / VT Enterprise | virustotal.com → Profile → API Key | Threat actor TTP lookup |
| GitHub token (optional) | github.com → Settings → Developer settings → PAT | Increases GitHub API rate limit from 60 → 5,000 req/hr |

## Architecture

```
Browser (static React SPA)
  ├── GTI API (virustotal.com/api/v3)        — threat actor TTP lookup
  ├── GitHub API (api.github.com)            — enumerate splunk/attack_data folders
  └── media.githubusercontent.com            — download log files at replay time

Generated artifacts committed to replay repo:
  └── .github/workflows/logstory-replay.yml — HTTPS pull + logstory replay per tenant
```

No backend. No server. No database. Entirely static.

## Related repos

- [splunk/attack_data](https://github.com/splunk/attack_data) — log dataset source
- [chronicle/logstory](https://github.com/chronicle/logstory) — replay engine
- [MITRE ATT&CK](https://attack.mitre.org) — technique taxonomy
