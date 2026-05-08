# purple-team-detection-validator

> ⚠️ **DISCLAIMER — Read before use**
> This tool is intended **exclusively for use in isolated lab environments** on systems you own and have explicit written permission to test. Never run against production systems, cloud environments, or any infrastructure you do not personally control. Misuse may violate computer fraud laws in your jurisdiction.

---

A Python framework for validating SOC detection coverage through controlled ATT&CK-mapped simulations. It executes safe, log-generating attack technique simulations, queries your SIEM to check whether each one was detected, and produces a coverage report with remediation guidance for every gap.

**Built for:** Security interns, junior SOC analysts, and small blue teams who want to know whether their detection rules actually fire — before a real attacker finds out they don't.

---

## The problem it solves

SOC teams write detection rules but rarely validate whether those rules trigger when an attacker performs the action they're supposed to detect. Purple teaming is the practice of running controlled attack simulations to test detection coverage. Most small-to-mid SOC teams don't do this systematically.

This framework automates the simulation → wait → query → report loop for a library of ATT&CK techniques.

---

## How it works

```
┌─────────────────────┐
│  Technique Library  │  T1059, T1046, T1003, T1078, T1566 ...
└────────┬────────────┘
         │ simulate()
         ▼
┌─────────────────────┐
│   Lab Environment   │  Generates real log artifacts (process events,
│   (Linux VM)        │  file access, auth events, network connections)
└────────┬────────────┘
         │ logs flow to
         ▼
┌─────────────────────┐
│   Elastic SIEM      │  Free, runs locally in Docker
└────────┬────────────┘
         │ siem_query.check_detection()
         ▼
┌─────────────────────┐
│   Coverage Report   │  % detected, gap list, per-technique remediation
└─────────────────────┘
```

---

## Simulated techniques

| ID | Name | Tactic | Simulation method |
|----|------|--------|-------------------|
| T1059 | Command and Scripting Interpreter | Execution | Runs benign shell commands (whoami, id) to generate process execution telemetry |
| T1046 | Network Service Discovery | Discovery | TCP connect probe on localhost across common ports |
| T1003 | OS Credential Dumping | Credential Access | Reads /etc/passwd, creates .dmp canary file, accesses /proc/self/maps |
| T1078 | Valid Accounts | Defense Evasion | Writes structured auth failure / multi-source login events to a log file |
| T1566 | Phishing (Artifact Sim) | Initial Access | Drops double-extension file, macro-doc lookalike, spawns simulated shell child process |

---

## Quick start

### 1. Prerequisites

- Python 3.11+
- A Linux VM (Ubuntu 22.04 recommended)
- Elasticsearch 8.x running locally — [Docker quickstart](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html)

### 2. Install

```bash
git clone https://github.com/YOUR_USERNAME/purple-team-detection-validator
cd purple-team-detection-validator
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure

```bash
cp config/siem_config.yaml config/siem_config_local.yaml
# Edit siem_config_local.yaml — set host, api_key
```

`siem_config_local.yaml` is gitignored and will never be committed.

### 4. Run (offline / mock SIEM — no Elastic needed)

```bash
python main.py --mock-siem
```

### 5. Run against a real Elastic instance

```bash
python main.py --config config/siem_config_local.yaml --report-format both
```

### 6. Run a subset of techniques

```bash
python main.py --techniques T1059,T1046 --mock-siem
```

### 7. Dry run (no execution, no SIEM)

```bash
python main.py --dry-run
```

---

## Output

Reports are written to `reports/` (gitignored):

```
reports/
├── coverage_20250415_143201.json
└── coverage_20250415_143201.html
```

The HTML report shows detection rate, per-technique status, and remediation guidance for each gap.

---

## Adding a new technique

1. Create `techniques/t<ID>_<name>.py`, inherit from `TechniqueBase`
2. Implement `simulate()` and `cleanup()`
3. Add to `TECHNIQUE_REGISTRY` in `techniques/__init__.py`
4. Add a `REMEDIATION_MAP` entry in `reporting/coverage_report.py`

---

## Project structure

```
purple-team-detection-validator/
├── main.py                     ← CLI entry point
├── config/
│   └── siem_config.yaml        ← template (never commit secrets)
├── techniques/
│   ├── base.py                 ← TechniqueBase abstract class
│   ├── t1059_cmd_exec.py
│   ├── t1046_network_scan.py
│   ├── t1003_credential_access.py
│   ├── t1078_account_abuse.py
│   └── t1566_phishing_artifact.py
├── simulator/
│   └── runner.py               ← orchestrates execution loop
├── detection/
│   └── siem_query.py           ← Elastic / Mock / Splunk (stub)
├── reporting/
│   └── coverage_report.py      ← JSON + HTML report generation
└── reports/                    ← gitignored output directory
```

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — open-source technique reference library (Apache 2.0)
- [Elastic SIEM](https://www.elastic.co/security)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
