# Purple Team Detection Validation Framework (Realistic Edition)

> ⚠️ **DISCLAIMER — Read before use**  
> This tool is intended **exclusively for use in isolated security lab environments** on systems you own and have explicit written permission to test. Never run against production systems, corporate assets, or any infrastructure you do not personally control. Misuse may violate computer fraud laws in your jurisdiction.

---

A modular, lightweight Python validation framework designed to test SOC detection coverage against standard MITRE ATT&CK techniques. It automatically executes real Linux security simulations on your local machine, waits for Filebeat to harvest the generated telemetry, queries a local Dockerized Elasticsearch instance to verify if raw logs are visible, and compiles detailed Markdown and JSON coverage reports.

---

## 🏗️ How It Works

```
                        YOUR LOCAL MACHINE (WSL / KALI LINUX)
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                                                                  │
│   1. CLI Execution (main.py)                                                     │
│      ├── Reads Yaml Technique Definitions (T1046, T1105, T1078, etc.)            │
│      ├── Spawns Subprocess command pipelines                                    │
│      └── Appends ECS-compliant JSON events to /tmp/purpleteam/events.log         │
│                                                                                  │
│   2. Log Shipper (Filebeat Container)                                            │
│      ├── Harvests custom events (/tmp/purpleteam/events.log)                     │
│      ├── Harvests system auth events (/var/log/auth.log)                         │
│      └── Ships documents directly into local Elasticsearch                       │
│                                                                                  │
│   3. Query Engine (siem_querier.py)                                              │
│      ├── Queries ES directly for raw log visibility within the lookback window   │
│      └── Resolves detection status: DETECTED | NOT_DETECTED | PIPELINE_ERROR     │
│                                                                                  │
│   4. Report Engine (report_engine.py)                                            │
│      ├── Compiles timestamped JSON metadata logs & Markdown reports              │
│      └── Outputs actionable remediation advice and Sigma links for all gaps     │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Architecture

```
purple-team-detection-validator/
│
├── docker-compose.yml       # Provisions single-node ES, Kibana, & Filebeat (8.13.0)
├── filebeat.yml             # Harvests logs, ships custom indices to Elasticsearch
├── config.yaml              # Configures ES URL, lookback window, and delay settings
│
├── techniques/              # Data-driven ATT&CK techniques (YAML format)
│   ├── t1046.yaml           # T1046: Network Service Discovery (nmap sweep)
│   ├── t1105.yaml           # T1105: Ingress Tool Transfer (curl download)
│   ├── t1078.yaml           # T1078: Valid Accounts (failed SSH login loop)
│   ├── t1070_004.yaml       # T1070.004: Indicator Removal (touch/delete log file)
│   └── t1059_004.yaml       # T1059.004: Command and Scripting (obfuscated base64 shell)
│
├── technique_schema.py      # Dataclass model and YAML parsers (PyYAML)
├── executor.py              # Platform-native subprocess executor
├── siem_querier.py          # Elasticsearch search engine (requests)
├── report_engine.py         # Metrics calculations and Markdown / JSON reporter
├── orchestrator.py          # Framework orchestration flow logic
└── main.py                  # Thin entrypoint wrapper
```

---

## ⚙️ Environment Setup

Ensure you are working inside your **WSL (Kali/Ubuntu) Linux setup** or native Linux host, with Docker Desktop running on the Windows host (WSL Integration enabled).

### 1. Configure the Docker Stack
Bring up the single-node Elasticsearch 8.13.0, Kibana 8.13.0, and Filebeat 8.13.0 containers. Permission checks are disabled to allow mounting configurations cleanly on WSL:
```bash
sudo docker compose up -d
```
Verify the services are active:
```bash
sudo docker compose ps
```

### 2. Install Python Dependencies
Ensure you have Python 3.10+ installed. Activate a virtual environment and run the installation command:
```bash
pip install -r requirements.txt
```

---

## 🚀 Full End-to-End Validation Run

To execute the purple team validator pipeline end-to-end:

### Step 1: Start the Validation Pipeline
Run the main execution command inside your terminal:
```bash
python main.py run
```

### Step 2: Confirm the Run Plan
The validator will print a formatted terminal plan listing all techniques mapped for simulation. Confirm by typing `y` and hitting Enter:
```text
======================================================================
  RUN PLAN
======================================================================
  Techniques to execute: 5
----------------------------------------------------------------------
  1. [T1046] Network Service Discovery (Discovery)
     Commands: 3, Cleanup: 1, Log: purpleteam-events
  2. [T1059.004] Command and Scripting Interpreter: Unix Shell (Execution)
     Commands: 2, Cleanup: 0, Log: purpleteam-events
  3. [T1070.004] Indicator Removal on Host: File Deletion (Defense Evasion)
     Commands: 4, Cleanup: 0, Log: purpleteam-events
  4. [T1078] Valid Accounts - Brute Force Login Simulation (Defense Evasion)
     Commands: 1, Cleanup: 0, Log: system-auth
  5. [T1105] Ingress Tool Transfer (Command and Control)
     Commands: 2, Cleanup: 1, Log: purpleteam-events
----------------------------------------------------------------------

  Proceed with execution? [y/N]: y
```

### Step 3: Simulation and Ingestion Delay
The framework will:
1. Execute the sequence of commands specified for each technique.
2. Wait a configurable post-execution delay (default: 25s) allowing Filebeat to harvest the logs, parse the structure, and index them into Elasticsearch.
3. Automatically run any technique cleanup commands to revert target host changes.

### Step 4: SIEM Query Checks
The framework queries the `/purpleteam-*` and `/filebeat-*` endpoints in Elasticsearch to verify if the logs are fully visible inside the time window.

### Step 5: Read the Summary Table and Reports
At the end of execution, a clean summary table is printed to your console, and timestamped `.md` and `.json` reports are created in `reports/`:
```text
==========================================================================================
  PURPLE TEAM DETECTION COVERAGE REPORT
==========================================================================================
  Techniques Tested : 5
  Detection Rate    : 100.0%
  Detected          : 5
  Not Detected      : 0
  Pipeline Errors   : 0
  Critical Gaps     : None
------------------------------------------------------------------------------------------
  STATUS            ID            NAME                                      PRIORITY  
  ----------------------------------------------------------------------------------
  [DETECTED]        T1046         Network Service Discovery                 MEDIUM    
  [DETECTED]        T1059.004     Command and Scripting Interpreter: Unix   CRITICAL  
  [DETECTED]        T1070.004     Indicator Removal on Host: File Deletion  HIGH      
  [DETECTED]        T1078         Valid Accounts - Brute Force Login Simu   HIGH      
  [DETECTED]        T1105         Ingress Tool Transfer                     HIGH      
==========================================================================================
```

---

## 🛠️ CLI Usage Guide

### Filter Executions
Run a single technique to isolate testing:
```bash
python main.py run --technique T1046
```

Filter execution to a specific ATT&CK tactic area:
```bash
python main.py run --tactic Discovery
```

### Regenerate Reports
If you want to modify the Markdown format or apply updates without re-running time-consuming shell simulations, you can regenerate complete Markdown outputs directly from your saved run JSON results file:
```bash
python main.py report --input reports/report_TIMESTAMP.json
```

### Dry Run (Syntax and Command Check)
Simulate parser and loader flow without running active commands or making network requests:
```bash
python main.py run --help
```

---

## 📖 Methodology & Custom Logging

* **What "DETECTED" means in this lab:** In this environment, a technique is marked `DETECTED` if the Elasticsearch query returns at least one matching document within the configured time window. This validates **raw log visibility and pipeline ingestion ingestion** (crucial EDR/SIEM metrics), not alert firing. In production networks, you would deploy Kibana SIEM Alerts or correlation queries to flag these matching events.
* **Adding a New Technique:** Simply drop a new `.yaml` file into the `techniques/` directory using the standard format. The framework dynamically discovers, loads, and processes any valid technique during runtime.
