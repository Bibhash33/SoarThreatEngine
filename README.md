# 🛡️ Automated Threat Detection & Incident Response (SOAR) Engine

An enterprise-grade, cloud-native SOAR engine built in Python that automatically ingests IDS telemetry logs, maps threats to the **MITRE ATT&CK Framework**, executes automated OS firewall containment, and notifies security operations teams via webhook APIs.

## 🏗️ Architecture & Workflow
[ Suricata IDS ] ──(eve.json)──> [ Python Detection Engine ] ──(MITRE Mapping)
│
▼
[ SOAR Auto-Mitigation ] ──> (OS Firewall Block)
│
▼
[ Telegram / Slack Webhook Alert ]


## 🛠️ Tech Stack
* **Language:** Python 3.11
* **Security Telemetry:** Suricata IDS, JSON logs
* **Automation & Orchestration:** OS `iptables` / Windows `netsh`
* **Infrastructure:** Docker, Docker-Compose, GitHub Actions CI/CD

## 🚀 Quick Start
1. Clone the repository and configure your environment.
2. Build and run via Docker:
   ```bash
   docker-compose up --build -d