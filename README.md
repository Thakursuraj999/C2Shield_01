# C2Shield: Behavioral Detection of Remote Access Tools (RATs)

## 📌 Overview
C2Shield is an academic cybersecurity project designed to explore behavioral detection of Remote Access Tools (RATs) through system-level indicators. Modern attackers often bypass signature-based defenses with custom RATs and command-and-control (C2) mechanisms. This project bridges the gap between offensive knowledge and defensive engineering, requiring students to design a controlled RAT and then build a detection system that identifies compromise through behavior rather than static signatures.

## 🎯 Objectives
- Understand RAT and C2 channel operations
- Design secure client–server communication
- Identify host-based indicators of compromise (IOCs)
- Build rule-based and behavioral detection logic
- Measure detection accuracy and analyze false positives/negatives
- Balance offensive research with defensive responsibility
- Document findings clearly and professionally

## ⚔ Offensive Tool Scope
The educational RAT models legitimate remote administration behavior with:
- Authenticated client–server communication
- Encrypted data exchange (TLS)
- Restricted command execution
- Configurable connection intervals
- Full logging of actions (Transparency emphasized; no stealth or weaponization)

## 🛡 Defensive Detection Scope
The detection system monitors and analyzes:
- Process creation and execution paths
- Network connections and long-lived outbound sessions
- Startup and persistence mechanisms
- Scheduled tasks and services
- Firewall rule changes
- Local administrator group modifications (Behavioral detection prioritized over signatures)

## 🧪 EDR Prototype (Terminal)
The repository now includes a Python-based EDR (Endpoint Detection and Response) prototype that runs in the terminal and performs real-time detections using telemetry logs.

**Script:** `edr_detection.py`

### ✅ Features
- Continuous real-time monitoring of telemetry logs (JSON Lines)
- Modular detection logic for RAT behaviors
- Scoring-based alerting (0–100 with alerts at ≥ 70)
- Clear terminal alert output with severity and key details

### ✅ Telemetry Inputs
The EDR script tails and processes these files:
- `process.jsonl` → `process_start` events
- `network.jsonl` → `network_connection` events
- `registry.jsonl` → `registry_event` events
- `persistence.jsonl` → `persistence_detected` events

### ✅ Detection Logic Included
- **RDP RAT Detection:** Port 3389 connection monitoring and suspicious RDP activity
- **Keylogger Detection:** Suspicious process names (e.g., keylog, hook, capture) with persistence correlation
- **File Transfer RAT Detection:** Large outbound transfers (> 5MB) and unknown processes
- **Persistence Abuse:** Startup entries in AppData, Temp, or unusual locations
- **Signature-Based Detection:** Known suspicious process names (mimikatz, nc.exe, netcat, powershell -enc)

### ✅ How to Run
```bash
python edr_detection.py
```

## 🧰 Languages Used
- **Python** (EDR prototype and defensive automation)

## 📂 Deliverables
- Offensive Tool: Python, C, C++, Go (TCP/TLS)
- Defensive Tool: PowerShell, C#, Windows Event Logs, WMI, CIM, ETW
- Lab & Analysis: VirtualBox/VMware, Windows 10/11, Kali Linux, Ubuntu, Sysmon, Wireshark, Autoruns, Process Explorer
- Documentation: Architecture, threat model, ATT&CK mapping, detection rules, ethics report
- Evaluation: Detection accuracy metrics, false positives/negatives, final report & presentation
