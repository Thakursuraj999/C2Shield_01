import argparse
import json
import os
import random
import threading
import time
from datetime import datetime
from typing import Dict, Any, List, Tuple

SUSPICIOUS_PROCESS_PATTERNS = [
    "mimikatz",
    "nc.exe",
    "netcat",
    "powershell -enc",
    "powershell -e",
]

KEYLOGGER_KEYWORDS = ["keylog", "hook", "capture"]

ALERT_THRESHOLD = 70

def safe_parse_json(line: str) -> Dict[str, Any]:
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {}

def get_severity(score: int) -> str:
    if score >= 90:
        return "HIGH"
    if score >= 70:
        return "MEDIUM"
    return "LOW"

def print_alert(threat: str, score: int, event_type: str, details: Dict[str, Any]) -> None:
    severity = get_severity(score)
    print("\n=== ALERT ===")
    print(f"Threat     : {threat}")
    print(f"Severity   : {severity}")
    print(f"Score      : {score}")
    print(f"Event Type : {event_type}")
    for key, value in details.items():
        print(f"{key:<11}: {value}")
    print("============")

def detect_rdp_rat(event: Dict[str, Any]) -> List[Tuple[str, int, str, Dict[str, Any]]]:
    alerts = []
    if event.get("event_type") != "network_connection":
        return alerts

    dest_port = event.get("dest_port") or event.get("destination_port")
    if dest_port == 3389:
        score = 75
        details = {
            "process": event.get("process_name"),
            "dest_ip": event.get("dest_ip"),
            "dest_port": dest_port,
        }
        alerts.append(("RDP RAT Activity", score, event.get("event_type"), details))
    return alerts

def detect_keylogger(event: Dict[str, Any], persistence_cache: Dict[str, Dict[str, Any]]) -> List[Tuple[str, int, str, Dict[str, Any]]]:
    alerts = []
    if event.get("event_type") != "process_start":
        return alerts

    process_name = (event.get("process_name") or "").lower()
    if any(keyword in process_name for keyword in KEYLOGGER_KEYWORDS):
        score = 70
        if process_name in persistence_cache:
            score += 10
        details = {
            "process": event.get("process_name"),
            "pid": event.get("pid"),
            "user": event.get("user"),
        }
        alerts.append(("Keylogger Suspected", min(score, 100), event.get("event_type"), details))
    return alerts

def detect_file_transfer_rat(event: Dict[str, Any]) -> List[Tuple[str, int, str, Dict[str, Any]]]:
    alerts = []
    if event.get("event_type") != "network_connection":
        return alerts

    bytes_sent = event.get("bytes_sent") or 0
    process_name = event.get("process_name") or "unknown"
    if bytes_sent > 5 * 1024 * 1024:
        score = 80
        details = {
            "process": process_name,
            "bytes_sent": bytes_sent,
            "dest_ip": event.get("dest_ip"),
        }
        alerts.append(("Large Outbound Transfer", score, event.get("event_type"), details))
    return alerts

def detect_persistence_abuse(event: Dict[str, Any]) -> List[Tuple[str, int, str, Dict[str, Any]]]:
    alerts = []
    if event.get("event_type") != "persistence_detected":
        return alerts

    path = (event.get("path") or "").lower()
    suspicious_locations = ["appdata", "temp", "\\users\\public", "\\programdata\\"]
    if any(location in path for location in suspicious_locations):
        score = 75
        details = {
            "path": event.get("path"),
            "entry": event.get("entry"),
            "user": event.get("user"),
        }
        alerts.append(("Suspicious Persistence", score, event.get("event_type"), details))
    return alerts

def detect_signature(event: Dict[str, Any]) -> List[Tuple[str, int, str, Dict[str, Any]]]:
    alerts = []
    if event.get("event_type") != "process_start":
        return alerts

    process_name = (event.get("process_name") or "").lower()
    if any(pattern in process_name for pattern in SUSPICIOUS_PROCESS_PATTERNS):
        score = 85
        details = {
            "process": event.get("process_name"),
            "pid": event.get("pid"),
            "user": event.get("user"),
        }
        alerts.append(("Known Malware Signature", score, event.get("event_type"), details))
    return alerts

def update_persistence_cache(event: Dict[str, Any], persistence_cache: Dict[str, Dict[str, Any]]) -> None:
    if event.get("event_type") != "persistence_detected":
        return
    process_name = event.get("process_name")
    if process_name:
        persistence_cache[process_name.lower()] = event

def process_event(
    event: Dict[str, Any],
    persistence_cache: Dict[str, Dict[str, Any]],
) -> None:
    if not event:
        return

    update_persistence_cache(event, persistence_cache)

    detections = []
    detections.extend(detect_rdp_rat(event))
    detections.extend(detect_keylogger(event, persistence_cache))
    detections.extend(detect_file_transfer_rat(event))
    detections.extend(detect_persistence_abuse(event))
    detections.extend(detect_signature(event))

    for threat, score, event_type, details in detections:
        if score >= ALERT_THRESHOLD:
            print_alert(threat, score, event_type, details)

def follow_file(path: str):
    with open(path, "r", encoding="utf-8") as file_handle:
        file_handle.seek(0, os.SEEK_END)
        while True:
            line = file_handle.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line

def monitor_files(paths: List[str]) -> None:
    persistence_cache: Dict[str, Dict[str, Any]] = {}
    generators = [follow_file(path) for path in paths]

    while True:
        for generator in generators:
            try:
                line = next(generator)
            except StopIteration:
                continue
            event = safe_parse_json(line.strip())
            process_event(event, persistence_cache)

def ensure_logs_exist(paths: List[str]) -> None:
    for path in paths:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8"):
                pass

def now_ts() -> str:
    return datetime.utcnow().isoformat() + "Z"

def write_event(path: str, event: Dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as file_handle:
        file_handle.write(json.dumps(event) + "\n")

def generate_process_event(malicious: bool) -> Dict[str, Any]:
    benign_processes = ["chrome.exe", "explorer.exe", "svchost.exe", "notepad.exe"]
    malicious_processes = ["keylog.exe", "hooksvc.exe", "mimikatz.exe", "powershell -enc"]
    process_name = random.choice(malicious_processes if malicious else benign_processes)
    return {
        "event_type": "process_start",
        "timestamp": now_ts(),
        "process_name": process_name,
        "pid": random.randint(1000, 9000),
        "user": random.choice(["student", "admin", "labuser"]),
    }

def generate_network_event(malicious: bool) -> Dict[str, Any]:
    benign_ports = [80, 443, 53]
    dest_port = 3389 if malicious and random.random() < 0.5 else random.choice(benign_ports)
    bytes_sent = random.randint(1000, 50000)
    if malicious and random.random() < 0.5:
        bytes_sent = 6 * 1024 * 1024
    process_name = random.choice(["chrome.exe", "svchost.exe", "unknown.exe"])
    return {
        "event_type": "network_connection",
        "timestamp": now_ts(),
        "process_name": process_name,
        "dest_ip": f"192.168.1.{random.randint(2, 254)}",
        "dest_port": dest_port,
        "bytes_sent": bytes_sent,
    }

def generate_registry_event(malicious: bool) -> Dict[str, Any]:
    key = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    value = "Updater"
    if malicious:
        value = "PersistenceLoader"
    return {
        "event_type": "registry_event",
        "timestamp": now_ts(),
        "key": key,
        "value": value,
        "action": "set_value",
    }

def generate_persistence_event(malicious: bool) -> Dict[str, Any]:
    benign_paths = ["C:/Program Files/GoodApp/app.exe", "C:/Windows/System32/svchost.exe"]
    malicious_paths = ["C:/Users/student/AppData/Roaming/keylog.exe", "C:/Users/student/Temp/rat.exe"]
    path = random.choice(malicious_paths if malicious else benign_paths)
    process_name = os.path.basename(path)
    return {
        "event_type": "persistence_detected",
        "timestamp": now_ts(),
        "path": path,
        "entry": "RunKey",
        "user": random.choice(["student", "admin", "labuser"]),
        "process_name": process_name,
    }

def telemetry_generator(paths: Dict[str, str], interval: float, malicious_rate: float) -> None:
    while True:
        malicious = random.random() < malicious_rate
        write_event(paths["process"], generate_process_event(malicious))
        write_event(paths["network"], generate_network_event(malicious))
        write_event(paths["registry"], generate_registry_event(malicious))
        write_event(paths["persistence"], generate_persistence_event(malicious))
        time.sleep(interval)

def build_paths(log_dir: str) -> Dict[str, str]:
    return {
        "process": os.path.join(log_dir, "process.jsonl"),
        "network": os.path.join(log_dir, "network.jsonl"),
        "registry": os.path.join(log_dir, "registry.jsonl"),
        "persistence": os.path.join(log_dir, "persistence.jsonl"),
    }

def main() -> None:
    parser = argparse.ArgumentParser(description="EDR prototype with telemetry generator.")
    parser.add_argument("--mode", choices=["detect", "generate", "demo"], default="demo")
    parser.add_argument("--log-dir", default=".")
    parser.add_argument("--interval", type=float, default=0.6)
    parser.add_argument("--malicious-rate", type=float, default=0.25)
    args = parser.parse_args()

    paths = build_paths(args.log_dir)
    ensure_logs_exist(list(paths.values()))

    if args.mode in {"generate", "demo"}:
        generator_thread = threading.Thread(
            target=telemetry_generator,
            args=(paths, args.interval, args.malicious_rate),
            daemon=True,
        )
        generator_thread.start()
        print("Telemetry generator started.")

    if args.mode in {"detect", "demo"}:
        print("EDR detection started. Monitoring telemetry logs...")
        monitor_files(list(paths.values()))

if __name__ == "__main__":
    main()