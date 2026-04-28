import json
import os
import time
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

def main() -> None:
    files = [
        "process.jsonl",
        "network.jsonl",
        "registry.jsonl",
        "persistence.jsonl",
    ]

    missing = [path for path in files if not os.path.exists(path)]
    if missing:
        print(f"Missing telemetry files: {', '.join(missing)}")
        print("Ensure the telemetry files exist in the current directory.")
        return

    print("EDR detection started. Monitoring telemetry logs...")
    monitor_files(files)

if __name__ == "__main__":
    main()