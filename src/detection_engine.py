import json
import os
import time
from typing import Any, Dict, Optional, List
from .mitigation import trigger_containment
from .notifier import send_telegram_alert

LOG_FILE_PATH = "logs/eve.json"
THRESHOLD_LIMIT = 5
ip_tracker: Dict[str, int] = {}

def parse_eve_log(line: str) -> List[Dict[str, Any]]:
    """Parses a log line, handling single JSON objects or concatenated JSON streams safely."""
    line = line.strip()
    if not line:
        return []
    
    parsed_events = []
    
    # Handle cases where multiple JSON objects are glued together without proper newlines
    # We replace '}{' with '}--SPLIT--{' to split them cleanly
    normalized_line = line.replace("}{", "}--SPLIT--{")
    chunks = normalized_line.split("--SPLIT--")
    
    for chunk in chunks:
        try:
            data = json.loads(chunk.strip())
            if data.get("event_type") == "alert":
                src_ip = data.get("src_ip", "0.0.0.0")
                alert_msg = data.get("alert", {}).get("signature", "Unknown Threat")
                
                # Map to MITRE ATT&CK Framework
                mitre_id = "T1595" if "RECON" in alert_msg.upper() else "T1498"
                
                parsed_events.append({
                    "src_ip": src_ip,
                    "dest_ip": data.get("dest_ip"),
                    "alert": alert_msg,
                    "mitre_ttp": mitre_id,
                    "timestamp": data.get("timestamp")
                })
        except json.JSONDecodeError:
            pass
            
    return parsed_events

def monitor_logs():
    """Real-time log tailing and threshold evaluation."""
    print("[*] SOAR Engine Started. Listening for threats...")
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    
    if not os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, 'w') as f:
            f.write("")

    with open(LOG_FILE_PATH, 'r') as file:
        file.seek(0, 2)  # Start tailing from the end of the file
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.5)
                continue

            events = parse_eve_log(line)
            for parsed in events:
                src_ip = parsed["src_ip"]
                ip_tracker[src_ip] = ip_tracker.get(src_ip, 0) + 1

                print(f"[Alert] {parsed['timestamp']} | IP: {parsed['src_ip']} | Alert: {parsed['alert']} | Mitre: {parsed['mitre_ttp']}")

                if ip_tracker[src_ip] >= THRESHOLD_LIMIT:
                    print(f"[Critical] Threshold exceeded for IP: {src_ip}. Initiating automated response.")
                    success = trigger_containment(src_ip)
                    action_status = "IP Blocked" if success else "Blocking Failed"

                    # Send Telegram Alert
                    send_telegram_alert(src_ip, parsed['alert'], parsed['mitre_ttp'], action_status)
                    ip_tracker[src_ip] = 0

if __name__ == "__main__":
    monitor_logs()