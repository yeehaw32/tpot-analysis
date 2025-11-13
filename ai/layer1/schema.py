# schema.py

from typing import Dict, Any


def make_layer1_result_template(session: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a base result dict for AI Layer 1 for a single session.

    AI Layer 1 is reasoning-only:
      - No external knowledge
      - No MITRE / Sigma / Suricata reference data
    """

    session_id = session.get("session_id", "")
    sensor = session.get("sensor", "")
    src_ip = session.get("src_ip", "")
    dest_ip = session.get("dest_ip", "")
    start_time = session.get("start_time", "")
    end_time = session.get("end_time", "")

    result = {
        "session_id": session_id,
        "sensor": sensor,
        "attack_intent": "",      # e.g. "ssh_bruteforce", "web_scanning", "malware_drop", "unknown"
        "summary": "",            # human-readable summary of what happened
        "key_indicators": {
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_ports": [],      # list of integers or strings
            "dest_ports": [],
            "protocols": [],
            "commands": [],       # for Cowrie etc.
            "urls": [],           # for Wordpot / HTTP
            "signatures": [],     # Suricata rule names or IDs present in the session events
            "files": []           # filenames, hashes, paths if visible in the session
        },
        "confidence": 0.0,        # float between 0 and 1
        "risk_score": 0,          # simple integer, e.g. 0–10
        "timestamp_range": {
            "start": start_time,
            "end": end_time
        }
    }

    return result
