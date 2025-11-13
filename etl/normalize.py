import os
import json
from dotenv import load_dotenv

load_dotenv()

NORMALIZED_BASE = os.getenv("NORMALIZED_BASE")
ETL_DATA_DIR = os.getenv("ETL_DATA_DIR")

def load_json_file(path):
    with open(path, "r") as f:
        return json.load(f)


def find_latest_file(prefix):
    files = []
    for name in os.listdir(ETL_DATA_DIR):
        if name.startswith(prefix) and name.endswith(".json"):
            files.append(name)
    if not files:
        return None
    files.sort()
    return os.path.join(ETL_DATA_DIR, files[-1])


# -----------------------------
# Normalizers (FIXED VERSIONS)
# -----------------------------

def normalize_cowrie(src):
    timestamp = src.get("@timestamp") or src.get("timestamp")
    event = {
        "timestamp": timestamp,
        "sensor": "Cowrie",
        "session_id": src.get("session"),   # <<< CRITICAL FIX
        "src_ip": src.get("src_ip"),
        "src_port": src.get("src_port"),
        "dest_ip": src.get("dest_ip") or src.get("t-pot_ip_int") or src.get("t-pot_ip_ext"),
        "dest_port": src.get("dest_port"),
        "protocol": src.get("protocol"),
        "eventid": src.get("eventid"),
        "message": src.get("message"),
        "url": None,
        "connection": None,
        "event_type": None,
        "raw": src,
    }
    return event


def normalize_wordpot(src):
    timestamp = src.get("@timestamp") or src.get("timestamp")
    event = {
        "timestamp": timestamp,
        "sensor": "Wordpot",
        "session_id": None,   # Wordpot does not have sessions
        "src_ip": src.get("src_ip"),
        "src_port": src.get("src_port"),
        "dest_ip": src.get("t-pot_ip_int") or src.get("dest_ip"),
        "dest_port": src.get("dest_port"),
        "protocol": "http",
        "eventid": None,
        "message": None,
        "url": src.get("url"),
        "connection": None,
        "event_type": None,
        "raw": src,
    }
    return event


def normalize_dionaea(src):
    timestamp = src.get("@timestamp") or src.get("timestamp")
    conn = src.get("connection", {}) or {}
    event = {
        "timestamp": timestamp,
        "sensor": "Dionaea",
        "session_id": None,   # Dionaea has no session identifiers
        "src_ip": src.get("src_ip"),
        "src_port": src.get("src_port"),
        "dest_ip": src.get("dest_ip") or src.get("t-pot_ip_int"),
        "dest_port": src.get("dest_port"),
        "protocol": conn.get("protocol"),
        "eventid": None,
        "message": None,
        "url": None,
        "connection": conn,
        "event_type": None,
        "raw": src,
    }
    return event


def normalize_suricata(src):
    timestamp = src.get("@timestamp") or src.get("timestamp")
    event = {
        "timestamp": timestamp,
        "sensor": "Suricata",
        "session_id": None,   # Suricata sessionized by time window later
        "src_ip": src.get("src_ip"),
        "src_port": src.get("src_port"),
        "dest_ip": src.get("dest_ip") or src.get("t-pot_ip_int"),
        "dest_port": src.get("dest_port"),
        "protocol": src.get("proto"),
        "eventid": None,
        "message": None,
        "url": None,
        "connection": None,
        "event_type": src.get("event_type"),
        "raw": src,
    }
    return event


# -----------------------------
# Helpers
# -----------------------------

def get_date_from_timestamp(ts):
    if not ts:
        return "unknown"
    if "T" in ts:
        return ts.split("T")[0]
    return ts[:10]


def process_hits(hits, out_dict):
    for hit in hits:
        src = hit.get("_source", {})
        sensor_type = src.get("type")

        if not sensor_type:
            continue

        if sensor_type == "Cowrie":
            norm = normalize_cowrie(src)
            key = "cowrie"
        elif sensor_type == "Wordpot":
            norm = normalize_wordpot(src)
            key = "wordpot"
        elif sensor_type == "Dionaea":
            norm = normalize_dionaea(src)
            key = "dionaea"
        elif sensor_type == "Suricata":
            norm = normalize_suricata(src)
            key = "suricata"
        else:
            continue

        date_str = get_date_from_timestamp(norm["timestamp"])
        if date_str not in out_dict:
            out_dict[date_str] = {}
        if key not in out_dict[date_str]:
            out_dict[date_str][key] = []
        out_dict[date_str][key].append(norm)


def save_normalized(out_dict):
    for date_str in out_dict:
        day_dir = os.path.join(NORMALIZED_BASE, date_str)
        os.makedirs(day_dir, exist_ok=True)

        for sensor_key in out_dict[date_str]:
            out_path = os.path.join(day_dir, sensor_key + ".json")
            with open(out_path, "w") as f:
                json.dump(out_dict[date_str][sensor_key], f, indent=2)
            print("Saved", len(out_dict[date_str][sensor_key]), "events to", out_path)


# -----------------------------
# Main
# -----------------------------

def main():
    print("Using RAW_DIR:", ETL_DATA_DIR)
    print("Using NORMALIZED_BASE:", NORMALIZED_BASE)

    honeypots_path = find_latest_file("tpot_raw_honeypots_")
    suricata_path = find_latest_file("tpot_raw_suricata_")

    if not honeypots_path and not suricata_path:
        print("No raw files found in", ETL_DATA_DIR)
        return

    out_dict = {}

    if honeypots_path:
        print("Loading honeypots from:", honeypots_path)
        hits = load_json_file(honeypots_path)
        process_hits(hits, out_dict)

    if suricata_path:
        print("Loading suricata from:", suricata_path)
        hits = load_json_file(suricata_path)
        process_hits(hits, out_dict)

    if out_dict:
        save_normalized(out_dict)
    else:
        print("No events to normalize.")


if __name__ == "__main__":
    main()
