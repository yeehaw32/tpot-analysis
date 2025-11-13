import os
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load .env
load_dotenv()

# ---------------------------------------------------------------------------
# Load directories from environment (NO hardcoding)
# ---------------------------------------------------------------------------
NORMALIZED_DIR = os.getenv("TPOT_NORMALIZED_DIR", "/data/tpot_sessions/normalized")
SESSIONIZED_DIR = os.getenv("TPOT_SESSIONIZED_DIR", "/data/tpot_sessions/sessionized")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_time(ts):
    """Parse ISO8601 timestamps into datetime."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Sessionizers for each honeypot sensor
# ---------------------------------------------------------------------------

def sessionize_wordpot(events):
    """Wordpot grouped into 5-minute activity windows."""
    if not events:
        return []

    events.sort(key=lambda x: x["timestamp"])
    sessions = []
    current = [events[0]]
    window = timedelta(minutes=5)

    for e in events[1:]:
        if parse_time(e["timestamp"]) - parse_time(current[-1]["timestamp"]) <= window:
            current.append(e)
        else:
            sessions.append(current)
            current = [e]

    sessions.append(current)
    return sessions


def sessionize_cowrie(events):
    """Cowrie grouped strictly by session_id."""
    buckets = {}
    for e in events:
        sid = e.get("session_id", "unknown")
        buckets.setdefault(sid, []).append(e)
    return list(buckets.values())


def sessionize_dionaea(events):
    """Dionaea grouped by 20 minutes of continuous activity."""
    if not events:
        return []

    events.sort(key=lambda x: x["timestamp"])
    sessions = []
    current = [events[0]]
    window = timedelta(minutes=20)

    for e in events[1:]:
        if parse_time(e["timestamp"]) - parse_time(current[-1]["timestamp"]) <= window:
            current.append(e)
        else:
            sessions.append(current)
            current = [e]

    sessions.append(current)
    return sessions


def sessionize_suricata(events):
    """Suricata grouped into 30-second network bursts."""
    if not events:
        return []

    events.sort(key=lambda x: x["timestamp"])
    sessions = []
    current = [events[0]]
    window = timedelta(seconds=30)

    for e in events[1:]:
        if parse_time(e["timestamp"]) - parse_time(current[-1]["timestamp"]) <= window:
            current.append(e)
        else:
            sessions.append(current)
            current = [e]

    sessions.append(current)
    return sessions


# ---------------------------------------------------------------------------
# Wrap raw event lists into proper session objects
# ---------------------------------------------------------------------------

def wrap_session(sensor, events_list):
    """
    Convert a list of event dicts into a proper session object
    suitable for AI Layer 1.
    """
    if not events_list:
        return None

    # Sort chronologically
    events_list.sort(key=lambda x: x["timestamp"])

    # Extract session_id if present
    session_id = None
    for ev in events_list:
        if ev.get("session_id"):
            session_id = ev["session_id"]
            break

    if session_id is None:
        # fallback: unique deterministic ID
        session_id = f"{sensor}_{events_list[0]['timestamp']}"

    src_ip = events_list[0].get("src_ip")
    dest_ip = events_list[0].get("dest_ip")
    start_time = events_list[0]["timestamp"]
    end_time = events_list[-1]["timestamp"]

    return {
        "session_id": session_id,
        "sensor": sensor.capitalize(),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "start_time": start_time,
        "end_time": end_time,
        "events": events_list,
    }


# ---------------------------------------------------------------------------
# Main processing pipeline
# ---------------------------------------------------------------------------

def process_day(date_str):
    """
    Example call:
        python3 sessionize.py 2025-11-11

    Expects:
        TPOT_NORMALIZED_DIR/YYYY-MM-DD/*.json
    Produces:
        TPOT_SESSIONIZED_DIR/YYYY-MM-DD/*_sessions.json
    """

    day_norm_dir = os.path.join(NORMALIZED_DIR, date_str)
    if not os.path.isdir(day_norm_dir):
        print(f"[WARN] Normalized directory not found: {day_norm_dir}")
        return

    out_dir = os.path.join(SESSIONIZED_DIR, date_str)
    ensure_dir(out_dir)

    sensors = {
        "wordpot": sessionize_wordpot,
        "cowrie": sessionize_cowrie,
        "dionaea": sessionize_dionaea,
        "suricata": sessionize_suricata,
    }

    for sensor, handler in sensors.items():
        input_file = os.path.join(day_norm_dir, f"{sensor}.json")

        if not os.path.isfile(input_file):
            print(f"[INFO] No {sensor}.json found for {date_str}")
            continue

        print(f"[INFO] Loading {sensor} events...")
        events = load_json(input_file)

        print(f"[INFO] Sessionizing {sensor} ({len(events)} events)...")
        raw_sessions = handler(events)

        # Wrap raw lists of events into proper session objects
        wrapped_sessions = []
        for sess in raw_sessions:
            obj = wrap_session(sensor, sess)
            if obj:
                wrapped_sessions.append(obj)

        out_file = os.path.join(out_dir, f"{sensor}_sessions.json")
        save_json(out_file, wrapped_sessions)

        print(f"[INFO] Saved {len(wrapped_sessions)} {sensor} sessions -> {out_file}")


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 sessionize.py YYYY-MM-DD")
        exit(1)

    process_day(sys.argv[1])
