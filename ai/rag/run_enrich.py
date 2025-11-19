import os
import json
from dotenv import load_dotenv
from ai.rag.enrich import enrich_session_full

load_dotenv()

LAYER1_DIR = os.getenv("TPOT_AI_LAYER1_DIR", "/data/tpot_sessions/ai_layer1")
ENRICHED_DIR = os.getenv("TPOT_ENRICHED_DIR", "/data/tpot_sessions/enriched")


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def process_day(date_str):
    """
    Input (structured like AI Layer 1):
        /ai_layer1/<date>/<Sensor>/<session_id>.json

    Output:
        /enriched/<date>/<session_id>.json
    """

    day_in_dir = os.path.join(LAYER1_DIR, date_str)
    if not os.path.isdir(day_in_dir):
        print(f"[WARN] AI-Layer-1 directory not found: {day_in_dir}")
        return

    day_out_dir = os.path.join(ENRICHED_DIR, date_str)
    ensure_dir(day_out_dir)

    session_files = []

    # Walk sensor subfolders
    for sensor in os.listdir(day_in_dir):
        sensor_dir = os.path.join(day_in_dir, sensor)
        if not os.path.isdir(sensor_dir):
            continue

        for f in os.listdir(sensor_dir):
            if f.endswith(".json"):
                session_files.append(os.path.join(sensor_dir, f))

    print(f"[INFO] Found {len(session_files)} Layer-1 session files")

    for path in session_files:
        session = load_json(path)

        enriched = enrich_session_full(session)

        out_path = os.path.join(day_out_dir, f"{session['session_id']}.json")
        save_json(out_path, enriched)

        print(f"[OK] Enriched session saved: {out_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python ai/rag/run_enrich.py YYYY-MM-DD")
        exit(1)

    process_day(sys.argv[1])
