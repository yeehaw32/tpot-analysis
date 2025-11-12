import os, json, requests, urllib3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- ENVIRONMENT CONFIG ---
TPOT_USER = os.getenv("TPOT_USER", "admin")
TPOT_PASS = os.getenv("TPOT_PASS")
TPOT_HOST = os.getenv("TPOT_HOST", "https://10.20.20.10:64297")
TPOT_INDEX = os.getenv("TPOT_INDEX", "logstash-2025.11.11")
TPOT_PROXY_PATH = os.getenv("TPOT_PROXY_PATH", "/kibana/api/console/proxy")
ETL_DATA_DIR = "/data/tpot_sessions/raw"  # keep your original folder
os.makedirs(ETL_DATA_DIR, exist_ok=True)

# --- FIXED BASE URL ---
BASE_URL = f"{TPOT_HOST}{TPOT_PROXY_PATH}?path={TPOT_INDEX}/_search&method=POST"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}

def fetch(label, type_list):
    print(f"[INFO] Fetching {label} from {TPOT_INDEX}...")
    query = {
        "size": 10000,
        "sort": [{"@timestamp": "desc"}],
        "query": {"terms": {"type.keyword": type_list}},
    }

    try:
        r = requests.post(BASE_URL, auth=(TPOT_USER, TPOT_PASS), headers=HEADERS,
                          json=query, verify=False, timeout=60)
        if r.status_code != 200:
            print(f"[{label}] HTTP {r.status_code}: {r.text}")
            return

        data = r.json()
        hits = data.get("hits", {}).get("hits", [])
        print(f"[{label}] Retrieved {len(hits)} records")

        if not hits:
            return

        out_path = os.path.join(
            ETL_DATA_DIR,
            f"tpot_raw_{label}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
        )
        with open(out_path, "w") as f:
            json.dump(hits, f, indent=2)
        print(f"[{label}] Saved {len(hits)} -> {out_path}")

    except Exception as e:
        print(f"[{label}] Error: {e}")

def main():
    print(f"[INFO] Index: {TPOT_INDEX}")
    print(f"[INFO] URL: {BASE_URL}")

    # separate searches to avoid Suricata dominance
    fetch("honeypots", ["Cowrie", "Dionaea", "Wordpot"])
    fetch("suricata", ["Suricata"])

if __name__ == "__main__":
    main()
