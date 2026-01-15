import os, json, requests, urllib3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TPOT_USER = os.getenv("TPOT_USER", "admin")
TPOT_PASS = os.getenv("TPOT_PASS")
TPOT_HOST = os.getenv("TPOT_HOST", "https://10.20.20.10:64297")
TPOT_INDEX = os.getenv("TPOT_INDEX", "logstash-2025.11.11")
TPOT_PROXY_PATH = os.getenv("TPOT_PROXY_PATH", "/kibana/api/console/proxy")
RAW_DIR = "/data/tpot_sessions/raw"
BASE_URL = f"{TPOT_HOST}{TPOT_PROXY_PATH}?path={TPOT_INDEX}/_search&method=POST"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}


os.makedirs(RAW_DIR, exist_ok=True)


def run_query(sensor_list):
    query = {
        "query": {"terms": {"type.keyword": sensor_list}},
        "sort": [{"@timestamp": "desc"}],
        "size": 10000,
    }

    response = requests.post(
        BASE_URL,
        auth=(TPOT_USER, TPOT_PASS),
        json=query,
        headers=HEADERS,
        verify=False,
        timeout=60
    )

    return response.json().get("hits", {}).get("hits", [])


def save_results(label, hits):
    if not hits:
        return

    out_path = os.path.join(
        RAW_DIR,
        f"tpot_raw_{label}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
    )

    with open(out_path, "w") as f:
        json.dump(hits, f, indent=2)

    print(f"[{label}] Saved {len(hits)} records → {out_path}")


def fetch(label, type_list):
    print(f"[INFO] Fetching {label}...")
    hits = run_query(type_list)
    save_results(label, hits)


def main():
    fetch("honeypots", ["Cowrie", "Dionaea", "Wordpot"])


if __name__ == "__main__":
    main()
