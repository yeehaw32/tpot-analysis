import os
import json
import requests
from datetime import datetime
from dateutil import tz
from dotenv import load_dotenv

# --- Load .env file ---
load_dotenv()

# --- Load environment variables ---
TPOT_USER = os.getenv("TPOT_USER")
TPOT_PASS = os.getenv("TPOT_PASS")
TPOT_HOST = os.getenv("TPOT_HOST")
TPOT_PROXY_PATH = os.getenv("TPOT_PROXY_PATH", "/kibana/api/console/proxy")
TPOT_INDEX = os.getenv("TPOT_INDEX", "logstash-*")   # adjustable
ETL_DATA_DIR = os.getenv("ETL_DATA_DIR", "/data/tpot_sessions/raw")
ETL_LOG_FILE = os.getenv("ETL_LOG_FILE", "/var/log/etl_fetch.log")
TPOT_TYPES = os.getenv("TPOT_TYPES", "Cowrie,Dionaea,Wordpot,Suricata").split(",")
PAGE_SIZE = int(os.getenv("TPOT_PAGE_SIZE", 500))

BASE_URL = f"{TPOT_HOST}{TPOT_PROXY_PATH}?path={TPOT_INDEX}/_search&method=POST"

# --- Setup output ---
os.makedirs(ETL_DATA_DIR, exist_ok=True)

def log(msg):
    timestamp = datetime.now(tz=tz.tzlocal()).strftime("%Y-%m-%d %H:%M:%S")
    with open(ETL_LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")

def fetch_batch(search_after=None):
    query = {
        "size": PAGE_SIZE,
        "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
        "query": {
            "bool": {
                "must": [
                    {"terms": {"type.keyword": TPOT_TYPES}}
                ]
            }
        }
    }

    if search_after:
        query["search_after"] = search_after

    headers = {
        "kbn-xsrf": "true",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.post(
            BASE_URL,
            auth=(TPOT_USER, TPOT_PASS),
            headers=headers,
            json=query,
            verify=False,
            timeout=30
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log(f"Fetch error: {e}")
        return None

def main():
    all_hits = []
    search_after = None
    batch_count = 0

    while True:
        data = fetch_batch(search_after)
        if not data or "hits" not in data or not data["hits"]["hits"]:
            break

        hits = data["hits"]["hits"]
        all_hits.extend(hits)
        search_after = hits[-1]["sort"]
        batch_count += 1
        log(f"Fetched batch {batch_count} ({len(hits)} docs)")

        if len(hits) < PAGE_SIZE:
            break

    if not all_hits:
        log("No data fetched.")
        return

    filename = os.path.join(
        ETL_DATA_DIR,
        f"tpot_raw_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    )

    with open(filename, "w") as f:
        json.dump(all_hits, f, indent=2)

    log(f"Saved {len(all_hits)} documents to {filename}")

if __name__ == "__main__":
    print(TPOT_HOST)
    print(TPOT_USER)
    # main()
