import os, json, requests, urllib3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TPOT_USER = os.getenv("TPOT_USER")
TPOT_PASS = os.getenv("TPOT_PASS")
TPOT_HOST = os.getenv("TPOT_HOST")
TPOT_PROXY_PATH = os.getenv("TPOT_PROXY_PATH", "/kibana/api/console/proxy")
TPOT_INDEX = os.getenv("TPOT_INDEX", "logstash-*")
ETL_DATA_DIR = os.getenv("ETL_DATA_DIR", "./etl_data/raw")
PAGE_SIZE = int(os.getenv("TPOT_PAGE_SIZE", "500"))

TYPES_HONEYPOTS = os.getenv("TPOT_TYPES_HONEYPOTS", "Cowrie,Dionaea,Wordpot").split(",")
TYPES_SURICATA  = os.getenv("TPOT_TYPES_SURICATA", "Suricata").split(",")

BASE_URL = f"{TPOT_HOST}{TPOT_PROXY_PATH}?path={TPOT_INDEX}/_search&method=POST"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}

def fetch_types(type_list, label):
    os.makedirs(ETL_DATA_DIR, exist_ok=True)
    all_hits = []
    search_after = None

    while True:
        query = {
            "size": PAGE_SIZE,
            "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
            "query": {"terms": {"type.keyword": type_list}}
        }
        if search_after:
            query["search_after"] = search_after

        r = requests.post(
            BASE_URL, auth=(TPOT_USER, TPOT_PASS),
            headers=HEADERS, json=query, verify=False, timeout=60
        )
        if r.status_code != 200:
            print(f"[{label}] HTTP {r.status_code}: {r.text}")
            break

        data = r.json()
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            break

        all_hits.extend(hits)
        search_after = hits[-1].get("sort")
        if len(hits) < PAGE_SIZE:
            break

    if not all_hits:
        print(f"[{label}] 0 records")
        return

    out = os.path.join(
        ETL_DATA_DIR,
        f"tpot_raw_{label}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    )
    with open(out, "w") as f:
        json.dump(all_hits, f, indent=2)
    print(f"[{label}] Saved {len(all_hits)} records -> {out}")

def main():
    print(f"[INFO] Index: {TPOT_INDEX}")
    print(f"[INFO] URL: {BASE_URL}")

    # 1) Honeypots (Cowrie, Dionaea, Wordpot)
    fetch_types(TYPES_HONEYPOTS, "honeypots")

    # 2) Suricata
    fetch_types(TYPES_SURICATA, "suricata")

if __name__ == "__main__":
    main()
