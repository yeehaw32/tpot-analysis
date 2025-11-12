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
ETL_DATA_DIR = os.getenv("ETL_DATA_DIR", "/data/tpot_sessions/raw")

BASE_URL = f"{TPOT_HOST}{TPOT_PROXY_PATH}?path={TPOT_INDEX}/_search&method=POST"

query = {
    "size": 10000,
    "sort": [{"@timestamp": "desc"}],
    "query": {
        "bool": {
            "should": [
                {"term": {"type": "Cowrie"}},
                {"term": {"type": "Dionaea"}},
                {"term": {"type": "Wordpot"}},
                {"term": {"type": "Suricata"}},
                {"term": {"type.keyword": "Cowrie"}},
                {"term": {"type.keyword": "Dionaea"}},
                {"term": {"type.keyword": "Wordpot"}},
                {"term": {"type.keyword": "Suricata"}}
            ]
        }
    }
}

def main():
    print(f"[DEBUG] URL: {BASE_URL}")
    print(f"[DEBUG] Index: {TPOT_INDEX}")
    print(f"[DEBUG] Auth user: {TPOT_USER!r}")
    try:
        r = requests.post(
            BASE_URL,
            auth=(TPOT_USER, TPOT_PASS),
            headers={"kbn-xsrf":"true", "Content-Type":"application/json"},
            json=query,
            verify=False,
            timeout=60
        )
        print(f"[DEBUG] HTTP {r.status_code}")
        # If Kibana proxy returns non-200, show body.
        if r.status_code != 200:
            print("[DEBUG] Response text:")
            print(r.text)
            return

        data = r.json()
        total = data.get("hits", {}).get("total", {})
        total_value = total["value"] if isinstance(total, dict) and "value" in total else total
        hits = data.get("hits", {}).get("hits", [])

        print(f"[DEBUG] hits.total: {total_value}")
        print(f"[DEBUG] returned hits: {len(hits)}")

        if not hits:
            print("No data found.")
            return

        # Show first 3 types for sanity
        preview = [h.get("_source", {}).get("type") for h in hits[:3]]
        print(f"[DEBUG] first types: {preview}")

        os.makedirs(ETL_DATA_DIR, exist_ok=True)
        out = os.path.join(
            ETL_DATA_DIR,
            f"tpot_raw_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(out, "w") as f:
            json.dump(hits, f, indent=2)
        print(f"Saved {len(hits)} records to {out}")

    except Exception as e:
        print(f"[ERROR] Exception: {e}")

if __name__ == "__main__":
    main()
