# TPOT-ANALYSIS

End-to-end ETL → AI Layer 1 → RAG enrichment pipeline for T-Pot honeypot datasets.

This pipeline:

1. Fetches raw logs from the T-Pot API  
2. Normalizes and sessionizes them  
3. Runs AI Layer 1 reasoning (structured JSON summaries)  
4. Enriches sessions with MITRE ATT&CK + Sigma rule recommendations  

Everything runs from the command line.

---

## 1. Environment Setup

### Create virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies
```bash
pip install -r requirements.txt
pip install -e .
```

### Required environment variables  
Create `.env` in repo root:

```
OPENAI_API_KEY=your_key_here

TPOT_API_URL=https://<tpot-ip>:64297/kibana/api/console/proxy
TPOT_API_USERNAME=admin
TPOT_API_PASSWORD=your_password

TPOT_RAW_DIR=/data/tpot_sessions/raw
TPOT_NORMALIZED_DIR=/data/tpot_sessions/normalized
TPOT_SESSIONIZED_DIR=/data/tpot_sessions/sessionized
TPOT_AI_LAYER1_DIR=/data/tpot_sessions/ai_layer1
```

---

## 2. Fetch Raw Logs From T-Pot

```bash
python etl/fetcher.py 2025-11-11
```

Produces:

```
/data/tpot_sessions/raw/tpot_raw_honeypots_2025-11-11.json
/data/tpot_sessions/raw/tpot_raw_suricata_2025-11-11.json
```

---

## 3. Normalize Logs

```bash
python etl/normalize.py
```

Output:

```
/data/tpot_sessions/normalized/<date>/cowrie.json
/data/tpot_sessions/normalized/<date>/wordpot.json
/data/tpot_sessions/normalized/<date>/dionaea.json
/data/tpot_sessions/normalized/<date>/suricata.json
```

---

## 4. Sessionize

```bash
python etl/sessionize.py data/tpot_sessions/normalized25-11-11
```

Creates:

```
/data/tpot_sessions/sessionized/2025-11-11/cowrie_sessions.json
/data/tpot_sessions/sessionized/2025-11-11/dionaea_sessions.json
/data/tpot_sessions/sessionized/2025-11-11/wordpot_sessions.json
/data/tpot_sessions/sessionized/2025-11-11/suricata_sessions.json
```

---

## 5. Run AI Layer 1

```bash
python ai/layer1/analyze_session.py 2025-11-11
```

Output:

```
/data/tpot_sessions/ai_layer1/2025-11-11/<Sensor>/*.json
```

---

## 6. Ingest MITRE Data

```bash
python ai/rag/mitre_ingest.py /path/to/cti/enterprise-attack/attack-pattern
```

---

## 7. Ingest Sigma Rules

```bash
python ai/rag/sigma_ingest.py /path/to/sigma/rules
```

---

## 8. RAG Enrichment

```python
from ai.rag.enrich import enrich_session_full
summary = {...}
res = enrich_session_full(summary, top_k=5)
```

---

## 9. Run Tests

```bash
python tests/rag_mitre_test.py
python tests/rag_sigma_test.py
python tests/test_rag_crosslink.py
```