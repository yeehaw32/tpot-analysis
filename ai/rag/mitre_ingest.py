# ai/rag/ingest.py

import json
import os
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction

from load_dotenv import load_dotenv

load_dotenv()

def load_attack_patterns_from_dir(json_dir):
    """
    Walk a directory (enterprise-attack/attack-pattern) and collect
    all non-revoked, non-deprecated attack-pattern objects.
    """
    json_dir = Path(json_dir)
    patterns = []

    for root, _, files in os.walk(json_dir):
        for filename in files:
            if not filename.endswith(".json"):
                continue

            path = Path(root) / filename
            with path.open("r", encoding="utf-8") as f:
                try:
                    bundle = json.load(f)
                except json.JSONDecodeError:
                    continue

            for obj in bundle.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                if obj.get("revoked", False):
                    continue
                if obj.get("x_mitre_deprecated", False):
                    continue

                patterns.append(obj)

    return patterns


def build_text(attack_pattern):
    """
    Build the text that will be embedded for this attack pattern.
    Uses name, description, detection, and external references.
    """
    parts = []

    name = attack_pattern.get("name")
    if name:
        parts.append(name)

    description = attack_pattern.get("description")
    if description:
        parts.append(description)

    detection = attack_pattern.get("x_mitre_detection")
    if detection:
        parts.append("Detection:\n" + detection)

    # External references (except the primary mitre-attack reference)
    external_refs = attack_pattern.get("external_references", [])
    ref_lines = []
    for ref in external_refs:
        if ref.get("source_name") == "mitre-attack":
            continue

        line = ref.get("source_name", "")
        desc = ref.get("description")
        url = ref.get("url")

        if desc:
            if line:
                line = line + " - " + desc
            else:
                line = desc

        if url:
            if line:
                line = line + " (" + url + ")"
            else:
                line = url

        if line:
            ref_lines.append(line)

    if ref_lines:
        refs_block = "External References:\n- " + "\n- ".join(ref_lines)
        parts.append(refs_block)

    if not parts:
        return ""

    return "\n\n".join(parts).strip()


def build_metadata(attack_pattern):
    """
    Extracts MITRE metadata for later filtering / display.
    Converts all list values to strings to comply with ChromaDB constraints.
    """
    tid = None
    mitre_url = None
    external_refs = attack_pattern.get("external_references", [])
    for ref in external_refs:
        if ref.get("source_name") == "mitre-attack":
            tid = ref.get("external_id")
            mitre_url = ref.get("url")
            break

    tactics = []
    for phase in attack_pattern.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            phase_name = phase.get("phase_name")
            if phase_name and phase_name not in tactics:
                tactics.append(phase_name)

    platforms = attack_pattern.get("x_mitre_platforms", [])
    domains = attack_pattern.get("x_mitre_domains", [])

    # Convert lists to comma-separated strings (or empty string if empty)
    metadata = {
        "tid": tid,
        "name": attack_pattern.get("name"),
        "tactics": ", ".join(tactics) if tactics else "",
        "platforms": ", ".join(platforms) if platforms else "",
        "domain": ", ".join(domains) if domains else "",
        "is_subtechnique": bool(attack_pattern.get("x_mitre_is_subtechnique", False)),
        "revoked": bool(attack_pattern.get("revoked", False)),
        "deprecated": bool(attack_pattern.get("x_mitre_deprecated", False)),
        "mitre_url": mitre_url,
        "stix_id": attack_pattern.get("id"),
    }

    return metadata


def ingest_mitre(json_dir, chroma_path="./data/chroma/mitre", batch_size=25):
    json_dir = Path(json_dir)
    chroma_path = Path(chroma_path)
    chroma_path.mkdir(parents=True, exist_ok=True)

    api_key = os.environ.get("OPENAI_API_KEY")
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

    patterns = load_attack_patterns_from_dir(str(json_dir))
    print("Found", len(patterns), "attack patterns before filtering for TID/text")

    # Filter + prepare all entries first
    entries = []
    for p in patterns:
        meta = build_metadata(p)
        tid = meta.get("tid")
        if not tid:
            continue

        text = build_text(p)
        if not text:
            continue

        entries.append((tid, text, meta))

    if not entries:
        print("No valid attack patterns found")
        return

    print("Prepared", len(entries), "patterns. Starting batched ingestion...")

    # Batched add → critical fix
    for i in range(0, len(entries), batch_size):
        batch = entries[i : i + batch_size]

        ids = [item[0] for item in batch]
        docs = [item[1] for item in batch]
        metas = [item[2] for item in batch]

        print(f"Ingesting batch {i//batch_size + 1} / {((len(entries)-1)//batch_size)+1} "
              f"({len(ids)} items)...")

        collection.add(
            ids=ids,
            documents=docs,
            metadatas=metas
        )

    print("Ingestion complete!")



if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ingest MITRE ATT&CK attack patterns into ChromaDB.")
    parser.add_argument(
        "json_dir",
        help="Path to the 'enterprise-attack/attack-pattern' directory containing .json bundles.",
    )
    parser.add_argument(
        "--chroma-path",
        default="./data/chroma/mitre",
        help="Path where ChromaDB persistent data will be stored.",
    )
    args = parser.parse_args()

    ingest_mitre(args.json_dir, args.chroma_path)
