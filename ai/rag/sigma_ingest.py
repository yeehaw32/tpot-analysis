#sigma ingest.py
import os
import yaml
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
from load_dotenv import load_dotenv

load_dotenv()


def load_sigma_rules(rule_dir):
    """
    Recursively load YAML Sigma rules from rule_dir.
    Only files with .yml or .yaml are processed.
    """
    rule_dir = Path(rule_dir)
    rules = []

    for root, _, files in os.walk(rule_dir):
        for filename in files:
            if not (filename.endswith(".yml") or filename.endswith(".yaml")):
                continue

            path = Path(root) / filename
            try:
                with path.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
            except Exception:
                continue

            if not isinstance(data, dict):
                continue

            if "title" not in data or "id" not in data:
                continue

            rules.append(data)

    return rules


def extract_mitre_tags(tags):
    """
    Extract MITRE technique IDs from Sigma 'tags' list.

    Examples:
        attack.t1059.004  -> T1059.004
        attack.t1105      -> T1105
    """
    if not isinstance(tags, list):
        return []

    out = []
    for t in tags:
        t = str(t).lower().strip()
        # attack.tXXXX(.YYY)?
        if t.startswith("attack.t"):
            tid = t.split("attack.")[1].upper()
            out.append(tid)

    return out


def build_text(rule):
    """
    Build the embedded document text for the Sigma rule.
    Includes title, description, flattened detection patterns, and references.
    """
    parts = []

    title = rule.get("title")
    if title:
        parts.append(f"Title: {title}")

    desc = rule.get("description")
    if desc:
        parts.append(f"Description:\n{desc}")

    # Flatten detection patterns
    detection = rule.get("detection", {})
    if isinstance(detection, dict):
        for key, val in detection.items():
            if isinstance(val, list):
                for item in val:
                    parts.append(f"Detection pattern: {item}")
            elif isinstance(val, str):
                parts.append(f"Detection: {val}")

    # Optional references
    refs = rule.get("references", [])
    if isinstance(refs, list) and refs:
        ref_block = ["References:"]
        for r in refs:
            ref_block.append(f"- {r}")
        parts.append("\n".join(ref_block))

    if not parts:
        return ""

    return "\n\n".join(parts).strip()


def build_metadata(rule):
    """
    Extract and normalize metadata for ChromaDB storage.
    Includes full YAML under 'yaml_raw'.
    """
    logsource = rule.get("logsource", {}) or {}
    tags = rule.get("tags", []) or []

    mitre_ids = extract_mitre_tags(tags)
    mitre_str = ", ".join(mitre_ids)

    metadata = {
        "sid": rule.get("id"),
        "title": rule.get("title", ""),
        "logsource_product": logsource.get("product", ""),
        "logsource_service": logsource.get("service", ""),
        "level": rule.get("level", ""),
        "mitre_techniques": mitre_str,
        "raw_tags": ", ".join(tags),

        # NEW: store full YAML rule
        "yaml_raw": yaml.dump(rule)
    }

    return metadata



def ingest_sigma(rule_dir, chroma_path="./data/chroma/sigma", batch_size=25):
    rule_dir = Path(rule_dir)
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
        name="sigma_rules",
        embedding_function=embed_fn,
    )

    rules = load_sigma_rules(rule_dir)
    print(f"Found {len(rules)} Sigma rules before filtering")

    entries = []
    for r in rules:
        sid = r.get("id")
        if not sid:
            continue

        text = build_text(r)
        if not text:
            continue

        meta = build_metadata(r)
        entries.append((sid, text, meta))

    if not entries:
        print("No valid Sigma rules found")
        return

    print(f"Prepared {len(entries)} rules. Starting batched ingestion...")

    for i in range(0, len(entries), batch_size):
        batch = entries[i : i + batch_size]

        ids = [b[0] for b in batch]
        docs = [b[1] for b in batch]
        metas = [b[2] for b in batch]

        print(
            f"Ingesting batch {i//batch_size + 1} / {((len(entries)-1)//batch_size) + 1} "
            f"({len(ids)} items)..."
        )

        collection.add(ids=ids, documents=docs, metadatas=metas)

    print("Sigma ingestion complete!")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ingest Sigma rules into ChromaDB")
    parser.add_argument(
        "rule_dir",
        help="Path to sigma/rules directory",
    )
    parser.add_argument(
        "--chroma-path",
        default="./data/chroma/sigma",
        help="Where to store ChromaDB sigma collection",
    )
    args = parser.parse_args()

    ingest_sigma(args.rule_dir, args.chroma_path)
