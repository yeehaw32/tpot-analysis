# ai/rag/ingest_suricata.py

import os
import re
import json
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
from load_dotenv import load_dotenv

load_dotenv()

# Regex for parsing the ET-style Suricata rules inside the merged suricata.rules file
RULE_PATTERN = re.compile(
    r'alert\s+(\w+)\s+(.+?)\s+(\w+)\s+->\s+(.+?)\s+\((.+)\)'
)


def parse_metadata_block(block):
    """
    Parse ET-style metadata into a dict:
    metadata: key value, key value, ...
    """
    meta = {}
    block = block.strip().rstrip(';')
    items = [item.strip() for item in block.split(',')]
    for item in items:
        if " " in item:
            key, val = item.split(" ", 1)
            meta[key.strip()] = val.strip()
    return meta


def parse_rule(line):
    """
    Parse one Suricata rule line into a structured dict.
    Only handles single-line rules (suricata-update default output).
    """
    line = line.strip()
    if not line.startswith("alert "):
        return None

    m = RULE_PATTERN.match(line)
    if not m:
        return None

    protocol = m.group(1)
    src_addrs = m.group(2)
    src_ports = m.group(3)
    dest_addrs = m.group(4)

    body = m.group(5)
    body_parts = [p.strip() for p in body.split(";") if p.strip()]

    msg = None
    classtype = None
    rev = None
    sid = None
    references = []
    flowbits = []
    metadata_dict = {}
    dest_ports = None

    for p in body_parts:
        if p.startswith("msg:"):
            msg = p[len("msg:"):].strip().strip('"')

        elif p.startswith("classtype:"):
            classtype = p[len("classtype:"):].strip()

        elif p.startswith("sid:"):
            sid = int(p[len("sid:"):].strip())

        elif p.startswith("rev:"):
            rev = int(p[len("rev:"):].strip())

        elif p.startswith("reference:"):
            ref = p[len("reference:"):].strip()
            references.append(ref)

        elif p.startswith("flowbits:"):
            fb = p[len("flowbits:"):].strip()
            flowbits.append(fb)

        elif p.startswith("metadata:"):
            meta_block = p[len("metadata:"):].strip()
            metadata_dict.update(parse_metadata_block(meta_block))

        elif " -> " in p and dest_ports is None:
            parts = p.split()
            if len(parts) > 1:
                dest_ports = parts[-1]

    severity = metadata_dict.get("signature_severity", "Unknown")

    return {
        "sid": sid,
        "msg": msg,
        "classtype": classtype,
        "severity": severity,
        "protocol": protocol,
        "src_addrs": src_addrs,
        "src_ports": src_ports,
        "dest_addrs": dest_addrs,
        "dest_ports": dest_ports,
        "references": references,
        "flowbits": flowbits,
        "rev": rev,
        "metadata": metadata_dict,
        "raw_rule": line,
    }


def normalize_metadata(rule):
    out = {}
    for k, v in rule.items():
        if k == "raw_rule":
            continue  # raw text goes into embedding doc

        # Convert None → "" so Chroma accepts it
        if v is None:
            out[k] = ""
            continue

        # List → comma-separated string
        if isinstance(v, list):
            out[k] = ", ".join(v)
            continue

        # Dict → JSON string
        if isinstance(v, dict):
            out[k] = json.dumps(v)
            continue

        # Everything else must be primitive (str/int/bool/float)
        out[k] = v

    return out



def ingest_suricata_rules(
    rule_file,
    chroma_path="./data/chroma/suricata",
    batch_size=50
):
    rule_file = Path(rule_file)
    chroma_path = Path(chroma_path)
    chroma_path.mkdir(parents=True, exist_ok=True)

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set")

    client = chromadb.PersistentClient(path=str(chroma_path))

    embed_fn = OpenAIEmbeddingFunction(
        api_key=api_key,
        model_name="text-embedding-3-small",
    )

    collection = client.get_or_create_collection(
        name="suricata_rules",
        embedding_function=embed_fn,
    )

    rules = []
    with rule_file.open("r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_rule(line)
            if parsed and parsed.get("sid") and parsed.get("msg"):
                rules.append(parsed)

    print(f"Parsed {len(rules)} Suricata rules")

    # Batch ingestion
    for i in range(0, len(rules), batch_size):
        batch = rules[i:i + batch_size]

        ids = [f"suricata-{r['sid']}" for r in batch]
        docs = [f"{r['msg']} {r['raw_rule']}" for r in batch]
        metas = [normalize_metadata(r) for r in batch]

        print(f"Ingesting batch {i//batch_size + 1} ({len(ids)} rules)")

        collection.add(
            ids=ids,
            documents=docs,
            metadatas=metas,
        )

    print("Ingestion complete!")


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Ingest Suricata rules into ChromaDB")
    p.add_argument("rule_file", help="Path to suricata.rules")
    p.add_argument("--chroma-path", default="./data/chroma/suricata")
    args = p.parse_args()

    ingest_suricata_rules(
        args.rule_file,
        chroma_path=args.chroma_path
    )
