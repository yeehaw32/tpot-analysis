# ai/rag/query_suricata.py

import os
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
from load_dotenv import load_dotenv

load_dotenv()

def get_suricata_collection(chroma_path="./data/chroma/suricata"):
    chroma_path = Path(chroma_path)

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")

    client = chromadb.PersistentClient(path=str(chroma_path))

    embed_fn = OpenAIEmbeddingFunction(
        api_key=api_key,
        model_name="text-embedding-3-small",
    )

    return client.get_or_create_collection(
        name="suricata_rules",
        embedding_function=embed_fn,
    )


def query_suricata_by_sid(sid, chroma_path="./data/chroma/suricata"):
    collection = get_suricata_collection(chroma_path)
    rule_id = f"suricata-{sid}"

    result = collection.get(
        ids=[rule_id]
    )

    if not result or not result.get("metadatas"):
        return None

    return result["metadatas"][0]


def query_suricata_semantic(text, top_k=5, chroma_path="./data/chroma/suricata"):
    collection = get_suricata_collection(chroma_path)

    result = collection.query(
        query_texts=[text],
        n_results=top_k
    )

    ids = result.get("ids", [[]])[0]
    metas = result.get("metadatas", [[]])[0]
    distances = result.get("distances", [[]])[0]

    out = []
    for i in range(len(ids)):
        out.append({
            "sid": metas[i].get("sid"),
            "msg": metas[i].get("msg"),
            "classtype": metas[i].get("classtype"),
            "severity": metas[i].get("severity"),
            "distance": distances[i],
            "metadata": metas[i].get("metadata"),
        })

    return out


if __name__ == "__main__":
    # Basic self-test
    example = query_suricata_semantic("Tor relay traffic")
    print(example)
