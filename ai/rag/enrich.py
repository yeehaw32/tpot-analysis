from ai.rag.mitre_query import enrich_session_with_mitre
from ai.rag.sigma_query import enrich_session_with_sigma
from ai.rag.suricata_query import enrich_session_with_suricata


def enrich_session_full(session_summary, top_k_mitre=5, top_k_sigma=5):
    """
    Performs full enrichment on a Layer 1 session summary:
      - MITRE ATT&CK
      - Sigma rules
      - Suricata rules (SID-based)
    """

    s = enrich_session_with_mitre(session_summary, top_k=top_k_mitre)
    s = enrich_session_with_sigma(s, top_k=top_k_sigma)
    s = enrich_session_with_suricata(s)

    return s
