from ai.rag.mitre_query import enrich_session_with_mitre
from ai.rag.sigma_query import enrich_session_with_sigma

def enrich_session_full(session_summary, top_k_mitre=5, top_k_sigma=5):
    """
    Run both MITRE and Sigma enrichment on a Layer 1 summary.
    They are independent lookups and do not depend on each other.
    """

    session = enrich_session_with_mitre(
        session_summary,
        top_k=top_k_mitre
    )

    session = enrich_session_with_sigma(
        session,
        top_k=top_k_sigma
    )

    return session
