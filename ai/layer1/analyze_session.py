# analyze_session.py

import json
import os
from pathlib import Path
from typing import Dict, Any, List

from dotenv import load_dotenv

from schema import make_layer1_result_template
from prompts import (
    build_session_digest,
    build_layer1_system_prompt,
    build_layer1_user_prompt,
)


from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage


load_dotenv()


def get_env_path(name: str, default: str) -> Path:
    value = os.getenv(name, default)
    return Path(value)


def load_sessions_for_day(base_dir: Path, date_str: str) -> List[Dict[str, Any]]:
    """
    Load and flatten all session files.
    """

    def flatten_sessions(obj):
        """Recursively flatten lists until only dict sessions remain."""
        flat = []
        if isinstance(obj, dict):
            # single session dict
            flat.append(obj)
        elif isinstance(obj, list):
            for item in obj:
                flat.extend(flatten_sessions(item))
        else:
            # unknown type – ignore
            pass
        return flat

    sessions: List[Dict[str, Any]] = []

    date_dir = base_dir / date_str
    if not date_dir.exists():
        raise FileNotFoundError(f"Session directory does not exist: {date_dir}")

    for filename in sorted(date_dir.iterdir()):
        if not filename.name.endswith("_sessions.json"):
            continue

        with filename.open("r", encoding="utf-8") as f:
            data = json.load(f)

        flattened = flatten_sessions(data)
        sessions.extend(flattened)

    return sessions



def make_model() -> ChatOpenAI:
    """
    Create the LangChain ChatOpenAI model for AI Layer 1.
    We use gpt-4o-mini for cost efficiency.
    """

    model = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0.1,
    )
    return model


def analyze_single_session(model: ChatOpenAI, session: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze one session with AI Layer 1 and return the parsed JSON dict.
    """

    session_digest = build_session_digest(session)
    system_prompt = build_layer1_system_prompt()
    user_prompt = build_layer1_user_prompt(session_digest)

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt),
    ]

    response = model.invoke(messages)
    content = response.content

    # Try to parse JSON
    try:
        result = json.loads(content)
    except json.JSONDecodeError:
        # If the model adds extra text, try a naive fix by extracting the first JSON block
        # This is a simple fallback; you can improve later if needed.
        start_idx = content.find("{")
        end_idx = content.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            json_str = content[start_idx : end_idx + 1]
            result = json.loads(json_str)
        else:
            raise ValueError(f"Model did not return valid JSON. Content was:\n{content}")

    # Optionally merge with template to ensure fields exist
    template = make_layer1_result_template(session)
    merged = template

    # update top-level keys, but keep template defaults if missing
    for key, value in result.items():
        if key in merged and isinstance(value, dict) and isinstance(merged[key], dict):
            merged[key].update(value)
        else:
            merged[key] = value

    return merged


def save_analysis(output_dir: Path, date_str: str, session: Dict[str, Any], analysis: Dict[str, Any]) -> None:
    """
    Save the analysis JSON per session.
    Path example:
      <output_dir>/<date>/<sensor>/<session_id>.json
    """

    session_id = session.get("session_id", "unknown_session")
    sensor = session.get("sensor", "unknown_sensor")

    target_dir = output_dir / date_str / sensor
    target_dir.mkdir(parents=True, exist_ok=True)

    target_file = target_dir / f"{session_id}.json"
    with target_file.open("w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2)


def run_layer1_for_date(date_str: str) -> None:
    """
    Main entry point: run AI Layer 1 over all sessions for one day.
    """

    session_dir = get_env_path("TPOT_SESSIONIZED_DIR", "/data/tpot_sessions/sessionized")
    output_dir = get_env_path("TPOT_AI_LAYER1_DIR", "/data/tpot_sessions/ai_layer1")

    sessions = load_sessions_for_day(session_dir, date_str)
    print(f"[INFO] Loaded {len(sessions)} sessions for {date_str} from {session_dir}")

    model = make_model()

    processed = 0
    for session in sessions:
        try:
            analysis = analyze_single_session(model, session)
            save_analysis(output_dir, date_str, session, analysis)
            processed += 1
        except Exception as e:
            session_id = session.get("session_id", "unknown")
            print(f"[WARN] Failed to analyze session {session_id}: {e}")

    print(f"[INFO] AI Layer 1 completed for {date_str}: {processed}/{len(sessions)} sessions processed.")


if __name__ == "__main__":
    # Example usage:
    #   python -m AI.layer1.analyze_session 2025-11-11
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m AI.layer1.analyze_session <YYYY-MM-DD>")
        sys.exit(1)

    date_arg = sys.argv[1]
    run_layer1_for_date(date_arg)
