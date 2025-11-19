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

    def flatten_sessions(obj):
        flat = []
        if isinstance(obj, dict):
            flat.append(obj)
        elif isinstance(obj, list):
            for item in obj:
                flat.extend(flatten_sessions(item))
        return flat

    sessions = []
    date_dir = base_dir / date_str

    if not date_dir.exists():
        raise FileNotFoundError(f"Session directory does not exist: {date_dir}")

    for filename in sorted(date_dir.iterdir()):
        if not filename.name.endswith("_sessions.json"):
            continue

        with filename.open("r", encoding="utf-8") as f:
            data = json.load(f)

        flattened = flatten_sessions(data)

        for obj in flattened:
            if isinstance(obj, dict) and "session_id" in obj and "events" in obj:
                sessions.append(obj)

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


def extract_key_indicators_from_session(session: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministically extract key_indicators from the session events.
    This uses only data already present in the session object
    (normalized + sessionized), no external knowledge.
    """

    src_ip = session.get("src_ip", "")
    dest_ip = session.get("dest_ip", "")
    sensor = session.get("sensor", "")

    src_ports: List[Any] = []
    dest_ports: List[Any] = []
    protocols: List[str] = []
    commands: List[str] = []
    urls: List[str] = []
    signatures: List[str] = []
    files: List[str] = []

    events = session.get("events", [])

    for event in events:
        # Ports
        sp = event.get("src_port")
        if sp is not None and sp not in src_ports:
            src_ports.append(sp)

        dp = event.get("dest_port")
        if dp is not None and dp not in dest_ports:
            dest_ports.append(dp)

        # Protocols
        proto = event.get("protocol")
        if proto and proto not in protocols:
            protocols.append(proto)

        # URLs from explicit field (Wordpot, Dionaea, etc.)
        u = event.get("url")
        if u and u not in urls:
            urls.append(u)

        # ------------------------------------------------------------------
        # COWRIE — CORRECT COMMAND EXTRACTION
        # ------------------------------------------------------------------
        if sensor == "Cowrie":
            if event.get("eventid") == "cowrie.command.input":
                raw_obj = event.get("raw", {})
                real_cmd = raw_obj.get("input")

                # Real attacker command
                if real_cmd and real_cmd not in commands:
                    commands.append(real_cmd)

                # Extract URLs from command text
                if real_cmd:
                    for part in real_cmd.split():
                        if part.startswith("http://") or part.startswith("https://"):
                            if part not in urls:
                                urls.append(part)

                # Extract files from "-O <file>" pattern
                if real_cmd and "-O " in real_cmd:
                    after = real_cmd.split("-O ", 1)[1].strip()
                    if after:
                        file_path = after.split()[0]
                        if file_path not in files:
                            files.append(file_path)

        # ------------------------------------------------------------------
        # SURICATA — SIGNATURES
        # ------------------------------------------------------------------
        if sensor == "Suricata":
            sig_list = event.get("signatures", [])
            if sig_list:
                for s in sig_list:
                    if s and s not in signatures:
                        signatures.append(s)

    # Final return structure
    indicators = {
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_ports": src_ports,
        "dest_ports": dest_ports,
        "protocols": protocols,
        "commands": commands,
        "urls": urls,
        "signatures": signatures,
        "files": files,
    }

    return indicators



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
        start_idx = content.find("{")
        end_idx = content.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            json_str = content[start_idx : end_idx + 1]
            result = json.loads(json_str)
        else:
            raise ValueError(f"Model did not return valid JSON. Content was:\n{content}")

    # Start from schema template (ensures all fields exist)
    template = make_layer1_result_template(session)
    merged = template

    # Merge model output into template
    for key, value in result.items():
        if key in merged and isinstance(value, dict) and isinstance(merged[key], dict):
            merged[key].update(value)
        else:
            merged[key] = value

    # Deterministic key_indicators from session events (override model guesses)
    static_indicators = extract_key_indicators_from_session(session)

    if "key_indicators" not in merged or not isinstance(merged["key_indicators"], dict):
        merged["key_indicators"] = static_indicators
    else:
        for k, v in static_indicators.items():
            # Only overwrite when we have a non-empty deterministic value
            if k in ["src_ip", "dest_ip"]:
                if v:  # non-empty string
                    merged["key_indicators"][k] = v
            else:
                if isinstance(v, list) and len(v) > 0:
                    merged["key_indicators"][k] = v

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
    total = len(sessions)

    print(f"[INFO] Loaded {total} sessions for {date_str} from {session_dir}")

    if total == 0:
        print(f"[INFO] No sessions to process for {date_str}.")
        return

    model = make_model()

    processed = 0
    for idx, session in enumerate(sessions, start=1):
        session_id = session.get("session_id", f"session_{idx}")

        print(f"[AI-L1] Processing session {idx}/{total}: {session_id} ...")

        try:
            analysis = analyze_single_session(model, session)
            save_analysis(output_dir, date_str, session, analysis)
            processed += 1
        except Exception as e:
            print(f"[WARN] Failed to analyze session {session_id}: {e}")

    print(f"[INFO] AI Layer 1 completed for {date_str}: {processed}/{total} sessions processed.")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python ai/layer1/analyze_session.py <YYYY-MM-DD>")
        sys.exit(1)

    date_arg = sys.argv[1]
    run_layer1_for_date(date_arg)
