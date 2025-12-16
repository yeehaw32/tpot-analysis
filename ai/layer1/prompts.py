# prompts.py

from typing import Dict, Any, List
from textwrap import dedent


def build_session_digest(session: Dict[str, Any], max_events: int = 50) -> str:
    """
    Build a compact, human-readable digest of the session.
    Only includes the most important fields from each event
    to keep the prompt small.
    """

    events: List[Dict[str, Any]] = session.get("events", [])
    lines: List[str] = []

    header = f"Session ID: {session.get('session_id', '')}\n" \
             f"Sensor: {session.get('sensor', '')}\n" \
             f"Src IP: {session.get('src_ip', '')}\n" \
             f"Dst IP: {session.get('dest_ip', '')}\n" \
             f"Start: {session.get('start_time', '')}\n" \
             f"End:   {session.get('end_time', '')}\n" \
             f"Total events: {len(events)}\n"
    lines.append(header)
    lines.append("Events (truncated):")

    count = 0
    for event in events:
        if count >= max_events:
            lines.append(f"... ({len(events) - max_events} more events omitted)")
            break

        timestamp = event.get("timestamp", "")
        src_ip = event.get("src_ip", "")
        src_port = event.get("src_port", "")
        dest_ip = event.get("dest_ip", "")
        dest_port = event.get("dest_port", "")
        protocol = event.get("protocol", "")
        eventid = event.get("eventid", "")
        message = event.get("message", "")
        url = event.get("url", "")

        line = f"- {timestamp} | {src_ip}:{src_port} -> {dest_ip}:{dest_port} | proto={protocol} | eventid={eventid}"
        if url:
            line += f" | url={url}"
        if message:
            # keep message short
            short_msg = message[:200]
            if len(message) > 200:
                short_msg += "..."
            line += f" | msg={short_msg}"

        lines.append(line)
        count += 1

    return "\n".join(lines)


def build_layer1_system_prompt() -> str:
  
    text = dedent(
        """
        You are an AI assistant performing security analysis on a single honeypot session.

        Rules:
        - Only use the information present in the provided session.
        - Do NOT use external knowledge, databases, or documentation.
        - Do NOT claim to know exact MITRE techniques, Sigma rules, or Suricata rules.
        - Do NOT extract or infer observables into key_indicators. Leave key_indicators empty (the pipeline fills it deterministically).
        - Stay strictly within the evidence you see.
        - If something is unclear, mark it as "unknown" rather than guessing wildly.

        Output:
        - You MUST return a single JSON object.
        - The JSON must be syntactically valid.
        - The JSON must follow this structure:

          {
            "session_id": string,
            "sensor": string,
            "attack_intent": string,
            "summary": string,
            "key_indicators": {
              "src_ip": string,
              "dest_ip": string,
              "src_ports": [string or int],
              "dest_ports": [string or int],
              "protocols": [string],
              "commands": [string],
              "urls": [string],
              "signatures": [string],
              "files": [string]
            },
            "confidence": float between 0 and 1,
            "risk_score": integer between 0 and 10,
            "timestamp_range": {
              "start": string,
              "end": string
            }
          }

        Constraints:
        - "attack_intent" should be a short label like
          "ssh_bruteforce", "telnet_bruteforce", "web_scanning",
          "directory_bruteforce", "malware_drop_attempt", "exploit_attempt", or "unknown".
        - "summary" should be 1 - 4 sentences, plain language.
        - "confidence" should reflect how clearly the events support the attack intent.
        - "risk_score" is a simple severity estimate based ONLY on this session.
        """
    ).strip()
    return text


def build_layer1_user_prompt(session_digest: str) -> str:
    """
    Human message that gives the actual session digest to the model.
    """

    return f"Here is the honeypot session you must analyze:\n\n{session_digest}\n\nReturn only the JSON object as specified."
