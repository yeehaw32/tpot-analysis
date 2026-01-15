import os
import json
import glob
import datetime
from ai.rag.sigma_query import get_sigma_collection
from flask import Flask, jsonify, render_template, request, abort

import chromadb

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ENRICHED_BASE_DIR = "/data/tpot_sessions/enriched"
CHROMA_PATH = "/home/bertil/tpot-analysis/data/chroma"

app = Flask(
    __name__,
    static_folder="static",
    template_folder="templates"
)


def today_str():
    return datetime.date.today().strftime("%Y-%m-%d")


def load_session_file(date_str, session_id):
    date_dir = os.path.join(ENRICHED_BASE_DIR, date_str)
    path = os.path.join(date_dir, f"{session_id}.json")
    if not os.path.isfile(path):
        return None

    with open(path, "r") as f:
        return json.load(f)


def list_sessions_for_date(date_str):
    date_dir = os.path.join(ENRICHED_BASE_DIR, date_str)
    if not os.path.isdir(date_dir):
        return []

    sessions = []

    for path in glob.glob(os.path.join(date_dir, "*.json")):
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except Exception:
            continue

        session_id = data.get("session_id")
        sensor = data.get("sensor")
        attack_intent = data.get("attack_intent")
        summary = data.get("summary", "") or ""

        key_ind = data.get("key_indicators", {})
        src_ip = key_ind.get("src_ip")
        dest_ip = key_ind.get("dest_ip")

        ts_range = data.get("timestamp_range", {})
        start_ts = ts_range.get("start")
        end_ts = ts_range.get("end")

        risk_score = data.get("risk_score")
        confidence = data.get("confidence")

        # Truncate summary for list view
        if len(summary) > 200:
            short_summary = summary[:197] + "..."
        else:
            short_summary = summary

        sessions.append({
            "session_id": session_id,
            "sensor": sensor,
            "attack_intent": attack_intent,
            "short_summary": short_summary,
            "risk_score": risk_score,
            "confidence": confidence,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "start_time": start_ts,
            "end_time": end_ts,
        })

    # Sort: highest risk first, then sensor, then session id
    sessions.sort(
        key=lambda s: (
            -(s["risk_score"] if isinstance(s["risk_score"], (int, float)) else 0),
            s["sensor"] or "",
            s["session_id"] or ""
        )
    )
    return sessions


@app.route("/")
def index():
    default_date = request.args.get("date") or today_str()
    return render_template("index.html", default_date=default_date)


@app.route("/api/sessions")
def api_sessions():
    date_str = request.args.get("date") or today_str()
    sessions = list_sessions_for_date(date_str)
    return jsonify({
        "date": date_str,
        "sessions": sessions
    })

@app.route("/api/session/<session_id>")
def api_session_detail(session_id):
    date_str = request.args.get("date") or today_str()
    data = load_session_file(date_str, session_id)
    if data is None:
        abort(404, description="Session not found")
    return jsonify(data)

@app.route("/api/sigma/<sid>")
def api_sigma_detail(sid):
    from ai.rag.sigma_query import get_sigma_collection

    collection = get_sigma_collection(
        chroma_path="/home/bertil/tpot-analysis/data/chroma/sigma"
    )

    res = None

    # First attempt: direct ID fetch
    try:
        get_res = collection.get(ids=[sid])
        if get_res and get_res["ids"] and get_res["ids"][0]:
            res = {
                "id": get_res["ids"][0],
                "yaml": get_res["metadatas"][0].get("yaml_raw"),
                "metadata": get_res["metadatas"][0],
            }
    except Exception:
        pass

    # If not found, try metadata query
    if res is None:
        try:
            q = collection.query(where={"sid": sid}, n_results=1)
            if q and q["ids"] and q["ids"][0]:
                meta = q["metadatas"][0][0]
                res = {
                    "id": q["ids"][0][0],
                    "yaml": meta.get("yaml_raw"),
                    "metadata": meta
                }
        except Exception:
            pass

    if res is None:
        abort(404, description="Sigma rule not found")

    return jsonify(res)




@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # For PoC: run directly on Analysis VM
    # Example: python3 app.py
    app.run(host="0.0.0.0", port=5000, debug=True)
