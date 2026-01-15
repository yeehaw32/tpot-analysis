# schema.py

from typing import Dict, Any


def make_layer1_result_template(session: Dict[str, Any]) -> Dict[str, Any]:

    session_id = session.get("session_id", "")
    sensor = session.get("sensor", "")
    src_ip = session.get("src_ip", "")
    dest_ip = session.get("dest_ip", "")
    start_time = session.get("start_time", "")
    end_time = session.get("end_time", "")

    result = {
        "session_id": session_id,
        "sensor": sensor,
        "attack_intent": "",     
        "summary": "",            
        "key_indicators": {
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_ports": [],      
            "protocols": [],
            "commands": [],      
            "urls": [],          
            "signatures": [],     
            "files": []           
        },
        "confidence": 0.0,        
        "risk_score": 0,          
        "timestamp_range": {
            "start": start_time,
            "end": end_time
        }
    }

    return result

