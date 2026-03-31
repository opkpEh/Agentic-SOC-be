import re

def parse_log(log: str) -> dict:
    timestamp = datetime.utcnow().isoformat()
    level = "info"
    description = log

    agent_name = "unknown"
    agent_ip = "unknown"
    manager = "splunk"
    rule_id = "unknown"
    location = "unknown"

    user = "unknown"
    service = "unknown"
    outcome = "unknown"

    kv_pairs = dict(re.findall(r'(\w+)=("[^"]+"|\S+)', log))
    kv_pairs = {k: v.strip('"') for k, v in kv_pairs.items()}

    ts_match = re.search(r'\d{4}-\d{2}-\d{2}T[\d:.+-]+', log)
    if ts_match:
        timestamp = ts_match.group()
    
    ip_match = re.search(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})', log)
    if ip_match:
        agent_ip = ip_match.group(1)

    user_match = re.search(r'user[= ](\w+)', log)
    if user_match:
        user = user_match.group(1)

    host_match = re.search(r'host[= ](\S+)', log)
    if host_match:
        agent_name = host_match.group(1)

    if "sshd" in log.lower():
        service = "ssh"
    elif "http" in log.lower():
        service = "http"

    if "failed" in log.lower():
        outcome = "failed"
        level = "medium"
    elif "success" in log.lower() or "accepted" in log.lower():
        outcome = "success"
        level = "low"

    rule_match = re.search(r'\[(\d+)\]', log)
    
    if rule_match:
        rule_id = rule_match.group(1)

    location = service if service != "unknown" else "log"

    session_id = generate_session_id(agent_ip, user, agent_name)

    return {
        "timestamp": timestamp,
        "level": level,
        "description": description,
        "agent_name": agent_name,
        "agent_ip": agent_ip,
        "manager": manager,
        "rule_id": rule_id,
        "location": location,
        "user": user,
        "service": service,
        "outcome": outcome,
        "session_id": session_id,
        "raw": log
    }

def enrich(alert: dict):
    ip = alert.get("agent_ip", "unknown")
    user = alert.get("user", "unknown")
    host = alert.get("agent_name", "unknown")

    is_internal = is_internal_ip(ip)
    country = "India" if is_internal else "Unknown"

    if user.lower() in ["admin", "root"]:
        role = "admin"
    elif user.lower() in ["system", "service"]:
        role = "service"
    else:
        role = "user"

    device_key = f"{user}@{host}"

    if device_key in KNOWN_DEVICES:
        device_status = "known"
    else:
        device_status = "new"
        KNOWN_DEVICES.add(device_key)

    alert.update({
        "is_internal": is_internal,
        "country": country,
        "user_role": role,
        "device_status": device_status
    })

    return alert
