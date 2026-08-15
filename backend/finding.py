def create_finding(ip, risk_score, failed_logins, warnings):
    if risk_score >= 10:
        severity = "HIGH"
    elif risk_score >= 5:
        severity = "MEDIUM"
    elif risk_score > 0:
        severity = "LOW"
    else:
        severity = "NORMAL"

    if failed_logins >= 3:
        threat = "Brute Force"
    elif risk_score > 0:
        threat = "Suspicious Activity"
    else:
        threat = "Normal Activity"

    return {
        "ip": ip,
        "threat": threat,
        "severity": severity,
        "risk_score": risk_score,
        "failed_logins": failed_logins,
        "warnings": warnings
    }