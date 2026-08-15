def create_finding(ip, risk_score, failed_logins, warnings):
    if risk_score >= 10:
        severity = "HIGH"
    elif risk_score >= 5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "ip": ip,
        "threat": "Brute Force" if failed_logins >= 3 else "Suspicious Activity",
        "severity": severity,
        "risk_score": risk_score,
        "failed_logins": failed_logins,
        "warnings": warnings
    }