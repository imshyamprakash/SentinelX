def generate_report(findings):
    report = []

    for finding in findings:
        report.append("")
        report.append("IP Address   : " + finding["ip"])
        report.append("Threat       : " + finding["threat"])
        report.append("Severity     : " + finding["severity"])
        report.append("Risk Score   : " + str(finding["risk_score"]))
        report.append("Failed Logins: " + str(finding["failed_logins"]))
        report.append("Warnings     : " + str(finding["warnings"]))
        report.append("-" * 50)

    return "\n".join(report)