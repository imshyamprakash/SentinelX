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

        if finding.get("account_attack"):
            report.append("Account Attack: Yes")

            accounts = finding.get("targeted_accounts", [])
            report.append(
                "Targeted Accounts: " + ", ".join(accounts)
            )

            reason = finding.get("account_attack_reason")

            if reason:
                report.append("Attack Reason: " + reason)

        report.append("-" * 50)

    return "\n".join(report)
