from log_parser import read_log_file
from detection_engine import calculate_risk_score, detect_brute_force
from finding import create_finding
from report import generate_report


# --------------------------------------------------
# READ LOG FILE
# --------------------------------------------------

content = read_log_file("backend/data/sample.log")


# --------------------------------------------------
# DATA STORAGE
# --------------------------------------------------

error_count = 0
warning_count = 0

ip_counts = {}
failed_login_counts = {}
warning_counts = {}

findings = []


# --------------------------------------------------
# PARSE LOG DATA
# --------------------------------------------------

for line in content:

    if "ERROR" in line:
        error_count += 1

    if "WARNING" in line:
        warning_count += 1

    parts = line.split()
    ip_address = parts[-1]

    if ip_address in ip_counts:
        ip_counts[ip_address] += 1
    else:
        ip_counts[ip_address] = 1

    if "Failed login" in line:
        if ip_address in failed_login_counts:
            failed_login_counts[ip_address] += 1
        else:
            failed_login_counts[ip_address] = 1

    if "WARNING" in line:
        if ip_address in warning_counts:
            warning_counts[ip_address] += 1
        else:
            warning_counts[ip_address] = 1


# --------------------------------------------------
# ANALYZE IP ACTIVITY
# --------------------------------------------------

for ip in ip_counts:

    failed_logins = failed_login_counts.get(ip, 0)
    warnings = warning_counts.get(ip, 0)
    total_events = ip_counts[ip]

    risk_score = calculate_risk_score(
        failed_logins,
        warnings,
        total_events
    )

    brute_force_detected = detect_brute_force(failed_logins)

    finding = create_finding(
        ip,
        risk_score,
        failed_logins,
        warnings
    )

    finding["brute_force"] = brute_force_detected

    findings.append(finding)


# ==================================================
# SENTINELX HEADER
# ==================================================

print()
print("=" * 55)
print("           SENTINELX SECURITY ANALYZER")
print("=" * 55)


# ==================================================
# LOG SUMMARY
# ==================================================

print()
print("LOG SUMMARY")
print("-" * 55)

print("Total Log Events :", len(content))
print("Errors           :", error_count)
print("Warnings         :", warning_count)


# ==================================================
# IP ACTIVITY
# ==================================================

print()
print("IP ACTIVITY")
print("-" * 55)

for ip, count in ip_counts.items():

    event_word = "event" if count == 1 else "events"

    print(f"{ip} → {count} {event_word}")


# ==================================================
# AUTHENTICATION ACTIVITY
# ==================================================

print()
print("AUTHENTICATION ACTIVITY")
print("-" * 55)

if failed_login_counts:

    for ip, count in failed_login_counts.items():

        login_word = "failed login" if count == 1 else "failed logins"

        print(f"{ip} → {count} {login_word}")

else:

    print("No failed login activity detected.")


# ==================================================
# WARNING ACTIVITY
# ==================================================

print()
print("WARNING ACTIVITY")
print("-" * 55)

if warning_counts:

    for ip, count in warning_counts.items():

        warning_word = "warning" if count == 1 else "warnings"

        print(f"{ip} → {count} {warning_word}")

else:

    print("No warning activity detected.")


# ==================================================
# THREAT DETECTION
# ==================================================

print()
print("THREAT DETECTION")
print("-" * 55)

threat_detected = False

for finding in findings:

    if finding["brute_force"]:

        print(
            f"{finding['ip']} → "
            "BRUTE FORCE DETECTED"
        )

        threat_detected = True


if not threat_detected:

    print("No brute-force activity detected.")


# ==================================================
# RISK ANALYSIS
# ==================================================

print()
print("RISK ANALYSIS")
print("-" * 55)

for finding in findings:

    print(
        f"{finding['ip']} → "
        f"{finding['severity']} | "
        f"Score: {finding['risk_score']}"
    )


# ==================================================
# SECURITY REPORT
# ==================================================

print()
print("SECURITY REPORT")
print("=" * 55)

print(generate_report(findings))