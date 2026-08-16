from log_parser import (
    read_log_file,
    is_valid_log_line,
    extract_timestamp
)

from detection_engine import (
    calculate_risk_score,
    detect_brute_force,
    detect_time_based_brute_force
)

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
valid_log_count = 0
invalid_log_count = 0

ip_counts = {}
failed_login_counts = {}
warning_counts = {}

# Store failed-login timestamps for each IP
failed_login_timestamps = {}

findings = []


# --------------------------------------------------
# PARSE AND VALIDATE LOG DATA
# --------------------------------------------------

for line in content:

    # Ignore malformed log entries
    if not is_valid_log_line(line):
        invalid_log_count += 1
        continue

    valid_log_count += 1

    parts = line.split()
    ip_address = parts[-1]

    timestamp = extract_timestamp(line)

    # Count errors
    if "ERROR" in line:
        error_count += 1

    # Count warnings
    if "WARNING" in line:
        warning_count += 1

    # Count activity for each IP
    if ip_address in ip_counts:
        ip_counts[ip_address] += 1
    else:
        ip_counts[ip_address] = 1

    # --------------------------------------------------
    # FAILED LOGIN ACTIVITY
    # --------------------------------------------------

    if "Failed login" in line:

        if ip_address in failed_login_counts:
            failed_login_counts[ip_address] += 1
        else:
            failed_login_counts[ip_address] = 1

        # Store timestamp for time-based detection
        if timestamp is not None:

            if ip_address not in failed_login_timestamps:
                failed_login_timestamps[ip_address] = []

            failed_login_timestamps[ip_address].append(
                timestamp
            )

    # --------------------------------------------------
    # WARNING ACTIVITY
    # --------------------------------------------------

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

    # Basic brute-force detection
    basic_brute_force = detect_brute_force(
        failed_logins
    )

    # Time-aware brute-force detection
    timestamps = failed_login_timestamps.get(
        ip,
        []
    )

    time_based_brute_force = detect_time_based_brute_force(
        timestamps,
        threshold=3,
        window_seconds=60
    )

    # Either detection rule can trigger brute force
    brute_force_detected = (
        basic_brute_force
        or time_based_brute_force
    )

    finding = create_finding(
        ip,
        risk_score,
        failed_logins,
        warnings
    )

    finding["brute_force"] = brute_force_detected
    finding["time_based_brute_force"] = (
        time_based_brute_force
    )

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

print("Total Log Events :", valid_log_count)
print("Errors           :", error_count)
print("Warnings         :", warning_count)

if invalid_log_count > 0:
    print("Invalid Log Lines:", invalid_log_count)


# ==================================================
# IP ACTIVITY
# ==================================================

print()
print("IP ACTIVITY")
print("-" * 55)

for ip, count in ip_counts.items():

    event_word = (
        "event"
        if count == 1
        else "events"
    )

    print(
        f"{ip} → {count} {event_word}"
    )


# ==================================================
# AUTHENTICATION ACTIVITY
# ==================================================

print()
print("AUTHENTICATION ACTIVITY")
print("-" * 55)

if failed_login_counts:

    for ip, count in failed_login_counts.items():

        login_word = (
            "failed login"
            if count == 1
            else "failed logins"
        )

        print(
            f"{ip} → {count} {login_word}"
        )

else:

    print(
        "No failed login activity detected."
    )


# ==================================================
# WARNING ACTIVITY
# ==================================================

print()
print("WARNING ACTIVITY")
print("-" * 55)

if warning_counts:

    for ip, count in warning_counts.items():

        warning_word = (
            "warning"
            if count == 1
            else "warnings"
        )

        print(
            f"{ip} → {count} {warning_word}"
        )

else:

    print(
        "No warning activity detected."
    )


# ==================================================
# THREAT DETECTION
# ==================================================

print()
print("THREAT DETECTION")
print("-" * 55)

threat_detected = False

for finding in findings:

    if finding["brute_force"]:

        if finding["time_based_brute_force"]:

            print(
                f"{finding['ip']} → "
                "BRUTE FORCE DETECTED "
                "(3 failures within 60 seconds)"
            )

        else:

            print(
                f"{finding['ip']} → "
                "BRUTE FORCE DETECTED"
            )

        threat_detected = True


if not threat_detected:

    print(
        "No brute-force activity detected."
    )


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

print(
    generate_report(findings)
)