from log_parser import (
    read_log_file,
    is_valid_log_line,
    extract_timestamp,
    extract_port
)

from detection_engine import (
    calculate_risk_score,
    detect_brute_force,
    detect_time_based_brute_force,
    detect_port_scan
)

from finding import create_finding
from report import generate_report


# ==================================================
# READ LOG FILE
# ==================================================

content = read_log_file(
    "backend/data/sample.log"
)


# ==================================================
# DATA STORAGE
# ==================================================

error_count = 0
warning_count = 0
valid_log_count = 0
invalid_log_count = 0

ip_counts = {}
failed_login_counts = {}
warning_counts = {}

failed_login_timestamps = {}

port_scan_events = {}

findings = []


# ==================================================
# PARSE AND VALIDATE LOG DATA
# ==================================================

for line in content:

    if not is_valid_log_line(line):
        invalid_log_count += 1
        continue

    valid_log_count += 1

    parts = line.split()

    port = extract_port(line)

    if port is not None:
        ip_address = parts[-2]
    else:
        ip_address = parts[-1]

    timestamp = extract_timestamp(line)

    # --------------------------------------------------
    # LOG LEVEL COUNTS
    # --------------------------------------------------

    if "ERROR" in line:
        error_count += 1

    if "WARNING" in line:
        warning_count += 1

    # --------------------------------------------------
    # IP ACTIVITY
    # --------------------------------------------------

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

        if timestamp is not None:

            if ip_address not in failed_login_timestamps:
                failed_login_timestamps[ip_address] = []

            failed_login_timestamps[
                ip_address
            ].append(timestamp)

    # --------------------------------------------------
    # WARNING ACTIVITY
    # --------------------------------------------------

    if "WARNING" in line:

        if ip_address in warning_counts:
            warning_counts[ip_address] += 1
        else:
            warning_counts[ip_address] = 1

    # --------------------------------------------------
    # PORT SCAN ACTIVITY
    # --------------------------------------------------

    if (
        port is not None
        and timestamp is not None
        and "Connection attempt" in line
    ):

        if ip_address not in port_scan_events:
            port_scan_events[ip_address] = []

        port_scan_events[ip_address].append(
            (timestamp, port)
        )


# ==================================================
# ANALYZE IP ACTIVITY
# ==================================================

for ip in ip_counts:

    failed_logins = failed_login_counts.get(
        ip,
        0
    )

    warnings = warning_counts.get(
        ip,
        0
    )

    total_events = ip_counts[ip]

    # --------------------------------------------------
    # BRUTE FORCE DETECTION
    # --------------------------------------------------

    basic_brute_force = detect_brute_force(
        failed_logins
    )

    timestamps = failed_login_timestamps.get(
        ip,
        []
    )

    time_based_brute_force = (
        detect_time_based_brute_force(
            timestamps,
            threshold=3,
            window_seconds=60
        )
    )

    # --------------------------------------------------
    # PORT SCAN DETECTION
    # --------------------------------------------------

    ports = port_scan_events.get(
        ip,
        []
    )

    port_scan_detected = detect_port_scan(
        ports,
        threshold=5,
        window_seconds=60
    )

    # --------------------------------------------------
    # RISK SCORE
    # --------------------------------------------------

    risk_score = calculate_risk_score(
        failed_logins,
        warnings,
        total_events,
        port_scan=port_scan_detected
    )

    # --------------------------------------------------
    # DETERMINE THREATS
    # --------------------------------------------------

    brute_force_detected = (
        basic_brute_force
        or time_based_brute_force
    )

    # --------------------------------------------------
    # DETECTION REASON
    # --------------------------------------------------

    if time_based_brute_force:

        detection_reason = (
            "3 failed logins within 60 seconds"
        )

    elif basic_brute_force:

        detection_reason = (
            f"{failed_logins} failed logins detected"
        )

    elif port_scan_detected:

        detection_reason = (
            "5 distinct ports targeted "
            "within 60 seconds"
        )

    else:

        detection_reason = None

    # --------------------------------------------------
    # CREATE FINDING
    # --------------------------------------------------

    finding = create_finding(
        ip,
        risk_score,
        failed_logins,
        warnings
    )

    if (
        port_scan_detected
        and not brute_force_detected
    ):
        finding["threat"] = "Port Scan"

    finding["brute_force"] = (
        brute_force_detected
    )

    finding["time_based_brute_force"] = (
        time_based_brute_force
    )

    finding["port_scan"] = (
        port_scan_detected
    )

    finding["detection_reason"] = (
        detection_reason
    )

    findings.append(finding)


# ==================================================
# SENTINELX HEADER
# ==================================================

print()

print("=" * 55)

print(
    "           SENTINELX SECURITY ANALYZER"
)

print("=" * 55)


# ==================================================
# LOG SUMMARY
# ==================================================

print()

print("LOG SUMMARY")

print("-" * 55)

print(
    "Total Log Events :",
    valid_log_count
)

print(
    "Errors           :",
    error_count
)

print(
    "Warnings         :",
    warning_count
)

if invalid_log_count > 0:

    print(
        "Invalid Log Lines:",
        invalid_log_count
    )


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

        print(
            f"{finding['ip']} → "
            "BRUTE FORCE DETECTED"
        )

        print(
            f"  Reason: "
            f"{finding['detection_reason']}"
        )

        threat_detected = True

    elif finding["port_scan"]:

        print(
            f"{finding['ip']} → "
            "PORT SCAN DETECTED"
        )

        print(
            f"  Reason: "
            f"{finding['detection_reason']}"
        )

        threat_detected = True


if not threat_detected:

    print(
        "No suspicious activity detected."
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