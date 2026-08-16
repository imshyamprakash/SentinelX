from detection_engine import (
    calculate_risk_score,
    detect_brute_force,
    detect_time_based_brute_force,
    detect_port_scan
)

from finding import create_finding
from report import generate_report

from log_parser import (
    read_log_file,
    is_valid_log_line,
    extract_timestamp,
    extract_port
)


# ==================================================
# RISK SCORE TESTS
# ==================================================

def test_failed_login_and_warning():

    score = calculate_risk_score(
        1,
        1,
        2
    )

    assert score == 5


def test_normal_activity():

    score = calculate_risk_score(
        0,
        0,
        2
    )

    assert score == 0


def test_multiple_events():

    score = calculate_risk_score(
        0,
        0,
        3
    )

    assert score == 2


def test_multiple_failed_logins():

    score = calculate_risk_score(
        3,
        0,
        3
    )

    assert score == 8


def test_port_scan_increases_risk_score():

    score = calculate_risk_score(
        failed_logins=0,
        warnings=0,
        total_events=5,
        port_scan=True
    )

    assert score == 7


def test_without_port_scan_risk_score_is_unchanged():

    score = calculate_risk_score(
        failed_logins=0,
        warnings=0,
        total_events=5,
        port_scan=False
    )

    assert score == 2


# ==================================================
# BRUTE FORCE TESTS
# ==================================================

def test_brute_force_detected():

    result = detect_brute_force(3)

    assert result is True


def test_brute_force_not_detected():

    result = detect_brute_force(2)

    assert result is False


def test_time_based_brute_force_detected():

    timestamps = [
        "2026-08-06 10:08:30",
        "2026-08-06 10:08:45",
        "2026-08-06 10:09:00"
    ]

    result = detect_time_based_brute_force(
        timestamps,
        threshold=3,
        window_seconds=60
    )

    assert result is True


def test_time_based_brute_force_not_detected():

    timestamps = [
        "2026-08-06 10:00:00",
        "2026-08-06 12:00:00",
        "2026-08-06 14:00:00"
    ]

    result = detect_time_based_brute_force(
        timestamps,
        threshold=3,
        window_seconds=60
    )

    assert result is False


# ==================================================
# PORT SCAN TESTS
# ==================================================

def test_port_scan_detected():

    ports = [
        ("2026-08-06 10:10:00", 22),
        ("2026-08-06 10:10:05", 23),
        ("2026-08-06 10:10:10", 80),
        ("2026-08-06 10:10:15", 443),
        ("2026-08-06 10:10:20", 3389)
    ]

    result = detect_port_scan(
        ports,
        threshold=5,
        window_seconds=60
    )

    assert result is True


def test_port_scan_not_detected():

    ports = [
        ("2026-08-06 10:10:00", 22),
        ("2026-08-06 12:10:00", 23),
        ("2026-08-06 14:10:00", 80),
        ("2026-08-06 16:10:00", 443),
        ("2026-08-06 18:10:00", 3389)
    ]

    result = detect_port_scan(
        ports,
        threshold=5,
        window_seconds=60
    )

    assert result is False


def test_port_scan_requires_distinct_ports():

    ports = [
        ("2026-08-06 10:10:00", 22),
        ("2026-08-06 10:10:05", 22),
        ("2026-08-06 10:10:10", 22),
        ("2026-08-06 10:10:15", 22),
        ("2026-08-06 10:10:20", 22)
    ]

    result = detect_port_scan(
        ports,
        threshold=5,
        window_seconds=60
    )

    assert result is False


# ==================================================
# FINDING TESTS
# ==================================================

def test_high_severity_finding():

    finding = create_finding(
        "192.168.1.15",
        11,
        3,
        1
    )

    assert finding["severity"] == "HIGH"

    assert (
        finding["threat"]
        == "Brute Force"
    )


def test_normal_finding():

    finding = create_finding(
        "192.168.1.10",
        0,
        0,
        0
    )

    assert finding["severity"] == "NORMAL"

    assert (
        finding["threat"]
        == "Normal Activity"
    )


# ==================================================
# REPORT TEST
# ==================================================

def test_generate_report():

    findings = [
        {
            "ip": "192.168.1.15",
            "threat": "Brute Force",
            "severity": "HIGH",
            "risk_score": 11,
            "failed_logins": 3,
            "warnings": 1
        }
    ]

    report = generate_report(findings)

    assert (
        "192.168.1.15"
        in report
    )

    assert (
        "Brute Force"
        in report
    )

    assert (
        "HIGH"
        in report
    )

    assert (
        "Risk Score   : 11"
        in report
    )


# ==================================================
# LOG FILE TESTS
# ==================================================

def test_read_log_file():

    lines = read_log_file(
        "backend/data/sample.log"
    )

    assert len(lines) == 12


def test_valid_log_line():

    line = (
        "2026-08-06 10:01:30 "
        "ERROR Failed login "
        "192.168.1.15"
    )

    assert (
        is_valid_log_line(line)
        is True
    )


def test_invalid_log_line():

    line = (
        "THIS IS NOT A VALID LOG"
    )

    assert (
        is_valid_log_line(line)
        is False
    )


def test_invalid_ip_address():

    line = (
        "2026-08-06 10:01:30 "
        "ERROR Failed login "
        "999.999.999.999"
    )

    assert (
        is_valid_log_line(line)
        is False
    )


def test_valid_ipv4_address():

    line = (
        "2026-08-06 10:01:30 "
        "ERROR Failed login "
        "10.0.0.1"
    )

    assert (
        is_valid_log_line(line)
        is True
    )


# ==================================================
# TIMESTAMP TESTS
# ==================================================

def test_extract_timestamp():

    line = (
        "2026-08-06 10:08:30 "
        "ERROR Failed login "
        "192.168.1.15"
    )

    timestamp = extract_timestamp(line)

    assert timestamp is not None

    assert (
        timestamp.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        == "2026-08-06 10:08:30"
    )


def test_invalid_timestamp():

    line = (
        "invalid timestamp "
        "ERROR Failed login "
        "192.168.1.15"
    )

    timestamp = extract_timestamp(line)

    assert timestamp is None


# ==================================================
# PORT EXTRACTION TESTS
# ==================================================

def test_valid_port_extraction():

    line = (
        "2026-08-06 10:10:00 "
        "INFO Connection attempt "
        "192.168.1.50 443"
    )

    port = extract_port(line)

    assert port == 443


def test_invalid_port_extraction():

    line = (
        "2026-08-06 10:10:00 "
        "INFO Connection attempt "
        "192.168.1.50"
    )

    port = extract_port(line)

    assert port is None


def test_invalid_port_range():

    line = (
        "2026-08-06 10:10:00 "
        "INFO Connection attempt "
        "192.168.1.50 70000"
    )

    port = extract_port(line)

    assert port is None


def test_valid_log_with_port():

    line = (
        "2026-08-06 10:10:00 "
        "INFO Connection attempt "
        "192.168.1.50 443"
    )

    assert (
        is_valid_log_line(line)
        is True
    )