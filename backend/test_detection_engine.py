from datetime import datetime

from detection_engine import (
    calculate_risk_score,
    detect_brute_force,
    detect_time_based_brute_force,
    detect_port_scan,
    detect_account_attack
)

from finding import create_finding
from report import generate_report

from log_parser import (
    read_log_file,
    is_valid_log_line,
    extract_timestamp,
    extract_port,
    extract_username
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


def test_account_attack_increases_risk_score():

    score = calculate_risk_score(
        failed_logins=0,
        warnings=0,
        total_events=3,
        account_attack=True
    )

    assert score == 7


def test_account_attack_and_port_scan_both_increase_risk_score():

    score = calculate_risk_score(
        failed_logins=0,
        warnings=0,
        total_events=1,
        port_scan=True,
        account_attack=True
    )

    assert score == 10


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
# MULTI-ACCOUNT ATTACK TESTS
# ==================================================

def test_account_attack_detected_with_three_distinct_users():

    events = [
        ("2026-08-06 10:00:00", "alice"),
        ("2026-08-06 10:01:00", "bob"),
        ("2026-08-06 10:04:59", "charlie")
    ]

    assert detect_account_attack(events) is True


def test_account_attack_detected_at_exact_five_minute_boundary():

    events = [
        ("2026-08-06 10:00:00", "alice"),
        ("2026-08-06 10:02:30", "bob"),
        ("2026-08-06 10:05:00", "charlie")
    ]

    assert detect_account_attack(events) is True


def test_account_attack_not_detected_with_only_two_distinct_users():

    events = [
        ("2026-08-06 10:00:00", "alice"),
        ("2026-08-06 10:01:00", "bob"),
        ("2026-08-06 10:02:00", "alice")
    ]

    assert detect_account_attack(events) is False


def test_account_attack_is_case_insensitive_for_duplicate_users():

    events = [
        ("2026-08-06 10:00:00", "alice"),
        ("2026-08-06 10:01:00", "ALICE"),
        ("2026-08-06 10:02:00", "Alice")
    ]

    assert detect_account_attack(events) is False


def test_account_attack_not_detected_outside_time_window():

    events = [
        ("2026-08-06 10:00:00", "alice"),
        ("2026-08-06 10:02:30", "bob"),
        ("2026-08-06 10:05:01", "charlie")
    ]

    assert detect_account_attack(events) is False


def test_account_attack_ignores_malformed_and_duplicate_events():

    events = [
        None,
        ("not a timestamp", "alice"),
        ("2026-08-06 10:00:00", ""),
        ("2026-08-06 10:00:00", None),
        ("2026-08-06 10:00:00", "alice"),
        ("2026-08-06 10:00:01", "ALICE"),
        ("2026-08-06 10:00:02", "bob"),
        ("2026-08-06 10:00:03", "malformed!")
    ]

    assert detect_account_attack(events) is False


def test_account_attack_accepts_unsorted_datetime_events():

    events = [
        (datetime(2026, 8, 6, 10, 2), "bob"),
        (datetime(2026, 8, 6, 10, 0), "alice"),
        (datetime(2026, 8, 6, 10, 4), "charlie")
    ]

    assert detect_account_attack(events) is True


def test_account_attack_rejects_invalid_rule_parameters():

    events = [
        ("2026-08-06 10:00:00", "alice"),
        ("2026-08-06 10:01:00", "bob"),
        ("2026-08-06 10:02:00", "charlie")
    ]

    assert detect_account_attack(events, threshold=0) is False
    assert detect_account_attack(events, window_seconds=-1) is False


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


def test_account_attack_finding_includes_targeted_accounts():

    finding = create_finding(
        "192.168.1.60",
        13,
        3,
        0,
        account_attack=True,
        targeted_accounts=["alice", "bob", "charlie"]
    )

    assert finding["threat"] == "Account Attack"
    assert finding["account_attack"] is True
    assert finding["targeted_accounts"] == [
        "alice",
        "bob",
        "charlie"
    ]


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


def test_report_includes_account_attack_details():

    finding = create_finding(
        "192.168.1.60",
        13,
        3,
        0,
        account_attack=True,
        targeted_accounts=["alice", "bob", "charlie"]
    )
    finding["account_attack_reason"] = (
        "3 distinct usernames targeted within 5 minutes"
    )

    report = generate_report([finding])

    assert "Account Attack: Yes" in report
    assert "Targeted Accounts: alice, bob, charlie" in report
    assert "within 5 minutes" in report


# ==================================================
# LOG FILE TESTS
# ==================================================

def test_read_log_file():

    lines = read_log_file(
        "backend/data/sample.log"
    )

    assert len(lines) == 15


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


def test_extract_username_for_user_format():

    line = (
        "2026-08-06 10:01:30 ERROR Failed login "
        "for user alice 192.168.1.15"
    )

    assert extract_username(line) == "alice"


def test_extract_username_for_account_and_key_value_formats():

    account_line = (
        "2026-08-06 10:01:30 ERROR Failed login "
        "for account Domain\\alice 192.168.1.15"
    )
    key_value_line = (
        "2026-08-06 10:01:30 ERROR Failed login "
        "username=bob 192.168.1.15"
    )

    assert extract_username(account_line) == "Domain\\alice"
    assert extract_username(key_value_line) == "bob"


def test_extract_username_ignores_missing_or_malformed_values():

    no_username_line = (
        "2026-08-06 10:01:30 ERROR Failed login "
        "192.168.1.15"
    )
    malformed_username_line = (
        "2026-08-06 10:01:30 ERROR Failed login "
        "user=alice! 192.168.1.15"
    )

    assert extract_username(no_username_line) is None
    assert extract_username(malformed_username_line) is None


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
