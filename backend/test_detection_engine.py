from detection_engine import calculate_risk_score, detect_brute_force
from finding import create_finding
from report import generate_report
from log_parser import read_log_file, is_valid_log_line


def test_failed_login_and_warning():
    score = calculate_risk_score(1, 1, 2)

    assert score == 5


def test_normal_activity():
    score = calculate_risk_score(0, 0, 2)

    assert score == 0


def test_multiple_events():
    score = calculate_risk_score(0, 0, 3)

    assert score == 2


def test_multiple_failed_logins():
    score = calculate_risk_score(3, 0, 3)

    assert score == 8


def test_brute_force_detected():
    result = detect_brute_force(3)

    assert result is True


def test_brute_force_not_detected():
    result = detect_brute_force(2)

    assert result is False


def test_high_severity_finding():
    finding = create_finding(
        "192.168.1.15",
        11,
        3,
        1
    )

    assert finding["severity"] == "HIGH"
    assert finding["threat"] == "Brute Force"


def test_normal_finding():
    finding = create_finding(
        "192.168.1.10",
        0,
        0,
        0
    )

    assert finding["severity"] == "NORMAL"
    assert finding["threat"] == "Normal Activity"


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

    assert "192.168.1.15" in report
    assert "Brute Force" in report
    assert "HIGH" in report
    assert "Risk Score   : 11" in report


def test_read_log_file():
    lines = read_log_file("backend/data/sample.log")

    assert len(lines) == 7


def test_valid_log_line():
    line = "2026-08-06 10:01:30 ERROR Failed login 192.168.1.15"

    assert is_valid_log_line(line) is True


def test_invalid_log_line():
    line = "THIS IS NOT A VALID LOG"

    assert is_valid_log_line(line) is False