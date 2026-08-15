from detection_engine import calculate_risk_score


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