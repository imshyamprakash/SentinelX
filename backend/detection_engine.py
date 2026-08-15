def calculate_risk_score(failed_logins, warnings, total_events):
    risk_score = 0

    risk_score += failed_logins * 2
    risk_score += warnings * 3

    if total_events >= 3:
        risk_score += 2

    return risk_score


def detect_brute_force(failed_logins):
    return failed_logins >= 3