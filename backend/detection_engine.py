from datetime import datetime


def calculate_risk_score(
    failed_logins,
    warnings,
    total_events
):
    score = 0

    score += failed_logins * 2
    score += warnings * 3

    if total_events >= 3:
        score += 2

    return score


def detect_brute_force(failed_logins):
    return failed_logins >= 3


def detect_time_based_brute_force(
    timestamps,
    threshold=3,
    window_seconds=60
):
    if len(timestamps) < threshold:
        return False

    parsed_times = []

    for timestamp in timestamps:
        if isinstance(timestamp, datetime):
            parsed_times.append(timestamp)
        else:
            parsed_times.append(
                datetime.strptime(
                    timestamp,
                    "%Y-%m-%d %H:%M:%S"
                )
            )

    parsed_times.sort()

    for index in range(
        len(parsed_times) - threshold + 1
    ):
        start_time = parsed_times[index]
        end_time = parsed_times[
            index + threshold - 1
        ]

        time_difference = (
            end_time - start_time
        ).total_seconds()

        if time_difference <= window_seconds:
            return True

    return False