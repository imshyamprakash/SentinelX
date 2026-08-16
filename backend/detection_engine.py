from datetime import datetime


def calculate_risk_score(
    failed_logins,
    warnings,
    total_events,
    port_scan=False
):
    score = 0

    # Failed login = 2 points each
    score += failed_logins * 2

    # Warning = 3 points each
    score += warnings * 3

    # Multiple events = 2 points
    if total_events >= 3:
        score += 2

    # Port scan = 5 additional points
    if port_scan:
        score += 5

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


def detect_port_scan(
    ports,
    threshold=5,
    window_seconds=60
):
    """
    Detect multiple distinct ports targeted
    within a short time window.

    Default rule:
    5 distinct ports within 60 seconds.
    """

    if len(ports) < threshold:
        return False

    parsed_events = []

    for event in ports:

        if not isinstance(event, tuple):
            continue

        timestamp, port = event

        if not isinstance(timestamp, datetime):
            timestamp = datetime.strptime(
                timestamp,
                "%Y-%m-%d %H:%M:%S"
            )

        parsed_events.append(
            (timestamp, port)
        )

    parsed_events.sort(
        key=lambda event: event[0]
    )

    for index in range(
        len(parsed_events) - threshold + 1
    ):

        window_events = parsed_events[
            index:index + threshold
        ]

        start_time = window_events[0][0]
        end_time = window_events[-1][0]

        time_difference = (
            end_time - start_time
        ).total_seconds()

        distinct_ports = {
            event[1]
            for event in window_events
        }

        if (
            len(distinct_ports) >= threshold
            and time_difference <= window_seconds
        ):
            return True

    return False