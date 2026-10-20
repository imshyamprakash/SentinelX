from datetime import datetime, timezone
import math


def calculate_risk_score(
    failed_logins,
    warnings,
    total_events,
    port_scan=False,
    account_attack=False
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

    # Multi-account attack = 5 additional points
    if account_attack:
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


def detect_account_attack(
    account_events,
    threshold=3,
    window_seconds=300
):
    """Detect failed logins against distinct accounts from one IP.

    Each event is a ``(timestamp, username)`` pair. Repeated attempts
    against the same username count once within the rolling time window.
    The default rule is 3 distinct usernames within 5 minutes.
    Malformed events are ignored.
    """

    if (
        type(threshold) is not int
        or threshold < 1
        or not isinstance(window_seconds, (int, float))
        or window_seconds < 0
    ):
        return False

    try:
        if not math.isfinite(window_seconds):
            return False
    except OverflowError:
        return False

    try:
        events = iter(account_events)
    except TypeError:
        return False

    parsed_events = []

    for event in events:
        if not isinstance(event, (tuple, list)) or len(event) != 2:
            continue

        timestamp, username = event

        if isinstance(timestamp, datetime):
            parsed_timestamp = timestamp

            if parsed_timestamp.tzinfo is not None:
                parsed_timestamp = parsed_timestamp.astimezone(
                    timezone.utc
                ).replace(tzinfo=None)

        elif isinstance(timestamp, str):
            try:
                parsed_timestamp = datetime.strptime(
                    timestamp,
                    "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                continue

        else:
            continue

        if not isinstance(username, str):
            continue

        normalized_username = username.strip().casefold()

        if not normalized_username or len(normalized_username) > 128:
            continue

        allowed_username_characters = "_.@-\\"

        if not all(
            character.isalnum()
            or character in allowed_username_characters
            for character in normalized_username
        ):
            continue

        parsed_events.append(
            (parsed_timestamp, normalized_username)
        )

    if len(parsed_events) < threshold:
        return False

    parsed_events.sort(key=lambda event: event[0])

    # A sliding window keeps the number of distinct usernames for each
    # range whose elapsed time is at most window_seconds.
    account_counts = {}
    start_index = 0

    for end_index, (end_time, username) in enumerate(parsed_events):
        account_counts[username] = (
            account_counts.get(username, 0) + 1
        )

        while (
            end_time - parsed_events[start_index][0]
        ).total_seconds() > window_seconds:
            old_username = parsed_events[start_index][1]
            account_counts[old_username] -= 1

            if account_counts[old_username] == 0:
                del account_counts[old_username]

            start_index += 1

        if len(account_counts) >= threshold:
            return True

    return False
