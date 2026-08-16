import ipaddress
from datetime import datetime


def read_log_file(file_path):
    try:
        with open(file_path, "r") as file:
            content = file.readlines()

        return content

    except FileNotFoundError:
        print("Error: Log file not found.")
        return []

    except PermissionError:
        print(
            "Error: Permission denied while "
            "reading the log file."
        )
        return []

    except OSError as error:
        print(
            "Error reading log file:",
            error
        )
        return []


def is_valid_log_line(line):
    parts = line.split()

    if len(parts) < 5:
        return False

    # Normal log:
    # ... IP
    #
    # Network log:
    # ... IP PORT

    ip_address = parts[-1]

    # If the final field is a port,
    # the IP is immediately before it.
    if ip_address.isdigit():

        if len(parts) < 6:
            return False

        ip_address = parts[-2]

    try:
        ipaddress.ip_address(ip_address)

    except ValueError:
        return False

    return True


def extract_timestamp(line):
    parts = line.split()

    if len(parts) < 2:
        return None

    timestamp_text = (
        parts[0] + " " + parts[1]
    )

    try:
        return datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S"
        )

    except ValueError:
        return None


def extract_port(line):
    parts = line.split()

    if len(parts) < 2:
        return None

    possible_port = parts[-1]

    if not possible_port.isdigit():
        return None

    try:
        port = int(possible_port)

        if 1 <= port <= 65535:
            return port

    except ValueError:
        return None

    return None