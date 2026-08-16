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
        print("Error: Permission denied while reading the log file.")
        return []

    except OSError as error:
        print("Error reading log file:", error)
        return []


def is_valid_log_line(line):
    parts = line.split()

    if len(parts) < 5:
        return False

    ip_address = parts[-1]

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return False

    return True


def extract_timestamp(line):
    parts = line.split()

    if len(parts) < 2:
        return None

    timestamp_text = parts[0] + " " + parts[1]

    try:
        return datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S"
        )

    except ValueError:
        return None