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

    if parts[1] == "":
        return False

    if parts[-1].count(".") != 3:
        return False

    return True