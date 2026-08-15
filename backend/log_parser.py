def read_log_file(file_path):
    with open(file_path, "r") as file:
        content = file.readlines()

    return content