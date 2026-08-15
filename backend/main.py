file = open("backend/data/sample.log", "r")

content = file.readlines()

error_count = 0
warning_count = 0

for line in content:
    if "ERROR" in line:
        error_count += 1

    if "WARNING" in line:
        warning_count += 1

    print(line)

print("Total errors:", error_count)
print("Total warnings:", warning_count)

file.close()