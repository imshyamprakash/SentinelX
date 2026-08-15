file = open("backend/data/sample.log", "r")

content = file.readlines()

error_count = 0
warning_count = 0
ip_counts = {}

for line in content:
    if "ERROR" in line:
        error_count += 1

    if "WARNING" in line:
        warning_count += 1

    parts = line.split()
    ip_address = parts[-1]

    if ip_address in ip_counts:
        ip_counts[ip_address] += 1
    else:
        ip_counts[ip_address] = 1

    print(line)

print("Total errors:", error_count)
print("Total warnings:", warning_count)
print("IP Activity:")

for ip, count in ip_counts.items():
    print(ip, "→", count, "events")

print("Suspicious IPs:")

for ip, count in ip_counts.items():
    if count >= 3:
        print(ip, "→", count, "events")

file.close()