from log_parser import read_log_file


content = read_log_file("backend/data/sample.log")

error_count = 0
warning_count = 0
ip_counts = {}
failed_login_counts = {}
warning_counts = {}


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

    if "Failed login" in line:
        if ip_address in failed_login_counts:
            failed_login_counts[ip_address] += 1
        else:
            failed_login_counts[ip_address] = 1

    if "WARNING" in line:
        if ip_address in warning_counts:
            warning_counts[ip_address] += 1
        else:
            warning_counts[ip_address] = 1

    print(line)


print("Total errors:", error_count)
print("Total warnings:", warning_count)


print("IP Activity:")

for ip, count in ip_counts.items():
    print(ip, "→", count, "events")


print("Failed Login Activity:")

for ip, count in failed_login_counts.items():
    print(ip, "→", count, "failed logins")


print("Warning Activity:")

for ip, count in warning_counts.items():
    print(ip, "→", count, "warnings")


print("Suspicious IPs:")

for ip, count in ip_counts.items():
    if count >= 3:
        print(ip, "→", count, "events")


print("Risk Analysis:")

for ip in ip_counts:

    risk_score = 0

    if ip in failed_login_counts:
        risk_score += failed_login_counts[ip] * 2

    if ip in warning_counts:
        risk_score += warning_counts[ip] * 3

    if ip_counts[ip] >= 3:
        risk_score += 2

    print(ip, "→ Risk Score:", risk_score)