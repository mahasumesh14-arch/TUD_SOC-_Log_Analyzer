
import re
from collections import Counter


# ==========================================
# 1. FIREWALL LOG PARSING
# ==========================================

def parse_firewall_log(filename):

    firewall_events = []
    wrongformat_count = 0

    pattern = (
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
        r'(ALLOWED|BLOCKED) '
        r'src=(\S+) '
        r'dst=(\S+) '
        r'proto=(TCP|UDP) '
        r'port=(\d+) '
        r'bytes=(\d+)$'
    )

    with open(filename, "r") as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            match = re.match(pattern, line)

            if match:

                event = {
                    "timestamp": match.group(1),
                    "action": match.group(2),
                    "src_ip_addr": match.group(3),
                    "dest_ip_addr": match.group(4),
                    "protocol": match.group(5),
                    "port": int(match.group(6)),
                    "bytes": int(match.group(7))
                }

                firewall_events.append(event)

            else:
                wrongformat_count += 1
                print("Wrongly formatted firewall line:", line_number)

    return firewall_events, wrongformat_count


# ==========================================
# 2. FIREWALL LOG ANALYSIS
# ==========================================

def analyse_firewall_logs(firewall_events):

    total_events = len(firewall_events)

    allowed_count = 0
    blocked_count = 0

    source_ips = set()
    blocked_ips = []
    destination_ports = []

    for event in firewall_events:

        if event["action"] == "ALLOWED":
            allowed_count += 1

        elif event["action"] == "BLOCKED":
            blocked_count += 1
            blocked_ips.append(event["src_ip_addr"])

        source_ips.add(event["src_ip_addr"])
        destination_ports.append(event["port"])

    top_blocked_ips = Counter(blocked_ips).most_common(10)

    common_ports = Counter(destination_ports).most_common(10)

    return {
        "total_events": total_events,
        "allowed": allowed_count,
        "blocked": blocked_count,
        "unique_source_ips": len(source_ips),
        "top_blocked_ips": top_blocked_ips,
        "common_ports": common_ports
    }


# ==========================================
# 3. DISPLAY FIREWALL RESULTS
# ==========================================

def display_firewall_results(results, wrongformat_count):

    print("\n========================================")
    print("       FIREWALL INVESTIGATION")
    print("========================================")

    print("Valid events:", results["total_events"])
    print("Wrongly formatted events:", wrongformat_count)
    print("Allowed events:", results["allowed"])
    print("Blocked events:", results["blocked"])
    print("Unique source IP addresses:", results["unique_source_ips"])

    print("\n Major 10 Blocked Source IPs:")

    for ip, count in results["top_blocked_ips"]:
        print(ip, "-", count, "blocked events")

    print("\n Major 10 Targeted Destination Ports:")

    for port, count in results["common_ports"]:
        print("Port", port, "-", count, "events")



# ==========================================
# 4. AUTHENTICATION LOG PARSING
# ==========================================

def parse_authentication_log(filename):

    auth_events = []
    wrongformatted_count = 0

    pattern = (
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
        r'(\S+) '
        r'user=(\S+) '
        r'src=(\S+) '
        r'host=(\S+) '
        r'method=(\S+)$'
    )

    with open(filename, "r") as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            match = re.match(pattern, line)

            if match:

                event = {
                    "timestamp": match.group(1),
                    "event": match.group(2),
                    "username": match.group(3),
                    "src_ip_addr": match.group(4),
                    "hostname": match.group(5),
                    "method": match.group(6)
                }

                auth_events.append(event)

            else:
                wrongformatted_count += 1
                print("Wrongly formatted authentication line:", line_number)

    return auth_events, wrongformatted_count


# ==========================================
# 5. AUTHENTICATION LOG ANALYSIS
# ==========================================

def analyse_authentication_logs(auth_events):

    success_count = 0
    failed_count = 0
    account_lock_count = 0
    other_events_count = 0
    failed_source_ips = []
    failed_usernames = []

    for event in auth_events:

        event_type = event["event"].upper()

        if event_type == "LOGIN_SUCCESS":
            success_count += 1

        elif event_type == "LOGIN_FAILED":
            failed_count += 1

            failed_source_ips.append(event["src_ip_addr"])
            failed_usernames.append(event["username"])

        elif event_type in ("ACCOUNT_LOCK", "ACCOUNT_LOCKED",
                            "ACCOUNT_LOCKOUT"):
            account_lock_count += 1
        else:
            other_events_count += 1

    frequent_failed_ips = Counter(
        failed_source_ips
    ).most_common(10)

    frequent_failed_users = Counter(
        failed_usernames
    ).most_common(10)

    return {
        "total_events": len(auth_events),
        "successful_logins": success_count,
        "failed_logins": failed_count,
        "account_lockouts": account_lock_count,
        "other_events" : other_events_count,
        "frequently_failed_ips": frequent_failed_ips,
        "frequently_failed_users": frequent_failed_users
    }


# ==========================================
# 6. DISPLAY AUTHENTICATION RESULTS
# ==========================================

def display_authentication_results(results, wrongformatted_count):

    print("\n========================================")
    print("     AUTHENTICATION INVESTIGATION")
    print("========================================")

    print("Valid authentication events:", results["total_events"])
    print("Wrongly formatted lines:", wrongformatted_count)

    print("Successful logins:", results["successful_logins"])
    print("Failed logins:", results["failed_logins"])
    print("Account lock activities:", results["account_lockouts"])
    print("Other auth activities were:" , results["other_events"])

    print("\nMost Frequent Failed-Login Source IP addresses:")

    for ip, count in results["frequently_failed_ips"]:
        print(ip, "-", count, "failed attempts")

    print("\nMost Frequently Targeted Usernames:")

    for username, count in results["frequently_failed_users"]:
        print(username, "-", count, "failed attempts")





# ==========================================
# 8. LOAD SUSPICIOUS IP ADDRESSES
# ==========================================

def load_suspicious_ips(file_name):

    suspicious_ips = set()

    with open(file_name, "r") as file:

        for line in file:

            ip = line.strip()

            if ip and not ip.startswith("#"):
                suspicious_ips.add(ip)

    return suspicious_ips


# ==========================================
# 9. SUSPICIOUS IP comparison
# ==========================================

def compare_suspicious_ips(
        suspicious_ips, firewall_events, auth_events):

    findings = {}

    for ip in suspicious_ips:

        firewall_source_count = 0
        firewall_destination_count = 0
        auth_source_count = 0

        for event in firewall_events:

            if event["src_ip_addr"] == ip:
                firewall_source_count += 1

            if event["dest_ip_addr"] == ip:
                firewall_destination_count += 1

        for event in auth_events:

            if event["src_ip_addr"] == ip:
                auth_source_count += 1

        if (firewall_source_count > 0 or
                firewall_destination_count > 0 or
                auth_source_count > 0):

            findings[ip] = {
                "firewall_source": firewall_source_count,
                "firewall_destination": firewall_destination_count,
                "authentication_source": auth_source_count
            }

    return findings


# ==========================================
# 10. DISPLAY COMPARISON RESULTS
# ==========================================

def display_comparison_results(findings):

    print("\n========================================")
    print("       SUSPICIOUS IP INVESTIGATION")
    print("========================================")

    if not findings:
        print("No suspicious IP addresses matched the logs.")
        return

    print("Matching suspicious IP addresses:", len(findings))

    for ip, details in findings.items():

        print("\nIP Address:", ip)

        print("Firewall source events:",
              details["firewall_source"])

        print("Firewall destination events:",
              details["firewall_destination"])

        print("Authentication source events:",
              details["authentication_source"])


# =========================================
# REPORT GENERATIONS.
# =========================================


def generate_INVEST_report(firewall_results, auth_results, findings,
                           firewall_malformed, auth_malformed):
    try:
        with open("TUD_SOC_investigation_report.txt", "w") as file:
            file.write("TUD SOC SECURITY INVESTIGATION REPORT\n")
            file.write("=" * 30 + "\n\n")

            # Firewall investigation
            file.write("1. FIREWALL LOG ANALYSIS\n")
            file.write("-" * 30 + "\n")

            for key, value in firewall_results.items():
                file.write(f"{key}: {value}\n")

            file.write(
                f"Wrongly formatted firewall lines: {firewall_malformed}\n\n"
            )

            # Authentication investigation
            file.write("2. AUTHENTICATION LOG ANALYSIS\n")
            file.write("-" * 30 + "\n")

            for key, value in auth_results.items():
                file.write(f"{key}: {value}\n")

            file.write(
                f"Wrongly formatted auth lines: {auth_malformed}\n\n"
            )

            # Suspicious IP investigation
            file.write("3. SUSPICIOUS IP INVESTIGATION\n")
            file.write("-" * 30 + "\n")

            file.write(
                f"Matching suspicious IP addresses: {len(findings)}\n\n"
            )

            for ip, details in findings.items():
                file.write(f"IP Address: {ip}\n")
                file.write(
                    f"Firewall source events: {details['firewall_source']}\n"
                )
                file.write(
                    f"Firewall destination events: {details['firewall_destination']}\n"
                )
                file.write(
                    f"Authentication source events: {details['authentication_source']}\n\n"
                )

            # Security observations
            file.write("4. SECURITY OBSERVATIONS\n")
            file.write("-" * 30 + "\n")

            file.write(
                "1. Wrongly formatted log entries: A total of 6 malformed "
                "firewall log entries were identified during parsing.\n\n"
            )

            file.write(
                "2. Potential brute-force activity: The suspicious IP "
                "address 198.51.100.23 generated 51 authentication "
                "events, including 46 failed login attempts. This "
                "repeated authentication failure pattern may indicate "
                "a possible brute-force attack and requires further "
                "investigation.\n\n"
            )

            file.write(
                "3. Frequently targeted destination ports: Ports "
                "443, 8080 and 80 recorded 104, 100 and 93 events "
                "respectively.\n\n"
            )

            file.write("END OF REPORT\n")

        print(
            "\nInvestigation report saved as "
            "TUD_SOC_investigation_report.txt"
        )

    except OSError as error:
        print(f"Error while creating report: {error}")


 

# ==========================================
# 4. MAIN FUNCTION
# ==========================================

def main():

# firewall investigations

    firewall_events, wrongformat_count = parse_firewall_log(
        "firewall.log"
    )

    results = analyse_firewall_logs(firewall_events)

    display_firewall_results(results, wrongformat_count)


# Authentication investigation
    auth_events, auth_malformed = parse_authentication_log(
        "authentication.log"
    )

    auth_results = analyse_authentication_logs(auth_events)

    display_authentication_results(
        auth_results, auth_malformed
    )

# Suspicious IP investigation

    suspicious_ips = load_suspicious_ips("suspicious_ips.txt")

    findings = compare_suspicious_ips(
        suspicious_ips,
        firewall_events,
        auth_events
    )

    display_comparison_results(findings)


# Generate investigation report
    generate_INVEST_report(
        results,
        auth_results,
        findings,
        wrongformat_count,
        auth_malformed
    )

    


if __name__ == "__main__":
    main()
