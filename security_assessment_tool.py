import socket
import os
import re
import subprocess
import datetime
import sys, threading, queue, time, argparse, requests
from colorama import init, Fore
import vulners
import win32evtlog
import datetime


init()
red = Fore.RED
green = Fore.GREEN
yellow = Fore.YELLOW
cyan = Fore.CYAN
reset = Fore.RESET

def is_valid_ip(address):
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    return bool(ip_pattern.match(address))

def parse_arguments():
    parser = argparse.ArgumentParser(description="This is a security assessment tool developed by dedlinux")
    parser.add_argument('-t', '--target', required=True, help="Enter the target to scan")
    parser.add_argument('-s', '--start_port', type=int, default='1', help="Enter the starting port to scan the port range")
    parser.add_argument('-e', '--end_port', type=int, default=65535, help="Enter the ending port to scan until the given end port")
    parser.add_argument('-f', '--thread_no', type=int, default=5, help="Enter how many threads you want to scan for")
    parser.add_argument('-o', '--output', required=True, help="Enter the filename to save the security report")
    return parser.parse_args()


argms = parse_arguments()
target = argms.target
start_port = int(argms.start_port)
end_port = int(argms.end_port)
thread_no = argms.thread_no

# Handle both IP address and domain name
target_ip = target if is_valid_ip(target) else socket.gethostbyname(target)

# Check for required arguments
if not argms.start_port or not argms.end_port or not argms.thread_no:
    parser.error("Missing required arguments. Please provide start_port, end_port, and thread_no.")

# queue for ports
q = queue.Queue()
for j in range(start_port, end_port + 1):
    q.put(j)
# end queue block

# banner grabbing
def grab_banner(port, s, target_ip):
    try:
        s.settimeout(1)
        s.connect((target_ip, port))
        banner = s.recv(1024).decode("utf-8").strip()
        return banner
    except Exception as e:
        banner = socket.getservbyport(port)
        return banner

results_ports = []
banners = []
# main scan block
def scan(t_no):
    global results_ports
    global banners
    # taking results to print results
    while not q.empty():
        port = q.get()
        try:
            s = socket.socket()
            s.settimeout(2)
            conn = s.connect_ex((target_ip, port))
            # if exception raises while connecting used connect_ex to pass
            if not conn:
                banner = grab_banner(port, s, target_ip)
                results_ports.append((port, "Open", banner))
                banners.append(banner)
        except Exception as e:
            print(e)
            pass
        s.close()
        q.task_done()

start_time = time.time()

# start threads
for i in range(thread_no):
    t = threading.Thread(target=scan, args=(i,))
    t.start()

# wait for all threads to finish
q.join()

# sort results by port number
results_ports.sort()

# print results in a table-like format
print("Port\tState\tService")
for port, state, service in results_ports:
    print(f"{green}{port}\t{state}\t{service}{reset}")

end_time = time.time()
print("Time taken for Port scanning: {}seconds".format(round(end_time - start_time, 3)))



def vulnerability_scan(banners):
    all_vulnerabilities = []
    vulners_api = vulners.VulnersApi(api_key="QRDTHXAEX2ID16HG561UEFPDDTDJC9GPMKIATCMQ6DWNN3L8V993XUZIC42927I4")

    for service in banners:
        print(f"\n\nVulnerabilities found for service: {service}\n\n")
        vulnerabilities = []

        try:
            # Search for vulnerabilities using the Vulners API
            results = vulners_api.find_exploit_all(service)

            # Check if vulnerabilities were found
            if results:
                for result in results:
                    vulnerability = {
                        "CVE ID": result.get('id'),
                        "Title": result.get('title'),
                        "Description": result.get('description')
                    }
                    vulnerabilities.append(vulnerability)

                    # Print vulnerability details
                    print(f"{cyan}[+] CVE ID: {result.get('id')}{reset}")
                    print(f"{yellow}- Title: {result.get('title')} {reset}")
                    print(f"{yellow}- Description: {result.get('description')}{reset}")
            else:
                print("No vulnerabilities found for this service.")
        except Exception as e:
            print(f"Error searching for vulnerabilities for service {service}:", e)

        # Append vulnerabilities for this service to the list
        all_vulnerabilities.append({
            "Service": service,
            "Vulnerabilities": vulnerabilities
        })

    return all_vulnerabilities

# Perform vulnerability scanning
vulnerabilities = vulnerability_scan(banners)
# print("Vulnerability scanning complete.")


def log_analysis():
    # Open the Security event log
    hand = win32evtlog.OpenEventLog(None, "Security")

    # go to the end of the log
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    events = win32evtlog.ReadEventLog(hand, flags, 0)

    # dictionary to store failed login attempts
    failed_attempts = {}

    # Iterate through the events
    while events:
        for event in events:
            if event.EventID == 4624:  # Failed logon event ID
                ip_address = event.StringInserts[18]

                if ip_address not in failed_attempts:
                    failed_attempts[ip_address] = 1
                else:
                    failed_attempts[ip_address] += 1

        # Read the next group of events
        events = win32evtlog.ReadEventLog(hand, flags, 0)

    # Close event log
    win32evtlog.CloseEventLog(hand)

    results_logs = ''
    for ip, attempts in failed_attempts.items():
        if attempts > 1:
            print(f"{cyan}Warning: Suspicios Multiple failed login attempts detected from IP address {ip} {reset}")
            results_logs +=f"{cyan}Warning: Suspicios Multiple failed login attempts detected from IP address {ip}{reset}"
    return results_logs



def write_report(open_ports, vulnerabilities, suspicious_activities, filename):
    # Generate a report with all the findings
    with open(filename, "w", encoding="utf-8") as report_file:
        report_file.write("Security Assessment Report\n")
        report_file.write("==========================\n\n")

        # Write open ports information
        report_file.write("Port\tState\tService\n")
        for port, state, service in open_ports:
            report_file.write(f"{port}\t{state}\t{service}\n")

        # Write vulnerabilities information
        report_file.write("\nVulnerabilities:\n")
        if vulnerabilities:
            for service_info in vulnerabilities:
                service = service_info["Service"]
                vulnerabilities_list = service_info["Vulnerabilities"]
                report_file.write(f"Vulnerabilities found for service: {service}\n")
                if vulnerabilities_list:
                    for vulnerability in vulnerabilities_list:
                        report_file.write(f"  - CVE ID: {vulnerability['CVE ID']}\n")
                        report_file.write(f"    Title: {vulnerability['Title']}\n")
                        report_file.write(f"    Description: {vulnerability['Description']}\n")
                else:
                    report_file.write("  No vulnerabilities found for this service\n")
                report_file.write("\n")
        else:
            report_file.write("No vulnerabilities found\n\n")

        # Write password analysis information
        report_file.write("Password Strength Analysis is a realtime process you need to verify the strength of your password in runtime\n\n\n")

        # Write suspicious activities information
        report_file.write("Suspicious Activities:\n")
        if suspicious_activities:
            for activity in suspicious_activities.split('\n'):
                report_file.write(activity + '\n')
        else:
            report_file.write("No suspicious activities found\n\n")
    print(f"Report generated: {filename}")


class PasswordStrengthChecker:
    def __init__(self, password):
        self.password = password

    def check_password_strength(self):
        length_criteria = len(self.password) >= 8
        special_char_criteria = any(char in '!@#$%^&*()-_+=~`[]{}|:;"\'<>?,./' for char in self.password)
        number_criteria = any(char.isdigit() for char in self.password)
        lowercase_criteria = any(char.islower() for char in self.password)
        uppercase_criteria = any(char.isupper() for char in self.password)

        if length_criteria and special_char_criteria and number_criteria and lowercase_criteria and uppercase_criteria:
            return f"{cyan}Strong Password{reset}"
        elif length_criteria and (number_criteria or uppercase_criteria):
            return f"{yellow}Moderate Password{reset}"
        else:
            return f"{red}Weak Password{reset}"

while True:
    password = input("Enter your password to check the strength of your password or Type 'end' to skip: ")
    if password.lower() == 'end':
        break
    else:
        evaluator = PasswordStrengthChecker(password)
        strength = evaluator.check_password_strength()
        print(f"Password: {password}, Strength: {strength}")

# Perform log analysis
suspicious_activities = log_analysis()
# print("[+]Log analysis complete.")

# Generate report
write_report(results_ports, vulnerabilities, suspicious_activities, argms.output)
