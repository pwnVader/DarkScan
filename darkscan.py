#!/usr/bin/env python3

import subprocess
import datetime
import signal
import threading
from termcolor import cprint

# Global list for detected devices
detected_devices = []
lock = threading.Lock()

def run_command(command):
    """Executes a shell command and returns the output."""
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        return output.decode().strip() if process.returncode == 0 else None
    except Exception as e:
        cprint(f"⚠️ Error running command: {str(e)}", "red")
        return None

def scan_network(network_range):
    """Scans the network and returns a list of active devices."""
    devices = []
    cprint(f"🔍 Scanning network {network_range}...", "yellow")

    result = run_command(f"sudo nmap -sn -T4 --min-rate=1000 {network_range}")
    if result:
        for line in result.splitlines():
            if "Nmap scan report for" in line:
                ip = line.split()[-1]
                devices.append({"IP": ip})

    return devices

def get_device_details(ip, deep_scan):
    """Retrieves additional device details like MAC and OS."""
    details = {"IP": ip}

    # Get MAC Address using ARP first
    mac_result = run_command(f"arp -n {ip} | grep {ip} | awk '{{print $3}}'")
    if mac_result and mac_result != "(incomplete)":
        details["MAC Address"] = mac_result.strip()

    # If deep scan is enabled, use -O; otherwise, use -F for a faster scan
    scan_option = "-O -Pn --max-retries=1" if deep_scan else "-F -Pn --max-retries=1"
    cprint(f"⏳ Analyzing {ip}... (This may take a few seconds)", "yellow")

    result = run_command(f"sudo nmap {scan_option} {ip}")

    if result:
        for line in result.splitlines():
            if "MAC Address" in line and "MAC Address" not in details:
                details["MAC Address"] = line.split("MAC Address: ")[1].split()[0]
            elif "Device type" in line:
                details["Device Type"] = line.split(": ")[1].strip()
            elif "Running" in line:
                details["OS Info"] = line.split(": ")[1].strip()
            elif "Aggressive OS guesses" in line:
                details["Possible OS"] = line.split(": ")[1].strip()

    with lock:
        detected_devices.append(details)

def generate_report():
    """Generates a report with detected devices in a simple format."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"network_report_{timestamp}.txt"

    with open(report_filename, "w") as file:
        file.write("📡 Network Device Report\n")
        file.write("=" * 50 + "\n")

        for device in detected_devices:
            file.write(f"- IP: {device['IP']}\n")
            if "MAC Address" in device:
                file.write(f"  MAC Address: {device['MAC Address']}\n")
            if "Device Type" in device:
                file.write(f"  Device Type: {device['Device Type']}\n")
            if "OS Info" in device:
                file.write(f"  OS Info: {device['OS Info']}\n")
            if "Possible OS" in device:
                file.write(f"  Possible OS: {device['Possible OS']}\n")
            file.write("=" * 50 + "\n")

    cprint(f"\n✅ Report saved as {report_filename}", "yellow")

def handle_interrupt(sig, frame):
    """Handles CTRL+C interruption to save progress before exiting."""
    if detected_devices:
        cprint("\n⚠️ Scan interrupted (CTRL+C). Saving progress...", "red")
        generate_report()
        cprint(f"📄 Partial report saved.", "yellow")
    cprint("\n🚪 Exiting DARKSCAN...", "red")
    exit(0)

def main():
    """Main function."""
    
    signal.signal(signal.SIGINT, handle_interrupt)

    cprint("\n██████╗  █████╗ ██████╗ ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗", 'green', attrs=['bold'])
    cprint("██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║", 'green', attrs=['bold'])
    cprint("██║  ██║███████║██████╔╝█████╔╝ ███████╗██║     ███████║██╔██╗ ██║", 'green', attrs=['bold'])
    cprint("██║  ██║██╔══██║██╔══██╗██╔═██╗ ╚════██║██║     ██╔══██║██║╚██╗██║", 'green', attrs=['bold'])
    cprint("██████╔╝██║  ██║██║  ██║██║  ██╗███████║╚██████╗██║  ██║██║ ╚████║", 'green', attrs=['bold'])
    cprint("╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝", 'green', attrs=['bold'])

    cprint("Identify active devices and generate a network report.", "green")
    cprint("By pwnVader (Jesus Romero)\n", "green", attrs=['bold'])

    network_range = input("📡 Enter IP or network range (e.g., 192.168.1.0/24): ").strip()

    while True:
        deep_scan = input("🔍 Do you want advanced OS detection? (y/n): ").strip().lower()
        if deep_scan in ["y", "n"]:
            break
        cprint("⚠️ Invalid option. Enter 'y' for yes or 'n' for no.", "red")

    active_devices = scan_network(network_range)

    if active_devices:
        threads = []
        for device in active_devices:
            ip = device["IP"]
            cprint(f"- IP: {ip}", "green")
            
            thread = threading.Thread(target=get_device_details, args=(ip, deep_scan == "y"))
            threads.append(thread)
            thread.start()

        for t in threads:
            t.join()

        generate_report()
    else:
        cprint("🕶️ No devices found... Try another scan method.", "red")

if __name__ == "__main__":
    main()
