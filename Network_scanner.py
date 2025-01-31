
import scapy.all as scapy
import argparse
import sys
import threading
import requests
import json
from tabulate import tabulate

def banner():
    print("""
     ███╗   ██╗███████╗██╗    ██╗ ██████╗ ██╗  ██╗
     ████╗  ██║██╔════╝██║    ██║██╔═══██╗██║ ██╔╝
     ██╔██╗ ██║█████╗  ██║ █╗ ██║██║   ██║█████╔╝ 
     ██║╚██╗██║██╔══╝  ██║███╗██║██║   ██║██╔═██╗ 
     ██║ ╚████║███████╗╚███╔███╔╝╚██████╔╝██║  ██╗
     ╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝
                ADVANCED NETWORK SCANNER
    """)

def get_arguments():
    parser = argparse.ArgumentParser \
        (description="An advanced network scanner with OS detection, vendor lookup, and port scanning.")
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP / IP range (e.g., 192.168.1.1/24)")
    parser.add_argument("-o", "--output", dest="output", help="Save results to a JSON file")
    args = parser.parse_args()
    return args

def get_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}")
        return response.text if response.status_code == 200 else "Unknown"
    except:
        return "Unknown"

def scan(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        clients = []
        threads = []

        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            client = {"IP Address": ip, "MAC Address": mac, "Vendor": "Fetching..."}

            thread = threading.Thread(target=lambda c: c.update({"Vendor": get_vendor(mac)}), args=(client,))
            threads.append(thread)
            clients.append(client)
            thread.start()

        for thread in threads:
            thread.join()

        return clients
    except KeyboardInterrupt:
        print("\n[!] User interrupted the scan. Exiting...")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {str(e)}")
        sys.exit(1)

def print_result(results):
    if results:
        print("\nScan Results:")
        print(tabulate(results, headers="keys", tablefmt="grid"))
    else:
        print("\n[!] No devices found. Ensure you're scanning the correct network range.")

def save_results(results, filename):
    if filename:
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        print(f"\n[+] Results saved to {filename}")

if __name__ == "__main__":
    banner()
    options = get_arguments()
    scan_result = scan(options.target)
    print_result(scan_result)
    save_results(scan_result, options.output)
