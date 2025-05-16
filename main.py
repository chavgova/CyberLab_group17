import argparse
import os
import sys

from ARP.main import main as run_arp
from DNS.main import main as run_dns

def root_main():
    parser = argparse.ArgumentParser(description="MITM Toolkit")
    parser.add_argument("--tool", choices=["arp", "dns"], required=True, help="Which tool to run")
    parser.add_argument("--args", nargs=argparse.REMAINDER, help="Arguments for the selected tool")
    args = parser.parse_args()

    sys.argv = [sys.argv[0]] + (args.args or [])

    if args.tool == "arp":
        run_arp()
    elif args.tool == "dns":
        run_dns()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this as root (sudo).")
        sys.exit(1)
    root_main()
