from DNS.DNSPoisoning import DNSPoisoning

spoof_ip = ''
target_dom = ''
# spoof_port = 53

dns_tool = DNSPoisoning(spoof_ip, target_dom)

# TODO get packet


dns_tool.poison_dns(pkt=packet)
