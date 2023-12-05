import os
from scapy.all import IP, TCP, UDP, send, sniff

class WifiBypass:
    def __init__(self, interface='wlan0', local_ip='192.168.1.100', remote_host='www.sfr.fr', remote_port=80):
        self.interface = interface
        self.local_ip = local_ip
        self.remote_host = remote_host
        self.remote_port = remote_port

    def set_ip_forward(self):
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    def process_packet(self, packet):
        if IP in packet:
            if packet[IP].dst == self.local_ip:
                packet[IP].dst = self.remote_host
                packet[IP].ttl -= 1

                if TCP in packet:
                    packet[TCP].dport = self.remote_port

                elif UDP in packet:
                    packet[UDP].dport = self.remote_port

                send(packet, iface=self.interface, verbose=0)
            elif packet[IP].dst == self.remote_host:
                packet[IP].dst = self.local_ip
                packet[IP].ttl -= 1

                if TCP in packet:
                    packet[TCP].dport = packet[TCP].sport

                elif UDP in packet:
                    packet[UDP].dport = packet[UDP].sport

                send(packet, iface=self.interface, verbose=0)
            else:
               
                pass

    def start(self):
        self.set_ip_forward()
        sniff(iface=self.interface, prn=self.process_packet)

bypass = WifiBypass()
bypass.start()
