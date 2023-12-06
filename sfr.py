import os
import signal
import threading
from scapy.all import ARP, Ether, IP, TCP, UDP, send, sniff, sr1
import time

class WifiBypass:
    def __init__(self, interface='wlan0', local_ip='192.168.1.100', remote_host='www.sfr.fr', remote_port=80, target_mac='00:00:00:00:00:00'):
        self.interface = interface
        self.local_ip = local_ip
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.target_mac = target_mac

    def set_ip_forward(self):
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    def process_packet(self, packet):
        if packet.haslayer(Ether):
            if packet[Ether].dst == self.target_mac:
                packet[Ether].dst = 'ff:ff:ff:ff:ff:ff'

                if packet.haslayer(IP):
                    packet[IP].dst = self.remote_host
                    packet[IP].ttl -= 1

                    if packet.haslayer(TCP):
                        packet[TCP].dport = self.remote_port

                    elif packet.haslayer(UDP):
                        packet[UDP].dport = self.remote_port

                send(packet, iface=self.interface, verbose=0)
            elif packet[Ether].dst == self.target_mac:
                packet[Ether].dst = self.target_mac

                if packet.haslayer(IP):
                    packet[IP].dst = self.local_ip
                    packet[IP].ttl -= 1

                    if packet.haslayer(TCP):
                        packet[TCP].dport = packet[TCP].sport

                    elif packet.haslayer(UDP):
                        packet[UDP].dport = packet[UDP].sport

                send(packet, iface=self.interface, verbose=0)

    def send_keep_alive(self):
        ip = IP(dst=self.remote_host)
        tcp = TCP(dport=self.remote_port, flags="S")
        send(ip / tcp, iface=self.interface, verbose=0)
        response = sr1(ip / tcp, timeout=5, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            tcp_ack = TCP(dport=self.remote_port, flags="A")
            send(ip / tcp_ack, iface=self.interface, verbose=0)

    def start(self):
        self.set_ip_forward()
        threading.Thread(target=self.sniff_and_send).start()

        while True:
            self.send_keep_alive()
            time.sleep(60) # sleep for 1 minute

    def sniff_and_send(self):
        sniff(iface=self.interface, prn=self.process_packet)

    def signal_handler(self, signum, frame):
        print('Vous avez arrêté le programme')
        exit(0)

if __name__ == '__main__':
    bypass = WifiBypass(target_mac='00:00:00:00:00:00')
    signal.signal(signal.SIGINT, bypass.signal_handler)
    bypass.start()
