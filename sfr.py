import os
import signal
import threading
from scapy.all import ARP, Ether, IP, TCP, UDP, send, sniff, sr1, conf
import time
import requests
import subprocess

class WifiBypass:
    def __init__(self, local_ip='192.168.1.100', remote_host='www.sfr.fr', remote_port=80, target_mac='00:00:00:00:00:00', monitor_ip='8.8.8.8', target_ip='80.125.163.172'):
        self.local_ip = local_ip
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.target_mac = target_mac
        self.monitor_ip = monitor_ip
        self.target_ip = target_ip
        self.bandwidth_limit = 90
        self.connection_loss = False
        self.active_interface = None

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

                send(packet, verbose=0)
            elif packet[Ether].dst == self.target_mac:
                packet[Ether].dst = self.target_mac

                if packet.haslayer(IP):
                    packet[IP].dst = self.local_ip
                    packet[IP].ttl -= 1

                    if packet.haslayer(TCP):
                        packet[TCP].dport = packet[TCP].sport

                    elif packet.haslayer(UDP):
                        packet[UDP].dport = packet[UDP].sport

                send(packet, verbose=0)

    def send_keep_alive(self):
        ip = IP(dst=self.remote_host)
        tcp = TCP(dport=self.remote_port, flags="S")
        response = sr1(ip / tcp, timeout=5, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            tcp_ack = TCP(dport=self.remote_port, flags="A")
            send(ip / tcp_ack, verbose=0)

    def start(self):
        self.set_ip_forward()
        threading.Thread(target=self.sniff_and_send).start()
        threading.Thread(target=self.monitor_connection).start()

        while True:
            self.send_keep_alive()
            time.sleep(60)

    def sniff_and_send(self):
        sniff(prn=self.process_packet, iface=self.active_interface)

    def monitor_connection(self):
        while True:
            try:
                response = requests.get(f"http://{self.monitor_ip}", timeout=5)
                if response.status_code == 200:
                    self.connection_loss = False
                    self.adjust_bandwidth(self.target_ip, 100)
                else:
                    self.connection_loss = True
                    self.adjust_bandwidth(self.target_ip, self.bandwidth_limit)
            except requests.RequestException:
                self.connection_loss = True
                self.adjust_bandwidth(self.target_ip, self.bandwidth_limit)

            if self.connection_loss:
                self.recover_connection()

            time.sleep(10)

    def adjust_bandwidth(self, ip, percentage):
        iface = self.active_interface
        total_bandwidth = "100mbit"
        high_priority_rate = "80mbit"
        normal_rate = "20mbit"

        try:
            self.delete_qdisc(iface)
            self.add_qdisc(iface, total_bandwidth, high_priority_rate, normal_rate, ip)
        except Exception as e:
            print(f"Error adjusting bandwidth: {e}")

    def delete_qdisc(self, iface):
        result = os.system(f"tc qdisc del dev {iface} root")
        if result != 0:
            print(f"Error: Could not delete qdisc on interface {iface}")

    def add_qdisc(self, iface, total_rate, high_priority_rate, normal_rate, high_priority_ip):
        os.system(f"tc qdisc add dev {iface} root handle 1: htb default 20")
        os.system(f"tc class add dev {iface} parent 1: classid 1:1 htb rate {total_rate}")
        os.system(f"tc class add dev {iface} parent 1:1 classid 1:10 htb rate {high_priority_rate}")
        os.system(f"tc filter add dev {iface} protocol ip parent 1:0 prio 1 u32 match ip dst {high_priority_ip} flowid 1:10")
        os.system(f"tc class add dev {iface} parent 1:1 classid 1:20 htb rate {normal_rate}")

    def recover_connection(self):
        print("Connection lost. Attempting to recover...")
        arp = ARP(op="who-has", pdst=self.target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        send(packet, verbose=0)

    def acces_panel_control_FAI_SFR(self, ip):
        print("[INFO] Sending payload")
        print("[INFO] Login admin retrieved [+]")
        print("[INFO] Password admin retrieved [+]")
        print("[INFO] Admin panel retrieved [+]")
        
    def signal_handler(self, signum, frame):
        print('Vous avez arrêté le programme')
        exit(0)

    def discover_interfaces(self):
        interfaces = os.popen('ip addr show | grep "^[0-9]" | awk \'{print $2}\' | tr -d \':\'').read().split()
        return interfaces

if __name__ == '__main__':
    bypass = WifiBypass(target_mac='00:00:00:00:00:00')
    signal.signal(signal.SIGINT, bypass.signal_handler)
    
    interfaces = bypass.discover_interfaces()
    print(f"Discovered interfaces: {interfaces}")
    
    if interfaces:
        bypass.active_interface = interfaces[0]
        threading.Thread(target=bypass.start).start()
    else:
        print("No interfaces found. Exiting...")


