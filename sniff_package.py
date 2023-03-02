import netifaces
from scapy.all import *
import pandas as pd

# On garde que les ports wifi et ethernet
interfaces = list(filter(lambda s: ('en' or 'eth') in s, netifaces.interfaces()))

# Capturer 100 packets
pkt = sniff(iface=interfaces, count=100)

data = []
for packet in pkt:
    data.append([packet.sniffed_on ,packet.time, packet.src, packet.dst, len(packet)])

sniffed_df = pd.DataFrame(data, columns=['interface','Time', 'Source', 'Destination', 'Length'])

sniffed_df.to_csv('sniffed_df.csv', index = False)