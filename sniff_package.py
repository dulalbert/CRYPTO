import netifaces
from scapy.all import *
import pandas as pd

# On garde que les ports wifi et ethernet
interfaces = list(filter(lambda s: ('en' or 'eth') in s, netifaces.interfaces()))

# Capturer les packets pendant 20 secondes
pkt = sniff(iface=interfaces, timeout=20)

data = []
for packet in pkt:
    data.append([packet.sniffed_on ,packet.time, packet.src, packet.dst, len(packet)])

sniffed_df = pd.DataFrame(data, columns=['interface','time', 'src', 'dst', 'length'])

print (sniffed_df)