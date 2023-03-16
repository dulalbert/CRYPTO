"""
Le script à lancer pour sniffer le réseau et formater le DataFrame
"""
#for Windows install npcap
import time
from platform import platform as pf
from netifaces import interfaces
from scapy.all import *
import pandas as pd

WINDOW = 4

# On garde que les ports wifi et ethernet séparé sur windows et mac
if pf()[:7] == "Windows":
    inter = [el[1:-1] for el in interfaces()]
else:
    inter= list(filter(lambda s: ('en' or 'eth') in s, interfaces()))

interfaces = list(filter(lambda s: ('en' or 'eth') in s, interfaces()))

# Capturer 200 packets, pas sur une durée car timeout ne fonctionne pas sur macos
pkt = sniff(iface=interfaces, count=200)

data = []
for packet in pkt:
    if IP in packet : # garder seulement packet IP
        data.append([packet.sniffed_on ,packet.time, packet[IP].src, packet[IP].dst, len(packet)])

sniffed_df = pd.DataFrame(data, columns=['interface','Time', 'Source', 'Destination', 'Length'])

#Filtrer sur l'interface la plus utilisée
most_used_interface = sniffed_df.groupby(by = 'interface').sum().nlargest(1, 'Length').iloc[0].name
sniffed_df.where(sniffed_df["interface"] == most_used_interface).drop(
    "interface", axis = 1, inplace = True)

# Add a column outbound
ip = get_if_addr(most_used_interface)
sniffed_df['outbound'] = sniffed_df['Source'].apply(lambda x : x == ip)

sniffed_df['delta'] = sniffed_df.Time.diff()

# Delta Rolling average + Standard Deviation
sniffed_df['ra_delta'] = sniffed_df.delta.rolling(window=WINDOW).mean()
sniffed_df['rstd_delta'] = sniffed_df.delta.rolling(window=WINDOW).std()

# Delta Rolling average + Standard Deviation
sniffed_df['ra_lenght'] = sniffed_df.Length.rolling(window=WINDOW).mean()
sniffed_df['rstd_lenght'] = sniffed_df.Length.rolling(window=WINDOW).std()
# remove useless columns
sniffed_df.drop(['Time', 'Source', 'Destination'], axis = 1, inplace = True)
sniffed_df.dropna(inplace = True)

sniffed_df.to_csv(f'network_sniff/scappy-{time.strftime("%Y%m%d-%H%M%S")}', index = False)
