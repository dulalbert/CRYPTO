# -*- coding: utf-8 -*-
"""
Created on Thu Mar  2 10:12:10 2023

@author: marc2
"""

import netifaces
from scapy.all import *
import pandas as pd
import analyse_cpu as ac
from multiprocessing import Process
import time

def traffic_analyse(os, timeout):
    """
    Cette fonction d'Albert permet d'analyser le traffic réseau.
    
    Elle ne fonctionne pas avec Windows.
    Elle renvoie un pd.DataFrame
    
    (pour windows on devra utiliser get_windows_if_list())
    
    os : l'os utiliser ("windows" ou autre)
    """
    if os == "windows":
        interfaces = netifaces.interfaces()
        interfaces = [el[1:-1] for el in interfaces]
    else:
        # On garde que les ports wifi et ethernet
        interfaces = list(filter(lambda s: ('en' or 'eth') in s, netifaces.interfaces()))

    # Capturer les packets pendant 20 secondes
    pkt = sniff(iface=interfaces, timeout=timeout)

    data = []
    for packet in pkt:
        data.append([packet.sniffed_on ,packet.time, packet.src, packet.dst, len(packet)])

    sniffed_df = pd.DataFrame(data, columns=['interface','time', 'src', 'dst', 'length'])

    return sniffed_df

def cpu_analyse(timeout, time_sleep):
    """
    Cette fonction regarde le cpu tout les time_sleep pendant timeut 
    et renvoie ses observation.
    """
    #écriture periodique.
    time_finish = time.time() + timeout
    
    data_tot = [["ptime_user","ptime_sys",
                "ptime_none","ptime_other",
                "pusing","freq_inst",
                "pfreq","pram"]]
    
    while time.time() < time_finish:
        data = ac.generalite_cpu() #collecte de donnees
        data_tot.append(data)
        time.sleep(time_sleep) # attente pour éviter de trop alourdir les données.
    
    return data_tot

def write_data(name, data):
    """
    Cette fonction ecrit un csv contenant les données.
    """
    file = open(name + ".csv", "w")
    for lign in data:
        for el in lign:
            file.write(str(el) + ",")
        file.write("\n")
    file.close()
    
def write_traffic(name, timeout, os):
    data = traffic_analyse(timeout, os)
    write_data(name, data)

def write_cpu(name, timeout, time_sleep):
    data = cpu_analyse(timeout, time_sleep)
    write_data(name, data)
    
def run(name, os = "windows", time_sleep = 1, timeout = 20):
    """
    Cette fonction lance l'analyse de paquet et l'analyse du cpu en parallèle.
    ne fonctionne pas avec windows
    """
    traffic = Process(target = write_traffic, args = [name + "Traffic", os,
                                                      timeout])
    traffic.start()
    
    cpu_analyse = Process(target = write_cpu, args = [name + "Cpu", 
                                                      timeout, time_sleep])
    cpu_analyse.start()
    
    traffic.join()
    cpu_analyse.join()
    
    print("finished")




