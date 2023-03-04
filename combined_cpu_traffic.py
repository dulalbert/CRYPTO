# -*- coding: utf-8 -*-
"""
Created on Thu Mar  2 10:12:10 2023

@author: marc2
"""
import time
from multiprocessing import Process
from platform import platform

from netifaces import interfaces
from scapy.all import *
import pandas as pd
import analyse_cpu as ac


def traffic_analyse():
    """
    Cette fonction d'Albert permet d'analyser le traffic réseau.
    A tester sur windows
    """
    if platform()[:7] == "Windows":
        inter = [el[1:-1] for el in interfaces()]
    else:
        # On garde que les ports wifi et ethernet
        inter= list(filter(lambda s: ('en' or 'eth') in s, interfaces()))


    # Capturer 200 packets
    pkt = sniff(iface=inter, count=200)

    data = []
    for packet in pkt:
        if IP in packet : # garder seulement packet IP
            data.append([packet.sniffed_on ,packet.time, packet[IP].src, packet[IP].dst, len(packet)])

    sniffed_df = pd.DataFrame(data, columns=['interface','Time', 'Source', 'Destination', 'Length'])

    #Filtrer sur l'interface la plus utilisée
    most_used_interface = sniffed_df.groupby(by = 'interface').sum().nlargest(1, 'Length').iloc[0].name
    sniffed_df.where(sniffed_df["interface"] == most_used_interface).drop(
        "interface", axis = 1, inplace = True)

    return sniffed_df

def cpu_analyse(timeout : int, time_sleep : int):
    """
    Cette fonction regarde le cpu tout les time_sleep pendant timeout
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

def write_traffic(name):
    data = traffic_analyse()
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