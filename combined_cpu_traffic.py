# -*- coding: utf-8 -*-
"""
Created on Thu Mar  2 10:12:10 2023

@author: marc2
"""
import time
from multiprocessing import Process, freeze_support
from platform import platform as pf

from netifaces import interfaces
from scapy.all import *
import pandas as pd
import analyse_cpu as ac
import xgboost as xgb

WINDOW = 4


def traffic_analyse():
    """
    Cette fonction d'Albert permet d'analyser le traffic réseau.
    A tester sur windows
    """
    if pf()[:7] == "Windows":
        inter = [el[1:-1] for el in interfaces()]
    else:
        # On garde que les ports wifi et ethernet
        inter= list(filter(lambda s: ('en' or 'eth') in s, interfaces()))


    # Capturer 200 packets
    pkt = sniff(iface=inter, count=200)

    data = []
    for packet in pkt:
        if IP in packet : # garder seulement packet IP
            data.append([packet.sniffed_on ,packet.time,
                          packet[IP].src, packet[IP].dst, len(packet)])

    sniffed_df = pd.DataFrame(data, columns=['interface','Time', 'Source', 'Destination', 'Length'])

    #Filtrer sur l'interface la plus utilisée
    most_used_interface = sniffed_df.groupby(by = 'interface').sum('Length').nlargest(
        1, 'Length').iloc[0].name
    sniffed_df = sniffed_df.where(sniffed_df["interface"] == most_used_interface).drop(
        "interface", axis = 1)
    sniffed_df.pipe(prepare_sniffed_df)
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

def write_traffic(name):
    traffic_analyse().to_csv(f'{name}.csv', index = False)

def write_cpu(name, timeout, time_sleep):
    data = pd.DataFrame(cpu_analyse(timeout, time_sleep))
    data.to_csv(f'{name}.csv')

def prepare_sniffed_df(sniffed_df : pd.DataFrame):
    """Applique le Feature Engineering choisi
    Args:
        sniffed_df (pd.DataFrame): Dataframe provenant de scapy

    Returns:
        cleaned_sniffed_df: Feature Engineering appliqué
    """
    sniffed_df['delta'] = sniffed_df.Time.diff()

    # Delta Rolling average + Standard Deviation
    sniffed_df['ra_delta'] = sniffed_df.delta.rolling(window=WINDOW).mean()
    sniffed_df['rstd_delta'] = sniffed_df.delta.rolling(window=WINDOW).std()

    # Delta Rolling average + Standard Deviation
    sniffed_df['ra_lenght'] = sniffed_df.Length.rolling(window=WINDOW).mean()
    sniffed_df['rstd_lenght'] = sniffed_df.Length.rolling(window=WINDOW).std()
    # remove useless columns
    sniffed_df.drop(['Time', 'Source', 'Destination'], axis = 1, inplace = True)
    cleaned_sniffed_df = sniffed_df.dropna(inplace = True)
    return cleaned_sniffed_df

def run(name : str, time_sleep = 1, timeout = 20):
    """
    Cette fonction lance l'analyse de paquet et l'analyse du cpu en parallèle.
    ne fonctionne pas avec windows
    """
    traffic = Process(target = write_traffic, args = [name + "_" + "Traffic"])
    traffic.start()

    enregistrement_cpu = Process(target = write_cpu, args = [name + "_" + "Cpu",
                                                      timeout, time_sleep])
    enregistrement_cpu.start()

    traffic.join()
    enregistrement_cpu.join()

    print("finished sniffing data")
    df = pd.read_csv('test_traffic.csv')

    bst = xgb.Booster({'nthread': 4})  # init model
    bst.load_model('model.bst')  # load data

    



if __name__ == '__main__':
    freeze_support()
    run('test')