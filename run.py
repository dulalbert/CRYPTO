"""
Fichier à lancer pour l'analyse
"""
import time
from multiprocessing import Process, freeze_support
from platform import platform as pf
import pkg_resources

from netifaces import interfaces
from scapy.all import *
import pandas as pd
import xgboost as xgb
import analyse_cpu as ac

try:
    from win10toast import ToastNotifier
except ImportError:
    # Si win10toast pas importé on ignore
    pass

pkg_resources.require('xgboost == 1.7.3')

WINDOW = 4
COUNT_SNIFF = 200

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

def traffic_analyse(name : str):
    """
    Sniff packet réseau et met dans le bon format pour le XGBoost
    """
    if pf()[:7] == "Windows":
        inter = [el[1:-1] for el in interfaces()]
        pkt = sniff(count= COUNT_SNIFF)
    else:
        # On garde que les ports wifi et ethernet
        inter= list(filter(lambda s: ('en' or 'eth') in s, interfaces()))
        # Capturer 200 packets
        pkt = sniff(iface=inter, count= COUNT_SNIFF)

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
    sniffed_df.to_csv(f'{name}.csv', index = False)
    return()

def cpu_analyse(name : str, timeout : int, time_sleep : int):
    """
    Cette fonction regarde le cpu tout les time_sleep pendant timeout
    et renvoie ses observation.
    """
    #écriture periodique.
    time_finish = time.time() + timeout

    data_tot = [["pusing"]]

    while time.time() < time_finish:
        data = ac.generalite_cpu() #collecte de donnees
        data_tot.append(data)
        time.sleep(time_sleep) # attente pour éviter de trop alourdir les données.
    df_cpu = pd.DataFrame(data_tot)
    df_cpu.to_csv(f'{name}.csv')
    return data_tot



def run(name : str, time_sleep = 1, timeout = 20):
    """
    Cette fonction lance l'analyse de paquet et l'analyse du cpu en parallèle.
    ne fonctionne pas avec windows
    """
    traffic = Process(target = traffic_analyse, args = [name + "_" + "Traffic"])
    traffic.start()

    enregistrement_cpu = Process(target = cpu_analyse, args = [name + "_" + "Cpu",
                                                      timeout, time_sleep])
    enregistrement_cpu.start()

    traffic.join()
    enregistrement_cpu.join()

    print("finished sniffing data")
    df = pd.read_csv(f'{name}_traffic.csv')
    df.pipe(prepare_sniffed_df)
    dtrain = xgb.DMatrix(df)

    bst = xgb.Booster({'nthread': 4})  # init model
    bst.load_model('model.bst')  # load data
    #cpu_result = pd.DataFrame()
    network_result = pd.DataFrame(bst.predict(dtrain))
    #retirer après test
    network_result.sort_values([0]).to_csv('result.csv')
    if [network_result[network_result > 0.5].count() > network_result[network_result < 0.5].count()][0][0] :
        if 'ToastNotifier' in locals():
            msg = "Attention du code de minage tourne sur votre ordinateur"
            notif = ToastNotifier()
            notif.show_toast(title='Notification', msg=msg)
        else:
            print("probable attaque de cryptojacking")

if __name__ == '__main__':
    freeze_support()
    run('test')