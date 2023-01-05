# -*- coding: utf-8 -*-
"""
Created on Thu Dec  1 15:02:39 2022

@author: Marc SERRE

fonction d'analyse du cpu

utiliser cpu_stat
"""

import psutil
import time

def generalite_cpu():
    """
    Cette fonction renvoie l'utilisation du cpu de manière général.
    c'est à dire une liste contenant:
        - le pourcentage de temps passer par des processus en mode utilisateur
        - le pourcentage de temps passer par des processus en mode noyau
        - le pourcentage de temps passer à ne rien faire.
        - le pourcentage de temps passer à faire autre chose
        - le pourcentage d'utilisation du cpu
        - le fréquence instantanée de travail du cpu
        - le pourcentage de la fréquence du cpu utilisé
        - le pourcentage de la mémoire ram utilisé.
    """
    ptime = psutil.cpu_times_percent()
    ptime_user = ptime.user
    ptime_sys = ptime.system
    ptime_none = ptime.idle
    ptime_other = 100-(ptime_user + ptime_sys + ptime_none)
    
    ptime = [ptime_user, ptime_sys, ptime_none, ptime_other]
    
    using = psutil.cpu_percent()
    
    freq = psutil.cpu_freq()
    if freq.max == 0:
        freq_max = freq.current
    else:
        freq_max = freq.max
    freq = [freq.current, 100*freq.current/freq_max]
    
    ram_using = psutil.swap_memory().percent
    
    return ptime + [using] + freq + [ram_using]


def cpu_stat(name, time_sleep = 10):
    """
    Cette fonction écris en arrière plan dans un fichier csv 
    l'utilisation du cpu toutes les time secondes.
    Il peut (et doit être arreter par un contrôle c)

    Parameters
    ----------
    name: string, 
        nom du fichier
        
    time_sleep : int, optional
        le temps d'attente entre deux écritures du fichier. 
        The default is 10.

    Returns
    -------
    None.

    """
    # préparation du fichier
    file = open(name + ".csv", "w")
    file.write("ptime_user,ptime_sys,ptime_none,ptime_other,pusing,freq_inst,pfreq,pram\n")
    file.close()
    
    #écriture periodique.
    while True:
        data = generalite_cpu() #collecte de donnees
        
        file = open(name + ".csv", "a") #écriture
        for el in data:
            file.write(str(el) + ",")
        file.write("\n")
        file.close() #nécessaire pour l'enregistrement
        
        time.sleep(time_sleep) # attente pour éviter de trop alourdir les données.

if __name__ == "__main__":
    name = input("nom du fichier d'enregistrement (sans .csv)")
    delay = int(input("rentrer la durée en seconde de l'attente entre l'écriture des lignes"))
    cpu_stat(name, delay)

    