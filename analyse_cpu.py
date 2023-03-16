# -*- coding: utf-8 -*-
"""
Created on Thu Dec  1 15:02:39 2022

@author: Marc SERRE

fonction d'analyse du cpu

utiliser cpu_stat
"""
import time
import psutil

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
    using = psutil.cpu_percent()
    return [using]


def cpu_stat(name_file:str, time_sleep = 10):
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
    file = open(name_file + ".csv", "w", encoding= "utf-8")
    file.write("pusing\n")
    file.close()

    #écriture periodique.
    while True:
        data = generalite_cpu() #collecte de donnees

        file = open(name + ".csv", "a", encoding = "UTF-8") #écriture
        for el in data:
            file.write(str(el) + ",")
        file.write("\n")
        file.close() #nécessaire pour l'enregistrement

        time.sleep(time_sleep) # attente pour éviter de trop alourdir les données.

if __name__ == "__main__":
    name = input("nom du fichier d'enregistrement (sans .csv)")
    delay = int(input("rentrer la durée en seconde de l'attente entre l'écriture des lignes"))
    cpu_stat(name, delay)