# -*- coding: utf-8 -*-
"""
Created on Thu Jan 19 19:59:24 2023

@author: marc2
"""

def separate_in_flux(file):
    """
    File est une chaine de caractère
    Le nom du fichier avec l'extension.

    Cette fonction créé un dictionnaire
    avec en clé les caractéristiques du flux
    et en valeur la liste des paquets du flux
    """
    file = open(file)
    data = file.readlines()[1:] #on enlève la première ligne
    file.close()
    dico_flux = {}
    for el in data:
        lign, flux = treatment_lign(el)
        if flux in dico_flux.keys():
            dico_flux[flux].append(lign)
        else:
            dico_flux[flux] = [lign]
    return dico_flux



def treatment_lign(el):
    """
    Parameters
    ----------
    el : une chaine de caractère
        contenant les informations d'une ligne de traffic

    Returns
    -------
    la ligne traitéee et son flux
    """
    el = el.split(",")
    num = int(el[0][1:-1])
    time = float(el[1][1:-1])
    source = el[2]
    destination = el[3]
    protocol = el[4]
    lenght = int(el[5][1:-1])
    infos = el[6]

    lign = (num, time, source, destination, protocol, lenght, infos)
    flux = (source, destination, protocol)
    return lign, flux
