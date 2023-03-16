# cryptojacking
## Installation
Testé uniquement sous MacOS 11.7.3

Python version 3.9.15

xgboost = 1.7.3

### Dépendances :
- condas
- netifaces
- xgboost = 1.7.3
- psutil
- winpcap

## Comment utiliser
Lancer le script run.py et attendre le résultat.

Pour rajouter des données dans le dataset d'entrainement et ré-entrainer le modèle :
- Lancer du minage avec XMRig (optionel)
- Lancer le sniff du réseau avec Wireshark
- Exporter en csv dans le dossier network_sniff avec minage dans le nom si il y a du minage et calme sinon.
- Lancer train_xgboost.py


## Roadmap
- Tester sur Linux.
- Vérifier si il faut remettre 0112_minage_traffic_internet_calmee.csv dans le dataset de train ou non.
- Rajouter des données dans le dataset.

# Interrogations

Faut-il réentrainer le modèle avec les output du sniff.

## Authors and acknowledgment
### Auteur
- Albert Dulout

- Marc Serre

- Tianrun Zhang

- Elias Bey

### Remerciement

- Francoise Sailhan
- Sandrine Vaton
- Santiago Ruano Rincón