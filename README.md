# cryptojacking

# Description

Ce projet permet de détécter la présence de malware de cryptojacking, une attaque de plus en plus fréquente sur des systèms peu protégés.

Pour plus d'informations, veuillez-vous referez à POSTER CRYPTOJACKING.pdf de ce repository.


## Installation

Installer les dépendances :

```
pip install -r requirements.txt
```
Sur Windows, on peut installer win10toast pour avoir une alerte plus esthétique.

## Comment utiliser

```
python3 run.py --time_sleep 1 --timeout 20
```

Variable globale pouvant être changées :
- WINDOW : la fenêtre surlaquelle on effectue les moyennes et écart-types mobiles
- COUNT_SNIFF : le nombre de paquet sniffés sur lesquels on applique le XGBoost
- CPU_AVERAGE_TIME : la durée sur laquelle étudie le pourcentage d'utilisation du CPU
- CPU_ALERT_PERCENT : le pourcentage surprenant d'utilisation du CPU
- NETWORK_ALERT_PERCENT : on compare le nombre de paquets ayant une probabilité supérieur à ce pourcentage et intférieue après le XGBoost et s'il y a une majorité de paquet ayant une probabilité supérieur, on alerte l'utilisateur.

Pour rajouter des données dans le dataset d'entrainement et ré-entrainer le modèle :
- Lancer du minage avec XMRig (optionel)
- Lancer le sniff du réseau avec Wireshark
- Exporter en csv dans le dossier network_sniff avec minage dans le nom si il y a du minage et calme sinon
- Lancer train_xgboost.py

Le model a été entrainé à partir de donnée snifées par Wireshark

## Roadmap

- Rajouter des données dans le dataset => voir Interrogations
- Essayer de créer un dataset avec plusieurs ordinateurs Windows avec Wireshark à utiliser en mode administrateur.
- Réecrire analyse_cpu ou le remplacer

# Interrogations

Faut il réentrainer le modèle avec des inputs de l'utilisateur.

## Avantages :
- Le modèle s'améliorerait avec le temps donc moins en moins de faux positif.

## Désaventages :
- Les classes étaient équilibrés au début, est-ce que déséquilibrer les classes ne diminurait pas le résultat du XGBoost.
- Les hyperparamètres ont été choisis par ggridsearch sur le dataset d'entrainement, faut il refaire un GridSearch à chaque entrainement?
- Pas eu de cours sur la mise en production de modèle.

## Génération du dataset

- Lancer la machine virtuelle
- Télécharger XMRig
- Sur le site web d’XMRIG aller dans Wizard, choisir Pool + Monnaie
- À l’aide du terminal, se déplacer dans le dossier téléchargement et ouvrir le tar.gz de xmrig
- Se déplacer dans le dossier Xmrig et avec ls vérifier qu’il y a bien 3 fichiers
- Copier la ligne de commande de la dernière page du Wizard dans l’onglet Linux
- Fermer Firefox
- Lancer l’enregistrement Wireshark
- Coller la ligne de commande de l’étape 6 dans le terminal et lancer le minage
- Arrêter le minage + Wireshark
- Enregistrer 2 fois : une en format pngcap et l’autre sous format csv avec comme nom :
    - Date_minage_pool_monnaie_
    - Date_traffic_typedecontenue si c’est du contenu bénin
Uploader dans le drive et dans le gitlab

## Auteurs and Remerciements

### Auteurs
- Albert Dulout

- Marc Serre

- Tianrun Zhang

- Elias Bey

### Remerciements

- Francoise Sailhan
- Sandrine Vaton
- Santiago Ruano Rincón
