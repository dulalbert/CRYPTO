# cryptojacking
## Installation

Installer les dépendances :

```
pip install -r requirements.txt
```

## Comment utiliser
Lancer le script run.py et attendre le résultat.

Pour rajouter des données dans le dataset d'entrainement et ré-entrainer le modèle :
- Lancer du minage avec XMRig (optionel)
- Lancer le sniff du réseau avec Wireshark
- Exporter en csv dans le dossier network_sniff avec minage dans le nom si il y a du minage et calme sinon.
- Lancer train_xgboost.py


## Roadmap

- Rajouter des données dans le dataset => voir Interrogations

# Interrogations

Faut'il réentrainer le modèle avec des inputs de l'utilisateur.

## Avantages :
- Le modèle s'améliorerait avec le temps donc moins en moins de faux positif.

## Désaventages :
- Les classes étaient équilibrés au début, est-ce que déséquilibrer les classes ne diminurait pas le résultat du XGBoost.
- Les hyperparamètres ont été choisis par ggridsearch sur le dataset d'entrainement, faut il refaire un GridSearch à chaque entrainement?
- Pas eu de cours sur la mise en production de modèle.

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