"""
Author : Albert Dulout
Entrainer le modèle de ML permettant la détection
"""
from os import getcwd, path
from glob import glob
import pkg_resources

from matplotlib import pyplot # a retirer
from sklearn.metrics import classification_report, confusion_matrix # a retirer aussi
import pandas as pd
from xgboost import XGBClassifier, plot_importance
pkg_resources.require('xgboost == 1.7.3')
WINDOW = 4

def prepare_sniff_wireshark(sniffed_df : pd.DataFrame):
    """ Applique le Feature Engineering choisi
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
    sniffed_df.drop(['Time', 'Source', 'Destination', 'Protocol', 'Info'], axis = 1, inplace = True)
    sniffed_df.dropna(inplace = True)
    return sniffed_df

mining_DF = pd.DataFrame(columns=['No.','Length', 'delta', 'ra_delta', 'rstd_delta', 'ra_lenght',
       'rstd_lenght', 'miner'])
non_mining_DF = pd.DataFrame(columns=['No.','Length', 'delta', 'ra_delta',
                                       'rstd_delta', 'ra_lenght', 'rstd_lenght', 'miner'])
for name in glob(path.join(getcwd()+"/network_sniff/", "*minage*.csv")):
    _ = pd.read_csv(name)
    _.pipe(prepare_sniff_wireshark)
    mining_DF = pd.concat([_,mining_DF], ignore_index= True)

# mettre tous les sniffs sans minage dans un DataFrame
for name in glob(path.join(getcwd()+"/network_sniff/", "*calme*.csv")):
    _ = pd.read_csv(name)
    _.pipe(prepare_sniff_wireshark)
    non_mining_DF = pd.concat([_,non_mining_DF], ignore_index= True)
(mining_DF.miner, non_mining_DF.miner) = (True, False)

training_DF = pd.concat([mining_DF,non_mining_DF], ignore_index= True)
training_DF[['No.', 'Length']] = training_DF[['No.', 'Length']].astype('int')

y = training_DF['miner']
X = training_DF.drop(['miner', 'No.'], axis = 1)

fix_params = {'learning_rate': 0.2, 'n_estimators': 100, 'eval_metric': 'aucpr'
              , 'objective': 'binary:logistic', 'max_depth': 5, 'min_child_weight': 2}
xg = XGBClassifier(**fix_params)

xg.fit(X, y)

# Feature importance pour le modèle
plot_importance(xg)
pyplot.show()
print(confusion_matrix(y,xg.predict(X)))

xg.save_model('model.bst')
print('Model trained')