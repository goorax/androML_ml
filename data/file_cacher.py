import os.path
import pdb
import data.db_adapter as dba
import logging

from sklearn import tree as tr
from structs.app_builder import AppBuilder
from general.settings import Settings
from sklearn.externals import joblib
from general.const import Consts

LOGGER = logging.getLogger()
PKL = '.pkl'

def build_id():
    m = Settings.MALWARE_AMOUNT
    b = Settings.BENIGN_AMOUNT
    c = Settings.MALWARE_CATEGORY
    f = Settings.FEATURE_TYPE
    return f'{m}.{b}.{c}.{f}'

def build_cluster_id():
    m = Settings.MALWARE_AMOUNT
    b = Settings.BENIGN_AMOUNT
    f = Settings.FEATURE_TYPE
    return f'{m}.{b}.{f}'

def are_matrices_available():
    m_id = build_id()
    return os.path.isfile(f'{Settings.CACHE_MATRICES}{m_id}{PKL}')

def load_matrices():
    LOGGER.info(f'Load X, y from cache ...')
    m_id = build_id()
    X, y = joblib.load(f'{Settings.CACHE_MATRICES}{m_id}{PKL}')
    return X, y

def dump_matrices(X, y):
    m_id = build_id()
    joblib.dump((X, y), f'{Settings.CACHE_MATRICES}{m_id}{PKL}')   

def remove_blacklisted(ids):
    blacklist = ['52dd03ca0f1480297200b625cc82b69ff20b8c6886de240836bfd7c994526e0d']
    for b in blacklist:
        if (ids.count(b) >= 1):
            ids.remove(b)
    return ids

def load_benign_ids():
    ids = load_ids('benign', Consts.DYNAMIC_INDEX_BENIGN, Settings.BENIGN_AMOUNT)
    return ids

def load_malware_ids():
    ids = load_ids('malware', Consts.DYNAMIC_INDEX_MALWARE, Settings.MALWARE_AMOUNT)
    return ids

def load_ids(type, db, amount):
    path = f'{Settings.CACHE_IDS}{type}.{amount}{PKL}'
    if os.path.isfile(path):
        ids = joblib.load(path)
    else:
        ids = dba.get_ids_from_db(db, 0, amount)        
        joblib.dump(ids, path)
    return remove_blacklisted(ids)

def is_app_cached(id):
    return os.path.isfile(f'{Settings.CACHE_APPS}{id}.{Settings.FEATURE_TYPE}{PKL}')

def load_app(id, type):
    if is_app_cached(id):
        LOGGER.info(f'Load app from cache - id: {id}')
        app = joblib.load(f'{Settings.CACHE_APPS}{id}.{Settings.FEATURE_TYPE}{PKL}')
    elif (Settings.FEATURE_TYPE == 0 or Settings.FEATURE_TYPE == 1):
        LOGGER.info(f'Load app from cache - id: {id}')
        app = joblib.load(f'{Settings.CACHE_APPS}{id}.3{PKL}')
    elif (Settings.FEATURE_TYPE == 2):
        LOGGER.info(f'Load app from cache - id: {id}')
        app = joblib.load(f'{Settings.CACHE_APPS}{id}.4{PKL}')
    else:
        ab = AppBuilder()
        app = ab.build_app(id, type)
        joblib.dump(app, f'{Settings.CACHE_APPS}{id}.{Settings.FEATURE_TYPE}{PKL}')
    return app

def dump_cluster_data(scan_results):
    c_id = build_cluster_id()
    path = f'{Settings.CACHE_CLUSTERING}{c_id}{PKL}'
    joblib.dump(scan_results, path)

def load_cluster_data():
    c_id = build_cluster_id()
    path = f'{Settings.CACHE_CLUSTERING}{c_id}{PKL}'
    scan_results = joblib.load(path) 
    return scan_results

def dump_feature_description(categorical_feature_names, numerical_feature_names):
    feature_names = categorical_feature_names + numerical_feature_names
    f_id = build_id()
    joblib.dump(feature_names, f'{Settings.CACHE_FEATURE_NAMES}{f_id}{PKL}')

def load_feature_description():
    f_id = build_id()
    return joblib.load(f'{Settings.CACHE_FEATURE_NAMES}{f_id}{PKL}')

def dump_graphviz(clf):
    feature_names_dirty = load_feature_description()
    feature_names = [fn.replace("->","...") for fn in feature_names_dirty] 
    f_id = build_id()
    path = f'{Settings.CACHE_TREES}{f_id}{PKL}'
    dot_data = tr.export_graphviz(clf, out_file=path, feature_names=feature_names, 
            filled=True, rounded=True, special_characters=True)

