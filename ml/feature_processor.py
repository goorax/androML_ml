import pdb
import logging
import numpy as np
import data.file_cacher as fc

from general.type import AppType
from general.type import FeatureType
from general.const import Consts
from general.settings import Settings
from scipy.sparse import coo_matrix, hstack
from sklearn.externals import joblib
from sklearn.feature_extraction import DictVectorizer

LOGGER = logging.getLogger()

class FeatureProcessor:
    """ This class will control the construction of the matrices X and y.
        Therefor apps will be generated and features will be extracted.
        The class will take care about malware, benign amount and 
        the desired features like hybrid, static and dynamic.
    """

    def __call__(self):
        return self._get_X_y()

    def _get_X_y(self):
        if fc.are_matrices_available():
            return fc.load_matrices()

        self.benign_ids = fc.load_benign_ids()
        self.malware_ids = [id for id in fc.load_malware_ids() if "VirusShare" not in id]
        #self.malware_ids = self.load_malware_ids()
        numericals, categories, y = self._get_features()
        vec = DictVectorizer()
        vectorizer = vec.fit_transform(categories)
        X = hstack([vectorizer, numericals]) 
        if (Settings.FEATURE_TYPE == FeatureType.HYBRID_S.value or Settings.FEATURE_TYPE == FeatureType.HYBRID_I.value):
            fc.dump_feature_description(vec.get_feature_names(), self._get_numerical_feature_names())
        fc.dump_matrices(X, y) 
        return X, y

    def _load_malware_ids(self):
        if Settings.MALWARE_CATEGORY == -1:
            LOGGER.info(f'Loading general malware.')
            malware_ids = [id for id in fc.load_malware_ids() if "VirusShare" not in id]
        else:
            LOGGER.info(f'Loading malware of category: {Settings.MALWARE_CATEGORY}')
            assignments, terms = fc.load_cluster_results()
            malware_ids = assignments[Settings.MALWARE_CATEGORY]
        return malware_ids

    def _get_features(self):
        cb, nb, yb, sb = self._iterate_apps(self.benign_ids, 'benign')
        cm, nm, ym, sm = self._iterate_apps(self.malware_ids, 'malware')
        categories = cb + cm 
        numericals = coo_matrix(nb + nm)
        sb.update(sm)
        fc.dump_cluster_data(sm)
        y = np.concatenate((yb , ym))
        return numericals, categories, y

    def _iterate_apps(self, ids, type):
        #y = np.zeros(len(ids))
        yt = []
        categories = []
        numericals = []
        scan_results = {}
        for i, id in enumerate(ids):
            app = fc.load_app(id, type)
            if app.app_type != AppType.UNKNOWN:
                if Consts.SCAN_RESULTS in app.static_content:
                    scan_results[app.id] = app.static_content[Consts.SCAN_RESULTS]
                features, numerical = self._get_adjusted_features(app)
                categories.append(features)
                numericals.append(numerical)
                #y[i] = app.app_type.value
                yt.append(app.app_type.value) 
        y = np.array(yt) 
        return categories, numericals, y, scan_results
    
    def _get_adjusted_features(self, app):
        categories = dict()
        numerical = []
        if (Settings.FEATURE_TYPE == FeatureType.HYBRID_S.value or Settings.FEATURE_TYPE == FeatureType.HYBRID_I.value):
            categories = self._get_categorical_features_from_app(app)
            numerical = self._get_numerical_features_from_app(app)
        elif (Settings.FEATURE_TYPE == FeatureType.DYNAMIC_S.value or Settings.FEATURE_TYPE == FeatureType.DYNAMIC_I.value):
            categories = self._get_dynamic_categorical_features(app)
            numerical = self._get_dynamic_numerical_features_from_app(app)
        elif (Settings.FEATURE_TYPE == FeatureType.STATIC.value):
            categories = self._get_static_categorical_features(app)
            numerical = self._get_static_numerical_features_from_app(app)
        return categories, numerical

    def _get_numerical_features_from_app(self, app):
        static_numerical_features = self._get_static_numerical_features_from_app(app)
        dynamic_numerical_features = self._get_dynamic_numerical_features_from_app(app)
        return static_numerical_features + dynamic_numerical_features

    def _get_static_numerical_features_from_app(self, app):
        features = [
                app.permission_amount,
                app.used_features_amount,
                app.additional_permissions_amount,
                app.activities_amount,
                app.services_amount,
                app.receivers_amount,
                app.assets_amount,
                app.filtered_class_names_amount,
                app.filtered_invoke_refs_amount,
                app.filtered_method_names_amount,
                app.filtered_uris_amount,
                app.total_classes_amount,
                app.total_method_amount,
                app.total_package_amount,
                app.total_system_classes_amount
                ]
        return features

    def _get_dynamic_numerical_features_from_app(self, app):
        features = [
                app.api_globals_amount,
                app.api_reflection_amount,
                app.api_generic_amount,
                app.api_content_amount,
                app.api_network_amount,
                app.api_dex_amount,
                app.api_crypto_amount,
                app.api_file_amount,
                app.api_binder_amount,
                app.api_fingerprint_amount
                ]
        return features

    def _get_categorical_features_from_app(self, app):
        features = dict()
        static_f = self._get_static_categorical_features(app)
        dynamic_f = self._get_dynamic_categorical_features(app)
        features.update(static_f)
        features.update(dynamic_f)
        return features

    def _get_dynamic_categorical_features(self, app):    
        features = dict()
        features.update(self._insert_categories('api_binder::', app.api_binder))
        features.update(self._insert_categories('api_content::', app.api_content))
        features.update(self._insert_categories('api_crypto::', app.api_crypto))
        features.update(self._insert_categories('api_dex::', app.api_dex))
        features.update(self._insert_categories('api_file::', app.api_file))
        features.update(self._insert_categories('api_fingerprint::', app.api_fingerprint))
        features.update(self._insert_categories('api_generic::', app.api_generic))
        features.update(self._insert_categories('api_globals::', app.api_globals))
        features.update(self._insert_categories('api_network::', app.api_network))
        features.update(self._insert_categories('api_reflection::', app.api_reflection))
        return features

    def _get_static_categorical_features(self, app):    
        features = dict()
        features[Consts.MIN_SDK] = app.min_sdk
        features[Consts.TARGET_SDK] = app.target_sdk
        for p in app.permissions:
            features[p] = True
        for f in app.used_features:
            uf = f.get('name')
            features['feature_' + uf] = True
        for ap in app.additional_permissions:
            features[ap] = True
        for a in app.activities:
            features[a] = True
        for s in app.services:
            features[s] = True
        for r in app.receivers:
            features[r] = True
        return features

    def _insert_categories(self, prefix, category):
        return { prefix + self._convert(api_item): True for api_item in category }

    def _convert(self, api_item):
        return api_item['class'] + '->' + api_item['method']

    def _get_numerical_feature_names(self):
        names = ['permission_amount',
                'used_features_amount',
                'additional_permissions_amount',
                'activities_amount',
                'services_amount',
                'receivers_amount',
                'assets_amount',
                'filtered_class_names_amount',
                'filtered_invoke_refs_amount',
                'filtered_method_names_amount',
                'filtered_uris_amount',
                'total_classes_amount',
                'total_method_amount',
                'total_package_amount',
                'total_system_classes_amount',
                'api_globals_amount',
                'api_reflection_amount',
                'api_generic_amount',
                'api_content_amount',
                'api_network_amount',
                'api_dex_amount',
                'api_crypto_amount',
                'api_file_amount',
                'api_binder_amount',
                'api_fingerprint_amount' ]
        return names
    


